package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/defensia/agent/internal/api"
	"github.com/defensia/agent/internal/firewall"
)

// This file is the ONLY place phase 15's CSF runtime behaviour lives — the
// heartbeat builder, the hash-gated lists uploader, the kill-switch and the
// port-action handler with action_id echo. main.go carries call sites only
// (see the plan's own <agent_repo_rules>: Phase 17 rebases onto this and
// must find minimal, self-contained hunks there).

// --- Seams (function-typed package vars) -------------------------------
//
// Every one of these defaults to the real internal/firewall function. Tests
// reassign them directly instead of exercising the real CSF binary or
// writing to /etc/defensia's real marker files, which this package (unlike
// internal/firewall's own tests) has no way to redirect to a temp dir.
var (
	safePortChange  = firewall.SafePortChange
	csfPausedFn     = firewall.CSFPaused
	setCSFPausedFn  = firewall.SetCSFPaused
	ackCSFRemovalFn = firewall.AckCSFRemovalReported
)

// csfPortOpts carries the one piece of runtime context handleCSFPortActions
// needs beyond the sync payload itself (the panel's own TCP_OUT port, so a
// "remove TCP_OUT" action can never cut the agent off from the panel). Set
// once at startup by startCSFRuntime.
var csfPortOpts firewall.PortChangeOptions

// csfPortActionsMu serializes handleCSFPortActions's background goroutine:
// two overlapping sync cycles (e.g. the 5-minute fallback ticker racing a
// WebSocket sync.requested) must never run SafePortChange concurrently.
var csfPortActionsMu sync.Mutex

// --- Heartbeat builder (COL-06) ----------------------------------------

// buildCSFHeartbeat turns a collector snapshot into the wire-contract
// fields (15-06). It performs no I/O and no CSF exec whatsoever — it only
// ever reads the struct it is given. The heartbeat ticker must call this
// with firewall.CurrentCSFSnapshot(), never firewall.CollectCSF(ctx).
//
//   - paused (kill switch) wins over everything: a non-nil *true is
//     returned and the snapshot is never inspected, however stale or fresh
//     it is.
//   - a nil snapshot (collector hasn't run yet, or CSF was never seen) means
//     "nothing to report": both return values are nil, which drops every
//     csf_ key from the heartbeat (COL-06).
//   - a snapshot with Installed:false means CSF was seen before and is now
//     gone: CSFInstalled is explicitly false and every other field is an
//     explicit JSON null (not omitted) — distinguishable byte-for-byte from
//     the nil-snapshot case, which sends no csf_ keys at all.
func buildCSFHeartbeat(s *firewall.CSFSnapshot, paused bool) (*api.CSFHeartbeatFields, *bool) {
	if paused {
		p := true
		return nil, &p
	}
	if s == nil {
		return nil, nil
	}
	if !s.Installed {
		return &api.CSFHeartbeatFields{CSFInstalled: false}, nil
	}

	notPaused := false
	listsTruncated := s.Deny.Truncated || s.Allow.Truncated
	fields := &api.CSFHeartbeatFields{
		CSFInstalled:       true,
		CSFVersion:         csfStrPtr(s.Version),
		CSFPortsIn:         csfStrPtr(s.PortsIn),
		CSFPortsOut:        csfStrPtr(s.PortsOut),
		CSFDenyCount:       csfIntPtr(s.Deny.Total),
		CSFAllowCount:      csfIntPtr(s.Allow.Total),
		CSFFork:            csfStrPtr(s.Fork),
		CSFForkEvidence:    s.ForkEvidence,
		CSFTesting:         s.Testing,
		CSFAutoUpdates:     s.AutoUpdates,
		CSFAutoUpdatesCron: csfBoolPtr(s.AutoUpdatesCron),
		CSFLFDaemon:        s.LFDaemon,
		CSFLFDRunning:      s.LFDRunning,
		CSFIPv6:            s.IPv6,
		CSFDownloadServers: s.DownloadServers,
		CSFDenyIPLimit:     s.DenyIPLimit,
		CSFDenyTempIPLimit: s.DenyTempIPLimit,
		CSFListsHash:       csfStrPtr(s.ListsHash),
		CSFListsTruncated:  csfBoolPtr(listsTruncated),
	}
	return fields, &notPaused
}

// onHeartbeatSuccess is called by main.go right after apiClient.Heartbeat
// returns with no error. It acknowledges a reported removal exactly once:
// once the panel has seen one csf_installed:false heartbeat, the collector
// should go back to reporting nothing (nil snapshot) rather than resending
// "removed" forever.
func onHeartbeatSuccess(s *firewall.CSFSnapshot) {
	if s != nil && !s.Installed {
		ackCSFRemovalFn()
	}
}

func csfStrPtr(s string) *string { return &s }
func csfIntPtr(i int) *int       { return &i }
func csfBoolPtr(b bool) *bool    { return &b }

// --- Lists uploader (COL-03) --------------------------------------------

// csfListsRefreshInterval is how long an unchanged hash is still re-sent
// anyway, so a panel that lost a row (or never got the first upload) isn't
// stuck without lists forever just because nothing has changed since.
const csfListsRefreshInterval = 60 * time.Minute

// csfListsBodyCapBytes is deliberately half the panel's own 1 MiB cap
// (15-10/15-06's csfListsMaxBodyBytes): headroom for the hash/collected_at
// envelope and so this agent backs off from the edge long before the
// panel's own 413 would ever fire.
const csfListsBodyCapBytes = 512 * 1024

// Backoff windows for a failed upload. 404/405 is deliberately the longest:
// it means "this panel has never heard of this route", which will still be
// true on the very next cycle, so there is no point spending even one
// request per heartbeat cycle re-discovering it. These are the durations
// this plan's own <behavior> spec calls for. The backoff policy is owned
// here, by the runtime that actually retries — internal/api only exposes
// the predicate (IsOldPanelCSFListsResponse) that classifies the error;
// it does not also publish a competing duration.
const (
	csfListsOldPanelBackoff  = 6 * time.Hour
	csfListsRateLimitBackoff = 60 * time.Second
	csfListsRejectedBackoff  = 60 * time.Minute
	csfListsNetworkBackoff   = 2 * time.Minute
)

// csfListsUploader holds the hash-gating/backoff state for one running
// agent. upload/now are seams: production wires upload to
// client.UploadCSFLists and now to time.Now; tests inject fakes of both so
// the 60-minute refresh and the backoff windows are provable without a real
// clock or a real HTTP round trip.
type csfListsUploader struct {
	upload func(api.CSFListsRequest) error
	now    func() time.Time

	lastHash     string
	lastAt       time.Time
	backoffUntil time.Time
}

// maybeUpload uploads the current lists exactly when there is something new
// to say and nothing is backing it off: paused, no snapshot, CSF absent, an
// active backoff window, or an unchanged hash inside the refresh interval
// all produce zero HTTP requests. This is the function that keeps the
// endpoint's 4/min-per-agent budget from being burned every single 60s
// cycle by every one of the fleet's agents.
func (u *csfListsUploader) maybeUpload(s *firewall.CSFSnapshot, paused bool) {
	if paused || s == nil || !s.Installed {
		return
	}

	now := u.now()
	if now.Before(u.backoffUntil) {
		return
	}
	if s.ListsHash == u.lastHash && !u.lastAt.IsZero() && now.Sub(u.lastAt) < csfListsRefreshInterval {
		return
	}

	if err := u.upload(buildCSFListsRequest(s)); err != nil {
		u.backoffUntil = now.Add(csfListsBackoffFor(err))
		log.Printf("[csf] lists upload failed: %v (retrying after %s)", err, u.backoffUntil.Format(time.RFC3339))
		return
	}

	u.lastHash = s.ListsHash
	u.lastAt = now
	u.backoffUntil = time.Time{}
}

// csfListsBackoffFor classifies an UploadCSFLists error into how long to
// wait before trying again. A plain network error (no HTTPError at all —
// dial failure, timeout, DNS) gets the shortest, most optimistic backoff;
// every HTTP status gets the window that matches what retrying sooner would
// actually buy.
func csfListsBackoffFor(err error) time.Duration {
	var httpErr *api.HTTPError
	if errors.As(err, &httpErr) {
		switch httpErr.Status {
		case http.StatusNotFound, http.StatusMethodNotAllowed:
			return csfListsOldPanelBackoff
		case http.StatusTooManyRequests:
			if httpErr.RetryAfter > 0 {
				return httpErr.RetryAfter
			}
			return csfListsRateLimitBackoff
		case http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
			return csfListsRejectedBackoff
		}
	}
	return csfListsNetworkBackoff
}

// runCSFListsUploader is the lists uploader's own ticker, entirely separate
// from the heartbeat ticker. This separation is what makes COL-03's "never
// on the heartbeat" guarantee structural rather than a code-review promise:
// nothing in the heartbeat goroutine can reach this function at all.
func runCSFListsUploader(ctx context.Context, client *api.Client) {
	u := &csfListsUploader{upload: client.UploadCSFLists, now: time.Now}

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			u.maybeUpload(firewall.CurrentCSFSnapshot(), firewall.CSFPaused())
		}
	}
}

// buildCSFListsRequest converts a snapshot to the wire request, trimming
// down to csfListsBodyCapBytes if necessary. Trimming drops entries only —
// Total (the real, uncapped line count) never changes, so the panel always
// knows how much was cut regardless of whether csf_lists.go's own 1000-cap
// or this body-size cap is what did the cutting.
func buildCSFListsRequest(s *firewall.CSFSnapshot) api.CSFListsRequest {
	req := api.CSFListsRequest{
		Hash:        s.ListsHash,
		CollectedAt: s.CollectedAt.UTC().Format(time.RFC3339),
		Deny:        csfListToPayload(s.Deny),
		Allow:       csfListToPayload(s.Allow),
	}

	for {
		data, err := json.Marshal(req)
		if err != nil || len(data) <= csfListsBodyCapBytes {
			break
		}
		if !trimLargerCSFListPayload(&req) {
			break
		}
	}

	return req
}

func csfListToPayload(l firewall.CSFList) api.CSFListPayload {
	entries := make([]api.CSFListEntryPayload, len(l.Entries))
	for i, e := range l.Entries {
		entries[i] = api.CSFListEntryPayload{Value: e.Value, Kind: e.Kind, Comment: e.Comment}
	}
	return api.CSFListPayload{Total: l.Total, Truncated: l.Truncated, Entries: entries}
}

// trimLargerCSFListPayload drops ~10% of the tail of whichever of
// Deny/Allow currently holds more entries, marking only that list
// Truncated. Returns false once neither list has anything left to drop, so
// buildCSFListsRequest's loop can never spin forever.
func trimLargerCSFListPayload(req *api.CSFListsRequest) bool {
	larger := &req.Deny
	if len(req.Allow.Entries) > len(req.Deny.Entries) {
		larger = &req.Allow
	}
	if len(larger.Entries) == 0 {
		return false
	}

	drop := len(larger.Entries) / 10
	if drop < 1 {
		drop = 1
	}
	larger.Entries = larger.Entries[:len(larger.Entries)-drop]
	larger.Truncated = true
	return true
}

// --- Port actions with action_id echo (COL-05) --------------------------

// handleCSFPortActions spawns exactly one goroutine and returns immediately
// — syncAndApply must never block waiting for a `csf -r` cycle (up to 90s
// per 15-05's restart timeout, longer still with the busy-retry and a
// rollback). Inside that goroutine, actions run strictly in order, guarded
// by csfPortActionsMu so a second sync cycle landing while the first is
// still mid-restart can never race it.
func handleCSFPortActions(reporter func([]api.EventRequest) error, actions []api.CSFPortAction, opts firewall.PortChangeOptions) {
	if len(actions) == 0 {
		return
	}

	// Copy so a caller that reuses/mutates its slice after this call
	// returns can never race the background goroutine's read of it.
	queued := make([]api.CSFPortAction, len(actions))
	copy(queued, actions)

	go func() {
		csfPortActionsMu.Lock()
		defer csfPortActionsMu.Unlock()
		for _, action := range queued {
			processCSFPortAction(reporter, action, opts)
		}
	}()
}

// processCSFPortAction runs one action to completion and reports exactly
// one result event. While the kill switch is on, SafePortChange is never
// even called — the rejection is synthesized locally — because the kill
// switch's whole point is "nothing may write to CSF", and a call that would
// itself refuse (SafePortChange checks CSFPaused() too) still isn't the
// same guarantee as never dialing it at all.
func processCSFPortAction(reporter func([]api.EventRequest) error, action api.CSFPortAction, opts firewall.PortChangeOptions) {
	var res firewall.PortChangeResult
	if csfPausedFn() {
		res = firewall.PortChangeResult{Result: "rejected", Reason: "integration_disabled"}
	} else {
		res = safePortChange(context.Background(), firewall.PortChangeRequest{
			Port:      action.Port,
			Direction: action.Direction,
			Action:    action.Action,
		}, opts)
	}

	log.Printf("[csf] port action %s %d %s -> %s (%s)", action.Action, action.Port, action.Direction, res.Result, res.Reason)

	if err := reporter([]api.EventRequest{buildCSFPortEvent(action, res)}); err != nil {
		log.Printf("[csf] failed to report port action result: %v", err)
	}
}

// buildCSFPortEvent maps a PortChangeResult to the event the panel
// correlates by action_id (15-04): applied/unchanged are informational,
// rejected/failed are a warning, and rollback_failed is critical — CSF was
// left in a state that could not be verified good, which is the one outcome
// that must page a human, not just show up in a log.
func buildCSFPortEvent(action api.CSFPortAction, res firewall.PortChangeResult) api.EventRequest {
	eventType, severity := "csf_port_error", "warning"
	switch res.Result {
	case "applied", "unchanged":
		eventType, severity = "csf_port_changed", "info"
	case "rollback_failed":
		severity = "critical"
	}

	details := map[string]string{
		"port":          strconv.Itoa(action.Port),
		"direction":     action.Direction,
		"action":        action.Action,
		"result":        res.Result,
		"reason":        res.Reason,
		"rolled_back":   strconv.FormatBool(res.RolledBack),
		"backup":        res.Backup,
		"ipv6_mirrored": strconv.FormatBool(res.IPv6Mirrored),
		"testing_mode":  strconv.FormatBool(res.TestingMode),
	}
	// action_id ONLY when the sync item carried one — an old panel's items
	// never do, and the panel falls back to FIFO correlation for those.
	if action.ID != "" {
		details["action_id"] = action.ID
	}
	if res.Err != nil {
		msg := res.Err.Error()
		if len(msg) > 300 {
			msg = msg[:300]
		}
		details["error"] = msg
	}

	return api.EventRequest{
		Type:       eventType,
		Severity:   severity,
		Details:    details,
		OccurredAt: time.Now().UTC().Format(time.RFC3339),
	}
}

// --- Kill switch ---------------------------------------------------------

// applyCSFIntegrationFlag mirrors the panel's org-level kill switch
// (sync.CSFIntegrationDisabled) into the collector's own pause state. A nil
// flag (absent key, i.e. an old panel) changes nothing — absent means
// enabled, per the locked policy that Defensia activates nothing on its
// own. SetCSFPaused is idempotent on the firewall side, so calling it again
// with the same value when already paused/resumed is harmless.
func applyCSFIntegrationFlag(disabled *bool) {
	if disabled == nil {
		return
	}
	if err := setCSFPausedFn(*disabled); err != nil {
		log.Printf("[csf] failed to apply integration_disabled=%v: %v", *disabled, err)
	}
}

// --- Startup wiring --------------------------------------------------------

// panelPortFromServerURL extracts the TCP_OUT port the agent's own API
// traffic depends on, so SafePortChange's panel-port guard
// (PortChangeOptions.PanelPort) can refuse to close it. Returns 0 (guard
// skipped) for anything it can't parse.
func panelPortFromServerURL(u string) int {
	parsed, err := url.Parse(u)
	if err != nil || parsed.Host == "" {
		return 0
	}
	if p := parsed.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			return n
		}
		return 0
	}
	switch parsed.Scheme {
	case "https":
		return 443
	case "http":
		return 80
	default:
		return 0
	}
}

// startCSFRuntime is the single call main.go makes at startup: it loads the
// persisted kill-switch state, computes the panel-port guard, starts the
// background collector (never blocking — see StartCSFCollector's own doc
// comment in internal/firewall/csf_collector.go) and launches the lists
// uploader on its own independent ticker.
//
// GeoBlocker re-assertion after a CSF restart: internal/firewall's
// GeoBlocker.ApplyCountryBlocks(g.ActiveCountries()) is NOT the idempotent
// re-apply this would need — it only calls addCountry for countries not
// already in its own activeCountries map, so replaying the current active
// set is a no-op and would NOT re-insert the iptables DROP rule a `csf -r`
// just wiped. Inventing a new "force re-apply" method was out of scope for
// this plan (the plan says not to invent one when none exists), so geoblock
// rules are NOT re-asserted after csf -r by this plan; Phase 17 (17-05)
// switching afterCSFRestart's default from Init() to firewall.Ensure() is
// expected to cover this.
func startCSFRuntime(ctx context.Context, client *api.Client, serverURL string) {
	firewall.LoadCSFPaused()
	csfPortOpts = firewall.PortChangeOptions{PanelPort: panelPortFromServerURL(serverURL)}
	firewall.StartCSFCollector(ctx, 5*time.Minute)
	go runCSFListsUploader(ctx, client)
}
