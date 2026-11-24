package main

import (
	"context"
	"log"
	"net"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"github.com/defensia/agent/internal/api"
	"github.com/defensia/agent/internal/csfsotwire"
	"github.com/defensia/agent/internal/firewall"
)

// This file is the ONLY place phase 16.1's CSF source-of-truth runtime
// behaviour lives (same convention csf_runtime.go established for phase
// 15): main.go carries call sites only.

// csfSotEngineIface is the slice of *firewall.SotEngine this runtime
// needs, as an interface so tests can substitute a fake whose Cycle()
// duration and return value are fully controlled -- the real engine's
// own tests already cover its internal policy; this file only wires it
// into the process.
type csfSotEngineIface interface {
	SetConfig(*csfsotwire.Config)
	Report() *csfsotwire.Report
	NeedsSync(*csfsotwire.Hint) bool
	Cycle(ctx context.Context) []firewall.SotEvent
}

var (
	csfSotEngine csfSotEngineIface
	csfSotKick   = make(chan struct{}, 1)

	// csfSotTriggerSync is set once by startCSFSot to the closure main.go
	// passes in (a sync against the same args as the fallback ticker).
	csfSotTriggerSync func()

	// csfSotEventSink is where csfSotRunCycle forwards every SotEvent;
	// startCSFSot points it at client.QueueEvent. A seam (not just a
	// direct call) so tests never need a live network client.
	csfSotEventSink func(api.EventRequest) = func(api.EventRequest) {}

	csfSotLastSyncOKMu sync.Mutex
	csfSotLastSyncOKAt time.Time

	csfSotHintMu        sync.Mutex
	csfSotLastHintFired time.Time
)

// csfSotHintDebounce caps how often a heartbeat-response hint can force
// an immediate sync (CONTRACT §3: "at most one triggered sync per 30s").
// NewSotEngine's own NeedsSync is edge-triggered but explicitly NOT
// debounced ("debounced by the caller, not here" -- its own doc
// comment); this runtime is that caller.
const csfSotHintDebounce = 30 * time.Second

// resetCSFSotHintDebounceForTest lets a test fire a hint immediately
// instead of waiting out whatever a previous test already consumed.
func resetCSFSotHintDebounceForTest() {
	csfSotHintMu.Lock()
	defer csfSotHintMu.Unlock()
	csfSotLastHintFired = time.Time{}
}

// startCSFSot builds the reconcile engine and runs its cycle loop on its
// own goroutine/ticker (sotTiming's Tick, 60s default) plus any kick from
// onSyncCSFSot -- never inside the heartbeat goroutine, so a slow Cycle
// can never delay a heartbeat. triggerSync is called (debounced here,
// see onHeartbeatResponseCSFSot) when the heartbeat response's hint says
// something changed since the config this agent last saw in a sync.
func startCSFSot(ctx context.Context, client *api.Client, serverURL string, triggerSync func()) {
	csfSotEngine = firewall.NewSotEngine(firewall.SotDeps{
		Now:          time.Now,
		PostSnapshot: client.PostCSFSotSnapshot,
		LastSyncOK:   csfSotLastSyncOK,
		PanelIP:      resolvePanelIP(serverURL),
	})
	csfSotTriggerSync = triggerSync
	csfSotEventSink = client.QueueEvent

	go csfSotLoop(ctx)
}

// resolvePanelIP resolves the panel host from the configured server_url
// once at startup, best-effort: an unresolvable host degrades the
// engine's would_block_panel guard silently rather than failing startup
// over it (the same posture panelPortFromServerURL takes for the port
// guard in csf_runtime.go).
func resolvePanelIP(serverURL string) netip.Addr {
	parsed, err := url.Parse(serverURL)
	if err != nil || parsed.Hostname() == "" {
		log.Printf("[csf-sot] panel IP guard disabled: cannot parse server_url %q: %v", serverURL, err)

		return netip.Addr{}
	}

	ips, err := net.LookupIP(parsed.Hostname())
	if err != nil || len(ips) == 0 {
		log.Printf("[csf-sot] panel IP guard disabled: cannot resolve %q: %v", parsed.Hostname(), err)

		return netip.Addr{}
	}

	addr, ok := netip.AddrFromSlice(ips[0])
	if !ok {
		return netip.Addr{}
	}

	return addr.Unmap()
}

func csfSotLastSyncOK() time.Time {
	csfSotLastSyncOKMu.Lock()
	defer csfSotLastSyncOKMu.Unlock()

	return csfSotLastSyncOKAt
}

func setCSFSotLastSyncOK(t time.Time) {
	csfSotLastSyncOKMu.Lock()
	defer csfSotLastSyncOKMu.Unlock()
	csfSotLastSyncOKAt = t
}

// onSyncCSFSot records every successful sync's config.csf_sot block
// (nil, from an old panel or a row never activated, means mode csf) and
// kicks an immediate reconcile cycle so a generation bump or a new
// token takes effect within this tick instead of waiting for the next
// one.
func onSyncCSFSot(cfg *csfsotwire.Config) {
	csfSotEngine.SetConfig(cfg)
	setCSFSotLastSyncOK(time.Now())

	select {
	case csfSotKick <- struct{}{}:
	default:
	}
}

// csfSotHeartbeatFields is read by the heartbeat ticker on every tick.
// Capabilities is always ["csf_sot"] regardless of the engine's report
// (CONTRACT §2) -- it is how the panel tells "old agent" from "new
// agent with nothing to report yet" apart.
func csfSotHeartbeatFields() ([]string, *csfsotwire.Report) {
	return []string{"csf_sot"}, csfSotEngine.Report()
}

// onHeartbeatResponseCSFSot reacts to the heartbeat response's sync-
// trigger hint (CONTRACT §3): a difference from the config this engine
// last saw means something changed on the panel since our last sync,
// so trigger one now -- debounced to at most once per
// csfSotHintDebounce, because every heartbeat (every ~60s) could
// otherwise re-fire it as long as the panel-side state keeps changing.
func onHeartbeatResponseCSFSot(h *csfsotwire.Hint) {
	if !csfSotEngine.NeedsSync(h) {
		return
	}

	csfSotHintMu.Lock()
	now := time.Now()
	if now.Sub(csfSotLastHintFired) < csfSotHintDebounce {
		csfSotHintMu.Unlock()

		return
	}
	csfSotLastHintFired = now
	csfSotHintMu.Unlock()

	if csfSotTriggerSync != nil {
		go csfSotTriggerSync()
	}
}

// csfSotLoop runs csfSotRunCycle on its own ticker plus any kick from
// onSyncCSFSot, until ctx is cancelled. This is the ONLY goroutine that
// ever calls Cycle(); the heartbeat path never does.
func csfSotLoop(ctx context.Context) {
	ticker := time.NewTicker(firewall.SotTickInterval())
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			csfSotRunCycle(ctx)
		case <-csfSotKick:
			csfSotRunCycle(ctx)
		}
	}
}

// csfSotRunCycle runs one reconcile pass and forwards every edge-
// triggered event it returns to csfSotEventSink.
func csfSotRunCycle(ctx context.Context) {
	events := csfSotEngine.Cycle(ctx)
	for _, e := range events {
		csfSotEventSink(api.EventRequest{
			Type:       e.Type,
			Severity:   e.Severity,
			Details:    e.Details,
			OccurredAt: time.Now().UTC().Format(time.RFC3339),
		})
	}
}
