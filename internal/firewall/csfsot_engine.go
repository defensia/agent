package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defensia/agent/internal/csfsotwire"
)

// SotEvent is an edge-triggered fact the engine wants reported to the
// panel (converted by the runtime into an api.EventRequest).
type SotEvent struct {
	Type     string
	Severity string
	Details  map[string]string
}

// SotDeps are the engine's external dependencies, injected so tests can
// run with a fake clock and a fake PostSnapshot.
type SotDeps struct {
	Now          func() time.Time
	PostSnapshot func(csfsotwire.SnapshotRequest) (csfsotwire.SnapshotResponse, int, error)
	LastSyncOK   func() time.Time
	PanelIP      netip.Addr
}

// Seams for testing.
var (
	observeFn     = observeSot
	applyPortsFn  = applySotPorts
	applyListsFn  = applySotLists
	fingerprintFn = sotFingerprint
)

const (
	snapshotDebounce = 60 * time.Second
	settleSeconds    = 120 * time.Second
	driftSettleCycle = 2
)

// SotEngine is the agent-side reconcile engine for everything except
// the automatic-correction policy (16.1-11 fills maybeAutoCorrect).
type SotEngine struct {
	mu   sync.Mutex
	deps SotDeps

	cfg   *csfsotwire.Config
	cfgAt time.Time

	st       *sotLocalState
	stExists bool

	report atomic.Pointer[csfsotwire.Report]

	lastFP              string
	lastSnapshotPostAt  time.Time
	lastSnapshotCfgAt   time.Time
	lastSnapshotRefused bool
	lastDrift           []csfsotwire.DriftItem
	lastAuto            autoResult
}

// NewSotEngine loads any persisted state and returns a ready engine.
func NewSotEngine(deps SotDeps) *SotEngine {
	if deps.Now == nil {
		deps.Now = time.Now
	}

	st, exists, _ := loadSotState()
	if st.DriftFirstSeen == nil {
		st.DriftFirstSeen = map[string]time.Time{}
	}
	if st.DriftSeenCycles == nil {
		st.DriftSeenCycles = map[string]int{}
	}

	return &SotEngine{deps: deps, st: st, stExists: exists}
}

// SetConfig records the panel's latest config.csf_sot. nil means "mode
// csf" (not source-of-truth managed).
func (e *SotEngine) SetConfig(c *csfsotwire.Config) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.cfg = c
	e.cfgAt = e.deps.Now()
}

// Report returns the last computed heartbeat csf_sot block, or nil when
// CSF is paused (the agent should omit the key entirely that cycle).
func (e *SotEngine) Report() *csfsotwire.Report {
	return e.report.Load()
}

// NeedsSync reports whether the heartbeat's trigger hint differs from
// what this engine last saw in SetConfig -- true means "run a full sync
// now" (debounced by the caller, not here).
func (e *SotEngine) NeedsSync(h *csfsotwire.Hint) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	if h == nil {
		return false
	}

	return !h.Equal(e.cfg)
}

// Cycle runs one reconcile pass and returns any edge-triggered events
// that happened during it.
func (e *SotEngine) Cycle(ctx context.Context) []SotEvent {
	e.mu.Lock()
	defer e.mu.Unlock()

	if CSFPaused() {
		e.report.Store(nil)

		return nil
	}

	cfg := e.cfg

	if cfg == nil || cfg.Mode != csfsotwireModeDefensia {
		return e.cycleNotManaged()
	}

	if cfg.SnapshotRequested {
		return e.cycleSnapshot(cfg)
	}

	var events []SotEvent

	if !e.stExists {
		e.adopt(cfg)
	}

	// Token bookkeeping: a NEW retry token resets the attempt counter so
	// the next intentional-change attempt happens immediately. Recorded
	// right away (not just on a successful retry) so the SAME token
	// delivered again never resets the counter a second time.
	if cfg.RetryToken != nil && *cfg.RetryToken != e.st.LastRetryToken {
		e.st.LastRetryToken = *cfg.RetryToken
		e.st.IntentAttempts = 0
		e.st.IntentNextAt = time.Time{}
	}

	obs, err := observeFn()
	if err != nil {
		return events
	}

	fp := fingerprintFn()
	e.lastFP = fp

	if cfg.Generation > e.st.GenerationAcked {
		return append(events, e.applyIntentional(ctx, cfg, obs)...)
	}

	if cfg.RevertToken != nil && *cfg.RevertToken != e.st.LastRevertToken {
		return append(events, e.applyRevert(ctx, cfg, obs)...)
	}

	events = append(events, e.detectDrift(ctx, cfg, obs)...)
	e.buildSteadyReport(cfg, obs)
	e.persist()

	return events
}

const csfsotwireModeDefensia = "defensia"

// cycleNotManaged handles mode nil/csf: exit once if a state file
// exists, otherwise a cheap precheck-only report.
func (e *SotEngine) cycleNotManaged() []SotEvent {
	var events []SotEvent

	if e.stExists {
		deleteSotState()
		e.stExists = false
		e.st = &sotLocalState{DriftFirstSeen: map[string]time.Time{}, DriftSeenCycles: map[string]int{}}
		events = append(events, SotEvent{Type: "csf_sot_exited", Severity: "info"})
	}

	obs, _ := observeFn()
	e.report.Store(&csfsotwire.Report{Active: false, Problems: obs.Problems})

	return events
}

// cycleSnapshot handles snapshot_requested=true: a single read-only
// Observe, POST it, and act on the response -- debounced so a panel
// that hasn't updated yet doesn't get hammered.
func (e *SotEngine) cycleSnapshot(cfg *csfsotwire.Config) []SotEvent {
	var events []SotEvent

	now := e.deps.Now()
	sameRequest := e.cfgAt.Equal(e.lastSnapshotCfgAt)

	if (sameRequest && e.lastSnapshotRefused) || (!e.lastSnapshotPostAt.IsZero() && now.Sub(e.lastSnapshotPostAt) < snapshotDebounce) {
		e.report.Store(&csfsotwire.Report{
			Active: true, Status: "activating",
			GenerationSeen: e.st.GenerationSeen, GenerationAcked: e.st.GenerationAcked,
		})

		return events
	}

	obs, err := observeFn()
	if err != nil {
		e.report.Store(&csfsotwire.Report{Active: true, Status: "activating"})

		return events
	}

	sshPorts, _ := sshPortsFn(context.Background())
	fork, version := "", ""
	if snap := CurrentCSFSnapshot(); snap != nil {
		fork, version = snap.Fork, snap.Version
	}

	req := csfsotwire.SnapshotRequest{
		Observed:     obs.Managed,
		ObservedHash: sotHash(obs.Managed),
		IPv6:         obs.IPv6,
		ManagedKeys:  obs.ManagedKeys,
		SSHPorts:     sshPorts,
		Fork:         fork,
		Version:      version,
		Problems:     obs.Problems,
	}

	e.lastSnapshotPostAt = now
	e.lastSnapshotCfgAt = e.cfgAt

	resp, status, err := e.deps.PostSnapshot(req)
	if err != nil {
		e.report.Store(&csfsotwire.Report{Active: true, Status: "activating"})

		return events
	}

	if status == 409 {
		e.lastSnapshotRefused = true
		e.report.Store(&csfsotwire.Report{Active: true, Status: "activating"})

		return events
	}
	e.lastSnapshotRefused = false

	if !resp.Accepted {
		e.report.Store(&csfsotwire.Report{Active: true, Status: "activating"})

		return events
	}

	e.st.GenerationSeen = resp.Generation
	e.st.GenerationAcked = resp.Generation
	e.st.Adopted = true
	e.stExists = true
	e.persist()

	events = append(events, SotEvent{
		Type: "csf_sot_snapshot_taken", Severity: "info",
		Details: map[string]string{"generation": fmt.Sprintf("%d", resp.Generation)},
	})

	e.report.Store(&csfsotwire.Report{
		Active: true, Status: "in_sync",
		GenerationSeen: e.st.GenerationSeen, GenerationAcked: e.st.GenerationAcked,
	})

	return events
}

// adopt creates a fresh local state the first time the engine sees a
// mode=defensia config with no local history: generation_acked is
// seeded from the panel's current generation (never applied -- the
// server's current state becomes the baseline, differences from
// `desired` are reported as drift, not corrected), and a 10-minute hold
// is set so auto-correction (16.1-11) doesn't fire immediately on an
// already-settled server.
func (e *SotEngine) adopt(cfg *csfsotwire.Config) {
	e.st = &sotLocalState{
		GenerationSeen:  cfg.Generation,
		GenerationAcked: cfg.Generation,
		Adopted:         true,
		HoldReason:      "adopted",
		HoldUntil:       e.deps.Now().Add(10 * time.Minute),
		DriftFirstSeen:  map[string]time.Time{},
		DriftSeenCycles: map[string]int{},
	}
	e.stExists = true
	e.persist()
}

// applyIntentional handles generation > generation_acked: a
// user/template-initiated change, applied immediately regardless of
// correction mode (warn or auto), with bounded retries on failure.
func (e *SotEngine) applyIntentional(ctx context.Context, cfg *csfsotwire.Config, obs sotObservation) []SotEvent {
	now := e.deps.Now()
	if e.st.IntentGen != cfg.Generation {
		e.st.IntentGen = cfg.Generation
		e.st.IntentAttempts = 0
		e.st.IntentNextAt = time.Time{}
	}

	if !e.st.IntentNextAt.IsZero() && now.Before(e.st.IntentNextAt) {
		e.buildApplyingReport(cfg, obs)
		e.persist()

		return nil
	}

	// Retries are exhausted for this generation: stop trying until a new
	// generation or an explicit retry_token resets the counter (handled
	// above, in Cycle, when a new retry_token arrives).
	if e.st.IntentAttempts >= len(sotTiming().IntentBackoff) {
		e.buildApplyingReport(cfg, obs)
		e.persist()

		return nil
	}

	desired := csfsotwire.Managed{}
	if cfg.Desired != nil {
		desired = *cfg.Desired
	}

	var events []SotEvent

	portsResult := applyPortsFn(ctx, desired.Ports, obs)
	listsResult := applyListsFn(ctx, desired, obs, e.deps.PanelIP)

	e.st.IntentAttempts++

	allRefusals := append(append([]csfsotwire.Refusal{}, portsResult.Refusals...), listsResult.Refusals...)
	// Indexed, not `for _, r := range` -- a range loop's `r` is a COPY of
	// each element, so `r.Generation = ...` silently mutated only the
	// copy and never touched allRefusals itself. Confirmed live (phase
	// 16.1, 2026-11-20): every refusal's Generation stayed its zero
	// value, so the panel's own refusalAtGeneration($state,
	// $item->target_generation) -- which matches on this exact field --
	// could never find it (target_generation is never 0 in practice),
	// and a rollout item stuck on a refused intentional change never
	// resolved to failed.
	for i := range allRefusals {
		allRefusals[i].Generation = cfg.Generation
		events = append(events, SotEvent{
			Type: "csf_sot_refused", Severity: "warning",
			Details: map[string]string{"reason": allRefusals[i].Reason, "detail": allRefusals[i].Detail, "generation": fmt.Sprintf("%d", cfg.Generation)},
		})
	}

	portsOK := portsResult.Result == "applied" || portsResult.Result == "unchanged"
	listsOK := listsResult.Result == "applied" || listsResult.Result == "unchanged"
	hardError := portsResult.Result == "error" || listsResult.Result == "error"

	if portsOK && listsOK && len(allRefusals) == 0 {
		e.st.GenerationAcked = cfg.Generation
		e.st.GenerationSeen = cfg.Generation
		e.st.IntentAttempts = 0
		e.st.IntentNextAt = time.Time{}
		if portsResult.SelfWriteHash != "" {
			e.st.LastSelfWriteHash = portsResult.SelfWriteHash
		}
		e.persist()

		events = append(events, SotEvent{
			Type: "csf_sot_applied", Severity: "info",
			Details: map[string]string{"generation": fmt.Sprintf("%d", cfg.Generation), "trigger": "intentional"},
		})
		e.buildSteadyReport(cfg, obs)

		return events
	}

	// Partial success (some list entries refused) or a hard error: do NOT
	// ack the generation, so the panel's rollout sees the failure.
	e.scheduleRetry(now)

	var errRef *csfsotwire.Refusal
	if hardError {
		if portsResult.Err != nil {
			errRef = portsResult.Err
		} else if listsResult.Err != nil {
			errRef = listsResult.Err
		}
	} else if len(allRefusals) > 0 {
		errRef = &allRefusals[0]
	}

	// Same generation-tagging gap as allRefusals above, for the single
	// hard-error case (reload_failed/rollback_failed/csf_not_installed):
	// the panel's onAgentReport checks
	// ($state->last_error['generation'] ?? null) === $item->target_generation
	// BEFORE it ever looks at $state->refused, so a hard error with no
	// Generation would never resolve a dispatched rollout item either.
	if errRef != nil {
		errRef.Generation = cfg.Generation
	}

	e.st.LastError = errRef
	e.persist()

	e.report.Store(&csfsotwire.Report{
		Active: true, Status: "error",
		GenerationSeen: e.st.GenerationSeen, GenerationAcked: e.st.GenerationAcked,
		Refused: capRefusals(allRefusals, 10), Error: errRef,
	})

	return events
}

func (e *SotEngine) scheduleRetry(now time.Time) {
	idx := e.st.IntentAttempts - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sotTiming().IntentBackoff) {
		e.st.IntentNextAt = time.Time{} // out of retries

		return
	}
	next := now.Add(sotTiming().IntentBackoff[idx])
	e.st.IntentNextAt = next
}

// applyRevert handles a new revert_token: apply the desired state once
// (same mechanics as an intentional change), then echo the token
// regardless of outcome -- the token is single-shot, re-delivery of the
// same token (even across a restart, since it's persisted) never
// re-applies.
func (e *SotEngine) applyRevert(ctx context.Context, cfg *csfsotwire.Config, obs sotObservation) []SotEvent {
	desired := csfsotwire.Managed{}
	if cfg.Desired != nil {
		desired = *cfg.Desired
	}

	portsResult := applyPortsFn(ctx, desired.Ports, obs)
	listsResult := applyListsFn(ctx, desired, obs, e.deps.PanelIP)

	e.st.LastRevertToken = *cfg.RevertToken
	if portsResult.SelfWriteHash != "" {
		e.st.LastSelfWriteHash = portsResult.SelfWriteHash
	}
	e.persist()

	events := []SotEvent{{
		Type: "csf_sot_corrected", Severity: "info",
		Details: map[string]string{"trigger": "revert"},
	}}

	allRefusals := append(append([]csfsotwire.Refusal{}, portsResult.Refusals...), listsResult.Refusals...)
	for _, r := range allRefusals {
		events = append(events, SotEvent{
			Type: "csf_sot_refused", Severity: "warning",
			Details: map[string]string{"reason": r.Reason, "detail": r.Detail, "trigger": "revert"},
		})
	}

	tok := *cfg.RevertToken
	status := "in_sync"
	if len(allRefusals) > 0 {
		status = "drift"
	}
	e.report.Store(&csfsotwire.Report{
		Active: true, Status: status,
		GenerationSeen: e.st.GenerationSeen, GenerationAcked: e.st.GenerationAcked,
		TokensAcked: csfsotwire.TokensAcked{Revert: &tok},
		Refused:     capRefusals(allRefusals, 10),
	})

	return events
}

// detectDrift compares desired vs observed in the engine's local
// state's bookkeeping (first-seen timestamps, seen-cycle counts),
// returning edge-triggered drift_detected/drift_resolved events. In
// warn mode nothing is ever written -- this is report-only. The
// automatic-correction decision itself is 16.1-11's maybeAutoCorrect
// hook, called here but a no-op in this plan.
func (e *SotEngine) detectDrift(ctx context.Context, cfg *csfsotwire.Config, obs sotObservation) []SotEvent {
	var events []SotEvent

	desired := csfsotwire.Managed{}
	if cfg.Desired != nil {
		desired = *cfg.Desired
	}

	selfWrite := e.st.LastSelfWriteHash != "" && e.st.LastSelfWriteHash == sotHash(obs.Managed)

	var drift []csfsotwire.DriftItem
	if !selfWrite {
		drift = diffSot(desired, obs.Managed)
	}

	for i := range drift {
		key := drift[i].Kind + ":" + drift[i].Key + ":" + drift[i].Value
		if fs, ok := e.st.DriftFirstSeen[key]; ok {
			drift[i].FirstSeen = fs
		} else {
			e.st.DriftFirstSeen[key] = e.deps.Now()
			drift[i].FirstSeen = e.deps.Now()
		}
		e.st.DriftSeenCycles[key]++
		drift[i].Hint = e.driftHint(obs)
	}

	// Record this cycle's IPv6 scope so the NEXT cycle's driftHint can
	// tell "just toggled" (scope_changed, this cycle) from "already
	// toggled a while ago" (settles back to a normal hint).
	ipv6Now := obs.IPv6
	e.st.LastIPv6 = &ipv6Now

	// Garbage-collect bookkeeping for keys no longer drifting.
	present := map[string]bool{}
	for _, d := range drift {
		present[d.Kind+":"+d.Key+":"+d.Value] = true
	}
	for k := range e.st.DriftFirstSeen {
		if !present[k] {
			delete(e.st.DriftFirstSeen, k)
			delete(e.st.DriftSeenCycles, k)
		}
	}

	wasReported := e.st.DriftReported
	nowDrifting := len(drift) > 0

	if nowDrifting && !wasReported {
		events = append(events, SotEvent{Type: "csf_sot_drift_detected", Severity: "warning"})
	} else if !nowDrifting && wasReported {
		events = append(events, SotEvent{Type: "csf_sot_drift_resolved", Severity: "info"})
	}
	e.st.DriftReported = nowDrifting

	autoRes := e.maybeAutoCorrect(ctx, cfg, obs, drift)
	events = append(events, autoRes.Events...)
	e.lastAuto = autoRes

	e.lastDrift = drift

	return events
}

// driftHint classifies WHY a drift item might exist, for UI copy.
func (e *SotEngine) driftHint(obs sotObservation) string {
	if obs.Testing {
		return "testing_mode"
	}

	snap := CurrentCSFSnapshot()
	if snap != nil && (snap.Fork != e.st.LastFork || snap.Version != e.st.LastVersion) {
		return "version_changed"
	}

	if e.st.LastIPv6 != nil && *e.st.LastIPv6 != obs.IPv6 {
		return "scope_changed"
	}

	if obs.DenyTotal >= obs.DenyIPLimit && obs.DenyIPLimit > 0 {
		return "removed_by_limit"
	}

	return "default"
}

// buildSteadyReport builds the heartbeat report for the normal
// (non-applying, non-snapshot) path, folding in maybeAutoCorrect's
// result (status override, hold reason, resume-token echo, refusals).
func (e *SotEngine) buildSteadyReport(cfg *csfsotwire.Config, obs sotObservation) {
	desired := csfsotwire.Managed{}
	if cfg.Desired != nil {
		desired = *cfg.Desired
	}

	auto := e.lastAuto

	status := "in_sync"
	if len(e.lastDrift) > 0 {
		status = "drift"
	}
	if auto.StatusOverride != "" {
		status = auto.StatusOverride
	}

	r := &csfsotwire.Report{
		Active: true, Status: status,
		GenerationSeen: e.st.GenerationSeen, GenerationAcked: e.st.GenerationAcked,
		DesiredHash: sotHash(desired), ObservedHash: sotHash(obs.Managed),
		Drift: capDrift(e.lastDrift, 50),
		IPv6:  obs.IPv6, ManagedKeys: obs.ManagedKeys, TaggedEntriesCount: len(obs.Managed.Allow) + len(obs.Managed.Deny),
		SSHPorts: nil, TestingMode: obs.Testing,
		Refused: capRefusals(append(append([]csfsotwire.Refusal{}, e.st.Refused...), auto.Refused...), 10), Error: e.st.LastError,
	}

	if cfg.Correction == "auto" {
		var holdReasonPtr *string
		if auto.HoldReason != "" {
			hr := auto.HoldReason
			holdReasonPtr = &hr
		}
		r.Auto = &csfsotwire.AutoInfo{FixesInWindow: auto.FixesInWindow, NextAt: auto.NextAt, HoldReason: holdReasonPtr}
	}

	if auto.ResumeTokenEcho != nil {
		r.TokensAcked.Resume = auto.ResumeTokenEcho
	}

	if status == "in_sync" {
		r.Observed = nil
	} else if r.ObservedHash != r.DesiredHash {
		if b, err := jsonSize(obs.Managed); err == nil && b <= 65536 {
			m := obs.Managed
			r.Observed = &m
		}
	}

	e.report.Store(r)
}

// buildApplyingReport reports the "applying" (intentional-change retry)
// state. Surfaces obs.Problems (read-only precheck, always current --
// unlike Refused/Error below, this costs nothing to recompute every
// cycle) AND e.st.LastError (the last ATTEMPT's actual failure reason,
// e.g. duplicate_key/reload_failed) persisted from the last cycle that
// actually ran applyPortsFn/applyListsFn -- without this, every cycle
// spent waiting for backoff or stuck at the retry ceiling reported
// "applying" with NO diagnostic information at all, even though the
// engine's own already-committed exhaustion comment ("stop trying until
// a new generation or an explicit retry_token") makes that silence
// permanent: a rollout item dispatched against an out-of-scope key
// (e.g. a duplicate_key csf.conf) stayed "applying" forever with an
// empty refused/problems/error, so nothing could ever tell the panel
// (or a human) why -- confirmed live, phase 16.1, 2026-11-20.
func (e *SotEngine) buildApplyingReport(cfg *csfsotwire.Config, obs sotObservation) {
	e.report.Store(&csfsotwire.Report{
		Active: true, Status: "applying",
		GenerationSeen: e.st.GenerationSeen, GenerationAcked: e.st.GenerationAcked,
		Retry:    &csfsotwire.RetryInfo{Count: e.st.IntentAttempts, NextAt: timePtr(e.st.IntentNextAt)},
		Problems: obs.Problems,
		Error:    e.st.LastError,
	})
}

func (e *SotEngine) persist() {
	_ = saveSotState(e.st)
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}

	return &t
}

func capDrift(d []csfsotwire.DriftItem, max int) []csfsotwire.DriftItem {
	if len(d) <= max {
		return d
	}

	return d[:max]
}

func capRefusals(r []csfsotwire.Refusal, max int) []csfsotwire.Refusal {
	if len(r) <= max {
		return r
	}

	return r[len(r)-max:]
}

func jsonSize(m csfsotwire.Managed) (int, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return 0, err
	}

	return len(b), nil
}
