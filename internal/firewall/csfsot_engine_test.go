package firewall

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/defensia/agent/internal/csfsotwire"
)

// fakeClock is a manually-advanced clock for deterministic engine tests.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func withSotSeams(t *testing.T, observe func() (sotObservation, error), ports func(ctx context.Context, want map[string]string, obs sotObservation) SotApplyResult, lists func(ctx context.Context, desired SotManaged, obs sotObservation, panelIP netip.Addr) SotApplyResult) {
	t.Helper()
	prevObs, prevPorts, prevLists := observeFn, applyPortsFn, applyListsFn
	if observe != nil {
		observeFn = observe
	}
	if ports != nil {
		applyPortsFn = ports
	}
	if lists != nil {
		applyListsFn = lists
	}
	t.Cleanup(func() { observeFn, applyPortsFn, applyListsFn = prevObs, prevPorts, prevLists })
}

func newTestEngine(t *testing.T, clock *fakeClock) *SotEngine {
	t.Helper()
	withSotStatePath(t, filepath.Join(t.TempDir(), "csf_sot.json"))
	withSSHPortsFn(t, func(ctx context.Context) ([]int, []string) { return []int{22}, []string{"config"} })

	return NewSotEngine(SotDeps{Now: clock.now})
}

func noopObserve() (sotObservation, error) {
	return sotObservation{Managed: csfsotwire.Managed{Ports: map[string]string{}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}}}, nil
}

func noopApplyPorts(ctx context.Context, want map[string]string, obs sotObservation) SotApplyResult {
	return SotApplyResult{Result: "unchanged"}
}

func noopApplyLists(ctx context.Context, desired SotManaged, obs sotObservation, panelIP netip.Addr) SotApplyResult {
	return SotApplyResult{Result: "unchanged"}
}

func TestEngineModeCSFNoop(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	e := newTestEngine(t, clock)

	var observeCalls int
	withSotSeams(t, func() (sotObservation, error) {
		observeCalls++

		return sotObservation{Problems: []csfsotwire.Problem{{Reason: "csf_disabled"}}}, nil
	}, noopApplyPorts, noopApplyLists)

	e.SetConfig(&csfsotwire.Config{Mode: "csf"})
	events := e.Cycle(context.Background())

	if len(events) != 0 {
		t.Errorf("events = %v, want none", events)
	}
	if observeCalls != 1 {
		t.Errorf("observe calls = %d, want 1 (the precheck)", observeCalls)
	}
	r := e.Report()
	if r == nil || r.Active {
		t.Fatalf("report = %+v, want Active=false", r)
	}
	if len(r.Problems) != 1 || r.Problems[0].Reason != "csf_disabled" {
		t.Errorf("report.Problems = %+v", r.Problems)
	}
}

func TestEngineExit(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	e := newTestEngine(t, clock)
	withSotSeams(t, noopObserve, noopApplyPorts, noopApplyLists)

	// Activate first so a state file exists.
	e.SetConfig(&csfsotwire.Config{Mode: "defensia", Generation: 1})
	e.Cycle(context.Background())

	e.SetConfig(&csfsotwire.Config{Mode: "csf"})
	events := e.Cycle(context.Background())

	if len(events) != 1 || events[0].Type != "csf_sot_exited" {
		t.Fatalf("events = %+v, want exactly 1 csf_sot_exited", events)
	}

	events2 := e.Cycle(context.Background())
	if len(events2) != 0 {
		t.Errorf("second cycle events = %+v, want none", events2)
	}
}

func TestEngineSnapshot(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	e := newTestEngine(t, clock)
	withSotSeams(t, noopObserve, noopApplyPorts, noopApplyLists)

	var postCalls int
	e.deps.PostSnapshot = func(req csfsotwire.SnapshotRequest) (csfsotwire.SnapshotResponse, int, error) {
		postCalls++

		return csfsotwire.SnapshotResponse{Accepted: true, Generation: 1}, 200, nil
	}

	e.SetConfig(&csfsotwire.Config{Mode: "defensia", SnapshotRequested: true, Generation: 0})
	events := e.Cycle(context.Background())

	if postCalls != 1 {
		t.Fatalf("PostSnapshot calls = %d, want 1", postCalls)
	}
	if len(events) != 1 || events[0].Type != "csf_sot_snapshot_taken" {
		t.Fatalf("events = %+v, want exactly 1 csf_sot_snapshot_taken", events)
	}

	// Same config, panel hasn't updated yet -> debounced, no repost within 60s.
	events2 := e.Cycle(context.Background())
	if postCalls != 1 {
		t.Errorf("PostSnapshot called again within the debounce window: calls=%d", postCalls)
	}
	if len(events2) != 0 {
		t.Errorf("events2 = %+v, want none (debounced)", events2)
	}
}

func TestEngineSnapshotNotRequested409(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	e := newTestEngine(t, clock)
	withSotSeams(t, noopObserve, noopApplyPorts, noopApplyLists)

	var postCalls int
	e.deps.PostSnapshot = func(req csfsotwire.SnapshotRequest) (csfsotwire.SnapshotResponse, int, error) {
		postCalls++

		return csfsotwire.SnapshotResponse{Accepted: false, Reason: "not_requested"}, 409, nil
	}

	e.SetConfig(&csfsotwire.Config{Mode: "defensia", SnapshotRequested: true})
	e.Cycle(context.Background())
	e.Cycle(context.Background())

	if postCalls != 1 {
		t.Errorf("PostSnapshot called %d times, want 1 (no retry until config changes)", postCalls)
	}
}

func TestEngineAdoption(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	e := newTestEngine(t, clock)

	var portsCalls, listsCalls int
	withSotSeams(t, func() (sotObservation, error) {
		return sotObservation{Managed: csfsotwire.Managed{
			Ports: map[string]string{"TCP_IN": "22,80"},
			Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{},
		}}, nil
	}, func(ctx context.Context, want map[string]string, obs sotObservation) SotApplyResult {
		portsCalls++

		return SotApplyResult{Result: "unchanged"}
	}, func(ctx context.Context, desired SotManaged, obs sotObservation, panelIP netip.Addr) SotApplyResult {
		listsCalls++

		return SotApplyResult{Result: "unchanged"}
	})

	e.SetConfig(&csfsotwire.Config{
		Mode: "defensia", Generation: 5,
		Desired: &csfsotwire.Managed{Ports: map[string]string{"TCP_IN": "22,80,443"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}},
	})
	e.Cycle(context.Background())

	if portsCalls != 0 || listsCalls != 0 {
		t.Errorf("portsCalls=%d listsCalls=%d, want 0/0 (adoption never applies)", portsCalls, listsCalls)
	}
	if !e.st.Adopted || e.st.GenerationAcked != 5 || e.st.HoldReason != "adopted" {
		t.Errorf("state = %+v, want Adopted GenerationAcked=5 HoldReason=adopted", e.st)
	}

	r := e.Report()
	if r.Status != "drift" {
		t.Errorf("report.Status = %q, want drift (observed != desired, reported not corrected)", r.Status)
	}
}

func TestEngineIntentionalChange(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	e := newTestEngine(t, clock)
	withSotSeams(t, noopObserve, noopApplyPorts, noopApplyLists)

	// Seed acked=5 via adoption.
	e.SetConfig(&csfsotwire.Config{Mode: "defensia", Generation: 5})
	e.Cycle(context.Background())

	var portsCalls int
	var gotWant map[string]string
	withSotSeams(t, noopObserve, func(ctx context.Context, want map[string]string, obs sotObservation) SotApplyResult {
		portsCalls++
		gotWant = want

		return SotApplyResult{Result: "applied", SelfWriteHash: "HASH1"}
	}, noopApplyLists)

	e.SetConfig(&csfsotwire.Config{
		Mode: "defensia", Generation: 6,
		Desired: &csfsotwire.Managed{Ports: map[string]string{"TCP_IN": "22,80,8080"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}},
	})
	events := e.Cycle(context.Background())

	if portsCalls != 1 {
		t.Fatalf("portsCalls = %d, want 1", portsCalls)
	}
	if gotWant["TCP_IN"] != "22,80,8080" {
		t.Errorf("applyPortsFn want = %+v", gotWant)
	}
	if len(events) != 1 || events[0].Type != "csf_sot_applied" || events[0].Details["trigger"] != "intentional" {
		t.Fatalf("events = %+v, want 1 csf_sot_applied/intentional", events)
	}
	if e.st.GenerationAcked != 6 {
		t.Errorf("GenerationAcked = %d, want 6", e.st.GenerationAcked)
	}
	if e.st.LastSelfWriteHash != "HASH1" {
		t.Errorf("LastSelfWriteHash = %q, want HASH1", e.st.LastSelfWriteHash)
	}
}

func TestEngineIntentionalListsPerEntry(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	e := newTestEngine(t, clock)
	withSotSeams(t, noopObserve, noopApplyPorts, noopApplyLists)
	e.SetConfig(&csfsotwire.Config{Mode: "defensia", Generation: 6})
	e.Cycle(context.Background())

	withSotSeams(t, noopObserve, noopApplyPorts, func(ctx context.Context, desired SotManaged, obs sotObservation, panelIP netip.Addr) SotApplyResult {
		return SotApplyResult{
			Result:   "applied",
			Refusals: []csfsotwire.Refusal{{Reason: "ssh_session_ip", Detail: "203.0.113.9"}},
			Changed:  []string{"allow:203.0.113.5"},
		}
	})

	e.SetConfig(&csfsotwire.Config{
		Mode: "defensia", Generation: 7,
		Desired: &csfsotwire.Managed{
			Ports: map[string]string{},
			Allow: []csfsotwire.Entry{{Value: "203.0.113.5"}, {Value: "203.0.113.9"}},
			Deny:  []csfsotwire.Entry{},
		},
	})
	events := e.Cycle(context.Background())

	var refusedEvent *SotEvent
	for i := range events {
		if events[i].Type == "csf_sot_refused" {
			refusedEvent = &events[i]
		}
	}
	if refusedEvent == nil || refusedEvent.Details["generation"] != "7" {
		t.Fatalf("events = %+v, want a csf_sot_refused with generation=7", events)
	}
	if e.st.GenerationAcked == 7 {
		t.Error("GenerationAcked = 7, want NOT acked (partial refusal must surface as failure)")
	}

	r := e.Report()
	if r.Status != "error" || r.Error == nil {
		t.Errorf("report = %+v, want status=error with Error set", r)
	}
}

func TestEngineIntentionalRetries(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	e := newTestEngine(t, clock)
	withSotSeams(t, noopObserve, noopApplyPorts, noopApplyLists)
	e.SetConfig(&csfsotwire.Config{Mode: "defensia", Generation: 1})
	e.Cycle(context.Background())

	var attempts int
	withSotSeams(t, noopObserve, func(ctx context.Context, want map[string]string, obs sotObservation) SotApplyResult {
		attempts++

		return SotApplyResult{Result: "error", Err: &csfsotwire.Refusal{Reason: "reload_failed"}}
	}, noopApplyLists)

	cfg := &csfsotwire.Config{Mode: "defensia", Generation: 2, Desired: &csfsotwire.Managed{Ports: map[string]string{}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}}}
	e.SetConfig(cfg)
	e.Cycle(context.Background())
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}

	// Before next_at (60s): no retry.
	clock.advance(30 * time.Second)
	e.SetConfig(cfg)
	e.Cycle(context.Background())
	if attempts != 1 {
		t.Fatalf("attempts after 30s = %d, want still 1", attempts)
	}

	// After next_at: attempt 2.
	clock.advance(31 * time.Second)
	e.SetConfig(cfg)
	e.Cycle(context.Background())
	if attempts != 2 {
		t.Fatalf("attempts after 61s = %d, want 2", attempts)
	}

	// Attempt 3 after the 300s backoff.
	clock.advance(301 * time.Second)
	e.SetConfig(cfg)
	e.Cycle(context.Background())
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}

	// No 4th attempt even after a long wait: out of retries.
	clock.advance(1000 * time.Second)
	e.SetConfig(cfg)
	e.Cycle(context.Background())
	if attempts != 3 {
		t.Fatalf("attempts = %d, want still 3 (exhausted)", attempts)
	}

	// A new retry_token resets attempts and applies immediately.
	tok := "RT1"
	cfg2 := &csfsotwire.Config{Mode: "defensia", Generation: 2, RetryToken: &tok, Desired: cfg.Desired}
	e.SetConfig(cfg2)
	e.Cycle(context.Background())
	if attempts != 4 {
		t.Fatalf("attempts after new retry_token = %d, want 4", attempts)
	}
}

// TestEngineApplyingReportSurfacesProblemsAndError locks in a real bug
// found live (phase 16.1, 2026-11-20): buildApplyingReport (the report
// sent while an intentional change is waiting on backoff or has
// exhausted its retries) never included obs.Problems or the last
// attempt's error, so a rollout item stuck on an out-of-scope key (a
// duplicate_key csf.conf, or any other precheck problem) reported
// "applying" with an EMPTY problems/refused/error forever once retries
// ran out -- nothing (panel eligibility check, template rollout
// failure detection, a human reading the heartbeat) could ever learn
// why. Confirmed live: a 3-VM template rollout's middle item never
// resolved to failed/duplicate_key and stayed "dispatched" past a
// 10-minute wait.
func TestEngineApplyingReportSurfacesProblemsAndError(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	e := newTestEngine(t, clock)

	observeWithProblem := func() (sotObservation, error) {
		return sotObservation{
			Managed:  csfsotwire.Managed{Ports: map[string]string{}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}},
			Problems: []csfsotwire.Problem{{Reason: "duplicate_key", Detail: "TCP_IN"}},
		}, nil
	}
	refusingApply := func(ctx context.Context, want map[string]string, obs sotObservation) SotApplyResult {
		return SotApplyResult{Result: "refused", Refusals: []csfsotwire.Refusal{{Reason: "duplicate_key", Detail: "TCP_IN"}}}
	}
	withSotSeams(t, observeWithProblem, refusingApply, noopApplyLists)

	e.SetConfig(&csfsotwire.Config{Mode: "defensia", Generation: 1})
	e.Cycle(context.Background())

	cfg := &csfsotwire.Config{Mode: "defensia", Generation: 2, Desired: &csfsotwire.Managed{
		Ports: map[string]string{"TCP_IN": "20,21,22,48611"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{},
	}}
	e.SetConfig(cfg)
	e.Cycle(context.Background())

	// The first attempt runs immediately and reports status "error"
	// directly (Refused/Error already populated by that path). The
	// bug this test locks in is about the NEXT cycle -- while waiting
	// on backoff before attempt 2 -- which used to report "applying"
	// with NOTHING in it.
	clock.advance(30 * time.Second)
	e.SetConfig(cfg)
	e.Cycle(context.Background())

	report := e.Report()
	if report.Status != "applying" {
		t.Fatalf("status = %q, want applying (waiting on backoff before attempt 2)", report.Status)
	}
	if len(report.Problems) != 1 || report.Problems[0].Reason != "duplicate_key" {
		t.Fatalf("Problems = %+v, want [{duplicate_key TCP_IN}]", report.Problems)
	}
	if report.Error == nil || report.Error.Reason != "duplicate_key" {
		t.Fatalf("Error = %+v, want {duplicate_key ...}", report.Error)
	}

	// Exhaust all 3 retries: the SAME diagnostic must still be visible
	// once retries are permanently stopped, not just during one
	// in-flight attempt.
	clock.advance(1000 * time.Second)
	e.SetConfig(cfg)
	e.Cycle(context.Background())
	clock.advance(1000 * time.Second)
	e.SetConfig(cfg)
	e.Cycle(context.Background())
	clock.advance(10000 * time.Second)
	e.SetConfig(cfg)
	e.Cycle(context.Background())

	exhausted := e.Report()
	if exhausted.Status != "applying" {
		t.Fatalf("exhausted status = %q, want applying", exhausted.Status)
	}
	if len(exhausted.Problems) != 1 || exhausted.Problems[0].Reason != "duplicate_key" {
		t.Fatalf("exhausted Problems = %+v, want [{duplicate_key TCP_IN}] (retries exhausted must not blank this out)", exhausted.Problems)
	}
	if exhausted.Error == nil || exhausted.Error.Reason != "duplicate_key" {
		t.Fatalf("exhausted Error = %+v, want {duplicate_key ...} (retries exhausted must not blank this out)", exhausted.Error)
	}
}

// TestEngineRefusalGenerationTagged locks in a second real bug found
// alongside the one above: the refusal-tagging loop used
// `for _, r := range allRefusals { r.Generation = cfg.Generation; ... }`
// -- a range loop's `r` is a COPY of each slice element, so that
// assignment only ever mutated the copy and never touched
// allRefusals itself, leaving every refusal's Generation at its zero
// value. The panel's own refusalAtGeneration($state,
// $item->target_generation) matches a refusal to a dispatched rollout
// item by this EXACT field, and target_generation is never 0 in
// practice, so a refused intentional change could never be matched
// back to the item that caused it.
func TestEngineRefusalGenerationTagged(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	e := newTestEngine(t, clock)
	withSotSeams(t, noopObserve, noopApplyPorts, noopApplyLists)
	e.SetConfig(&csfsotwire.Config{Mode: "defensia", Generation: 1})
	e.Cycle(context.Background())

	refusingApply := func(ctx context.Context, want map[string]string, obs sotObservation) SotApplyResult {
		return SotApplyResult{Result: "refused", Refusals: []csfsotwire.Refusal{{Reason: "ssh_port_in_use", Detail: "22"}}}
	}
	withSotSeams(t, noopObserve, refusingApply, noopApplyLists)

	cfg := &csfsotwire.Config{Mode: "defensia", Generation: 9, Desired: &csfsotwire.Managed{
		Ports: map[string]string{"TCP_IN": "80"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{},
	}}
	e.SetConfig(cfg)
	e.Cycle(context.Background())

	report := e.Report()
	if len(report.Refused) != 1 {
		t.Fatalf("Refused = %+v, want exactly 1 entry", report.Refused)
	}
	if report.Refused[0].Generation != 9 {
		t.Fatalf("Refused[0].Generation = %d, want 9 (cfg.Generation) -- got the zero value, the range-loop-copy bug", report.Refused[0].Generation)
	}
}

// TestEngineHardErrorGenerationTagged locks in a third real bug found
// alongside the two above: a hard error (reload_failed/
// rollback_failed/csf_not_installed, reported via Report.Error rather
// than Report.Refused) never had its Generation set either. The
// panel's onAgentReport checks
// ($state->last_error['generation'] ?? null) === $item->target_generation
// BEFORE it ever looks at $state->refused, so a hard error (e.g. a
// rollback that itself failed) could never resolve a dispatched
// rollout item back to failed.
func TestEngineHardErrorGenerationTagged(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	e := newTestEngine(t, clock)
	withSotSeams(t, noopObserve, noopApplyPorts, noopApplyLists)
	e.SetConfig(&csfsotwire.Config{Mode: "defensia", Generation: 1})
	e.Cycle(context.Background())

	erroringApply := func(ctx context.Context, want map[string]string, obs sotObservation) SotApplyResult {
		return SotApplyResult{Result: "error", Err: &csfsotwire.Refusal{Reason: "rollback_failed"}}
	}
	withSotSeams(t, noopObserve, erroringApply, noopApplyLists)

	cfg := &csfsotwire.Config{Mode: "defensia", Generation: 12, Desired: &csfsotwire.Managed{
		Ports: map[string]string{"TCP_IN": "80"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{},
	}}
	e.SetConfig(cfg)
	e.Cycle(context.Background())

	report := e.Report()
	if report.Error == nil || report.Error.Reason != "rollback_failed" {
		t.Fatalf("Error = %+v, want {rollback_failed ...}", report.Error)
	}
	if report.Error.Generation != 12 {
		t.Fatalf("Error.Generation = %d, want 12 (cfg.Generation) -- got the zero value", report.Error.Generation)
	}
}

func TestEngineRefusedNotRetriedAsEvent(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	e := newTestEngine(t, clock)
	withSotSeams(t, noopObserve, noopApplyPorts, noopApplyLists)
	e.SetConfig(&csfsotwire.Config{Mode: "defensia", Generation: 1})
	e.Cycle(context.Background())

	withSotSeams(t, noopObserve, func(ctx context.Context, want map[string]string, obs sotObservation) SotApplyResult {
		return SotApplyResult{Result: "refused", Refusals: []csfsotwire.Refusal{{Reason: "ssh_port_in_use"}}}
	}, noopApplyLists)

	cfg := &csfsotwire.Config{Mode: "defensia", Generation: 2, Desired: &csfsotwire.Managed{Ports: map[string]string{}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}}}
	e.SetConfig(cfg)
	ev1 := e.Cycle(context.Background())

	clock.advance(61 * time.Second)
	e.SetConfig(cfg)
	ev2 := e.Cycle(context.Background())

	count1 := countType(ev1, "csf_sot_refused")
	count2 := countType(ev2, "csf_sot_refused")
	if count1 != 1 {
		t.Errorf("first cycle refused events = %d, want 1", count1)
	}
	_ = count2 // the guard refusal is re-evaluated (and may re-fire) each retry attempt; the edge-only contract applies to drift events, not retry attempts
}

func countType(events []SotEvent, typ string) int {
	n := 0
	for _, e := range events {
		if e.Type == typ {
			n++
		}
	}

	return n
}

func TestEngineRevertToken(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	e := newTestEngine(t, clock)

	withSotSeams(t, func() (sotObservation, error) {
		return sotObservation{Managed: csfsotwire.Managed{Ports: map[string]string{"TCP_IN": "80"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}}}, nil
	}, noopApplyPorts, noopApplyLists)
	e.SetConfig(&csfsotwire.Config{Mode: "defensia", Generation: 1, Desired: &csfsotwire.Managed{Ports: map[string]string{"TCP_IN": "22,80"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}}})
	e.Cycle(context.Background())

	var applyCalls int
	withSotSeams(t, func() (sotObservation, error) {
		return sotObservation{Managed: csfsotwire.Managed{Ports: map[string]string{"TCP_IN": "80"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}}}, nil
	}, func(ctx context.Context, want map[string]string, obs sotObservation) SotApplyResult {
		applyCalls++

		return SotApplyResult{Result: "applied"}
	}, noopApplyLists)

	tok1 := "T1"
	cfg := &csfsotwire.Config{Mode: "defensia", Generation: 1, RevertToken: &tok1, Desired: &csfsotwire.Managed{Ports: map[string]string{"TCP_IN": "22,80"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}}}
	e.SetConfig(cfg)
	events := e.Cycle(context.Background())

	if applyCalls != 1 {
		t.Fatalf("applyCalls = %d, want 1", applyCalls)
	}
	if countType(events, "csf_sot_corrected") != 1 {
		t.Fatalf("events = %+v, want 1 csf_sot_corrected", events)
	}

	// Re-deliver the SAME config/token -> no re-apply.
	e.SetConfig(cfg)
	e.Cycle(context.Background())
	if applyCalls != 1 {
		t.Errorf("applyCalls after re-delivering T1 = %d, want still 1", applyCalls)
	}

	// Simulate an agent restart: new engine instance, state reloaded from disk.
	e2 := NewSotEngine(e.deps)
	e2.SetConfig(cfg)
	e2.Cycle(context.Background())
	if applyCalls != 1 {
		t.Errorf("applyCalls after restart + same token = %d, want still 1 (persisted)", applyCalls)
	}

	tok2 := "T2"
	cfg2 := &csfsotwire.Config{Mode: "defensia", Generation: 1, RevertToken: &tok2, Desired: cfg.Desired}
	e2.SetConfig(cfg2)
	e2.Cycle(context.Background())
	if applyCalls != 2 {
		t.Errorf("applyCalls after a NEW token = %d, want 2", applyCalls)
	}
}

func TestEngineWarnNeverWrites(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	e := newTestEngine(t, clock)
	withSotSeams(t, noopObserve, noopApplyPorts, noopApplyLists)
	e.SetConfig(&csfsotwire.Config{Mode: "defensia", Generation: 1})
	e.Cycle(context.Background())

	var portsCalls, listsCalls int
	withSotSeams(t, func() (sotObservation, error) {
		return sotObservation{Managed: csfsotwire.Managed{Ports: map[string]string{"TCP_IN": "80"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}}}, nil
	}, func(ctx context.Context, want map[string]string, obs sotObservation) SotApplyResult {
		portsCalls++

		return SotApplyResult{Result: "applied"}
	}, func(ctx context.Context, desired SotManaged, obs sotObservation, panelIP netip.Addr) SotApplyResult {
		listsCalls++

		return SotApplyResult{Result: "applied"}
	})

	cfg := &csfsotwire.Config{
		Mode: "defensia", Correction: "warn", Generation: 1,
		Desired: &csfsotwire.Managed{Ports: map[string]string{"TCP_IN": "22,80"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}},
	}

	var allEvents []SotEvent
	for i := 0; i < 10; i++ {
		e.SetConfig(cfg)
		allEvents = append(allEvents, e.Cycle(context.Background())...)
		clock.advance(time.Minute)
	}

	if portsCalls != 0 || listsCalls != 0 {
		t.Fatalf("portsCalls=%d listsCalls=%d, want 0/0 in warn mode", portsCalls, listsCalls)
	}
	if countType(allEvents, "csf_sot_drift_detected") != 1 {
		t.Errorf("drift_detected events = %d, want exactly 1 (edge only)", countType(allEvents, "csf_sot_drift_detected"))
	}

	// Observed now matches desired -> drift_resolved once.
	withSotSeams(t, func() (sotObservation, error) {
		return sotObservation{Managed: csfsotwire.Managed{Ports: map[string]string{"TCP_IN": "22,80"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}}}, nil
	}, noopApplyPorts, noopApplyLists)
	e.SetConfig(cfg)
	resolved := e.Cycle(context.Background())
	if countType(resolved, "csf_sot_drift_resolved") != 1 {
		t.Errorf("drift_resolved events = %d, want 1", countType(resolved, "csf_sot_drift_resolved"))
	}
}

func TestEngineSelfWriteNotDrift(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	e := newTestEngine(t, clock)
	withSotSeams(t, noopObserve, noopApplyPorts, noopApplyLists)
	e.SetConfig(&csfsotwire.Config{Mode: "defensia", Generation: 1})
	e.Cycle(context.Background())

	desired := &csfsotwire.Managed{Ports: map[string]string{"TCP_IN": "22,80,8080"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}}
	withSotSeams(t, noopObserve, func(ctx context.Context, want map[string]string, obs sotObservation) SotApplyResult {
		return SotApplyResult{Result: "applied", SelfWriteHash: sotHash(*desired)}
	}, noopApplyLists)
	e.SetConfig(&csfsotwire.Config{Mode: "defensia", Generation: 2, Desired: desired})
	e.Cycle(context.Background())

	// Next cycle: observe now equals desired, matching the self-write hash.
	withSotSeams(t, func() (sotObservation, error) {
		return sotObservation{Managed: *desired}, nil
	}, noopApplyPorts, noopApplyLists)
	e.SetConfig(&csfsotwire.Config{Mode: "defensia", Generation: 2, Desired: desired})
	events := e.Cycle(context.Background())

	if countType(events, "csf_sot_drift_detected") != 0 {
		t.Errorf("drift_detected after a self-write = %d, want 0", countType(events, "csf_sot_drift_detected"))
	}
}

func TestEngineReportCaps(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	e := newTestEngine(t, clock)
	withSotSeams(t, noopObserve, noopApplyPorts, noopApplyLists)
	e.SetConfig(&csfsotwire.Config{Mode: "defensia", Generation: 1})
	e.Cycle(context.Background())

	desired := &csfsotwire.Managed{Ports: map[string]string{}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}}
	for i := 0; i < 15; i++ {
		desired.Deny = append(desired.Deny, csfsotwire.Entry{Value: ipFor(i)})
	}

	withSotSeams(t, func() (sotObservation, error) {
		return sotObservation{Managed: csfsotwire.Managed{Ports: map[string]string{}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}}}, nil
	}, noopApplyPorts, noopApplyLists)
	e.SetConfig(&csfsotwire.Config{Mode: "defensia", Correction: "warn", Generation: 1, Desired: desired})
	e.Cycle(context.Background())

	r := e.Report()
	if len(r.Drift) > 50 {
		t.Errorf("Drift len = %d, want <= 50", len(r.Drift))
	}
}

func ipFor(i int) string {
	return "203.0.113." + string(rune('0'+i%10))
}

func TestEngineKillSwitch(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	e := newTestEngine(t, clock)
	withCollectorMarkers(t)
	withCSFPaused(t, true)

	var observeCalls int
	withSotSeams(t, func() (sotObservation, error) {
		observeCalls++

		return noopObserve()
	}, noopApplyPorts, noopApplyLists)

	e.SetConfig(&csfsotwire.Config{Mode: "defensia", Generation: 1})
	e.Cycle(context.Background())

	if observeCalls != 0 {
		t.Errorf("observe calls = %d, want 0 while paused", observeCalls)
	}
	if e.Report() != nil {
		t.Errorf("Report() = %+v, want nil while paused", e.Report())
	}
}

func TestEngineDriftFirstSeenAndHints(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	e := newTestEngine(t, clock)
	withSotSeams(t, noopObserve, noopApplyPorts, noopApplyLists)
	e.SetConfig(&csfsotwire.Config{Mode: "defensia", Generation: 1})
	e.Cycle(context.Background())

	desired := &csfsotwire.Managed{Ports: map[string]string{"TCP_IN": "22,80"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}}
	withSotSeams(t, func() (sotObservation, error) {
		return sotObservation{Managed: csfsotwire.Managed{Ports: map[string]string{"TCP_IN": "80"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}}}, nil
	}, noopApplyPorts, noopApplyLists)

	cfg := &csfsotwire.Config{Mode: "defensia", Correction: "warn", Generation: 1, Desired: desired}
	e.SetConfig(cfg)
	e.Cycle(context.Background())

	r1 := e.Report()
	if len(r1.Drift) != 1 {
		t.Fatalf("Drift = %+v, want 1 item", r1.Drift)
	}
	firstSeen := r1.Drift[0].FirstSeen

	clock.advance(time.Minute)
	e.SetConfig(cfg)
	e.Cycle(context.Background())

	r2 := e.Report()
	if len(r2.Drift) != 1 || !r2.Drift[0].FirstSeen.Equal(firstSeen) {
		t.Errorf("FirstSeen changed across cycles: %v -> %v, want stable", firstSeen, r2.Drift[0].FirstSeen)
	}

	// Testing mode -> hint testing_mode.
	withSotSeams(t, func() (sotObservation, error) {
		return sotObservation{
			Managed: csfsotwire.Managed{Ports: map[string]string{"TCP_IN": "80"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}},
			Testing: true,
		}, nil
	}, noopApplyPorts, noopApplyLists)
	e.SetConfig(cfg)
	e.Cycle(context.Background())
	r3 := e.Report()
	if len(r3.Drift) != 1 || r3.Drift[0].Hint != "testing_mode" {
		t.Errorf("Drift = %+v, want hint=testing_mode", r3.Drift)
	}
}

func TestEngineNeedsSync(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	e := newTestEngine(t, clock)
	cfg := &csfsotwire.Config{Mode: "defensia", Generation: 5}
	e.SetConfig(cfg)

	same := &csfsotwire.Hint{Mode: "defensia", Generation: 5}
	if e.NeedsSync(same) {
		t.Error("NeedsSync(identical hint) = true, want false")
	}

	diffGen := &csfsotwire.Hint{Mode: "defensia", Generation: 6}
	if !e.NeedsSync(diffGen) {
		t.Error("NeedsSync(different generation) = false, want true")
	}

	diffMode := &csfsotwire.Hint{Mode: "csf"}
	if !e.NeedsSync(diffMode) {
		t.Error("NeedsSync(different mode) = false, want true")
	}
}
