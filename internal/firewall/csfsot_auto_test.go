package firewall

import (
	"context"
	"testing"
	"time"

	"github.com/defensia/agent/internal/csfsotwire"
)

// newAutoTestEngine returns an auto-mode engine with generation already
// acked (so Cycle takes the drift-detection path) and a given
// LastSyncOK, ready to receive drift via the observeFn seam.
func newAutoTestEngine(t *testing.T, clock *fakeClock) (*SotEngine, *csfsotwire.Config) {
	t.Helper()
	e := newTestEngine(t, clock)
	withSotSeams(t, noopObserve, noopApplyPorts, noopApplyLists)
	e.deps.LastSyncOK = func() time.Time { return clock.now() }

	cfg := &csfsotwire.Config{Mode: "defensia", Correction: "auto", Generation: 1}
	e.SetConfig(cfg)
	e.Cycle(context.Background())

	// The adoption cycle sets a 10-minute "adopted" hold; these tests are
	// about the OTHER policy gates (settle, stale_sync, window, etc.), so
	// clear it here rather than making every single test advance the
	// clock past it first. TestAutoAdoptedHold below tests the hold
	// itself, on its own freshly-adopted engine.
	e.st.HoldUntil = time.Time{}
	e.st.HoldReason = ""

	return e, cfg
}

func driftingObserve(confAgeSeconds int) func() (sotObservation, error) {
	return func() (sotObservation, error) {
		return sotObservation{
			Managed:   csfsotwire.Managed{Ports: map[string]string{"TCP_IN": "80"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}},
			ConfMtime: time.Now().Add(-time.Duration(confAgeSeconds) * time.Second),
		}, nil
	}
}

func TestAutoSettleTwoCycles(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	e, cfg := newAutoTestEngine(t, clock)
	cfg.Desired = &csfsotwire.Managed{Ports: map[string]string{"TCP_IN": "22,80"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}}

	var applyCalls int
	applyFn := func(ctx context.Context, want map[string]string, obs sotObservation) SotApplyResult {
		applyCalls++

		return SotApplyResult{Result: "applied"}
	}

	// Cycle 1: drift just appeared -> settling (seen cycles = 1).
	withSotSeams(t, func() (sotObservation, error) {
		return sotObservation{Managed: csfsotwire.Managed{Ports: map[string]string{"TCP_IN": "80"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}}, ConfMtime: clock.now()}, nil
	}, applyFn, noopApplyLists)
	e.SetConfig(cfg)
	e.Cycle(context.Background())
	if applyCalls != 0 {
		t.Fatalf("cycle1: applyCalls = %d, want 0", applyCalls)
	}
	if e.Report().Auto == nil || e.Report().Auto.HoldReason == nil || *e.Report().Auto.HoldReason != "settling" {
		t.Fatalf("cycle1 Auto = %+v, want HoldReason=settling", e.Report().Auto)
	}

	// Cycle 2: 2nd consecutive cycle, but conf is only 30s old -> still settling.
	clock.advance(time.Second)
	withSotSeams(t, func() (sotObservation, error) {
		return sotObservation{Managed: csfsotwire.Managed{Ports: map[string]string{"TCP_IN": "80"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}}, ConfMtime: clock.now().Add(-30 * time.Second)}, nil
	}, applyFn, noopApplyLists)
	e.SetConfig(cfg)
	e.Cycle(context.Background())
	if applyCalls != 0 {
		t.Fatalf("cycle2: applyCalls = %d, want 0 (conf too fresh)", applyCalls)
	}

	// Cycle 3: conf 130s old -> apply.
	clock.advance(time.Second)
	withSotSeams(t, func() (sotObservation, error) {
		return sotObservation{Managed: csfsotwire.Managed{Ports: map[string]string{"TCP_IN": "80"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}}, ConfMtime: clock.now().Add(-130 * time.Second)}, nil
	}, applyFn, noopApplyLists)
	e.SetConfig(cfg)
	events := e.Cycle(context.Background())

	if applyCalls != 1 {
		t.Fatalf("cycle3: applyCalls = %d, want 1", applyCalls)
	}
	if countType(events, "csf_sot_corrected") != 1 {
		t.Fatalf("cycle3 events = %+v, want 1 csf_sot_corrected", events)
	}
	if e.Report().Auto.FixesInWindow != 1 {
		t.Errorf("FixesInWindow = %d, want 1", e.Report().Auto.FixesInWindow)
	}
}

func TestAutoAdoptedHold(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	e := newTestEngine(t, clock)
	withSotSeams(t, driftingObserve(130), func(ctx context.Context, want map[string]string, obs sotObservation) SotApplyResult {
		t.Fatal("applyPortsFn called during the adoption hold")

		return SotApplyResult{}
	}, noopApplyLists)

	cfg := &csfsotwire.Config{
		Mode: "defensia", Correction: "auto", Generation: 1,
		Desired: &csfsotwire.Managed{Ports: map[string]string{"TCP_IN": "22,80"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}},
	}
	e.SetConfig(cfg)
	e.Cycle(context.Background())

	if e.Report().Auto == nil || e.Report().Auto.HoldReason == nil || *e.Report().Auto.HoldReason != "adopted" {
		t.Fatalf("Auto = %+v, want HoldReason=adopted", e.Report().Auto)
	}
}

func TestAutoStaleSync(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	e, cfg := newAutoTestEngine(t, clock)
	cfg.Desired = &csfsotwire.Managed{Ports: map[string]string{"TCP_IN": "22,80"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}}

	lastSync := clock.now()
	e.deps.LastSyncOK = func() time.Time { return lastSync }

	var applyCalls int
	withSotSeams(t, driftingObserve(130), func(ctx context.Context, want map[string]string, obs sotObservation) SotApplyResult {
		applyCalls++

		return SotApplyResult{Result: "applied"}
	}, noopApplyLists)

	clock.advance(16 * time.Minute)
	e.SetConfig(cfg)
	e.Cycle(context.Background())

	if applyCalls != 0 {
		t.Fatalf("applyCalls = %d, want 0 (stale sync)", applyCalls)
	}
	if e.Report().Auto == nil || e.Report().Auto.HoldReason == nil || *e.Report().Auto.HoldReason != "stale_sync" {
		t.Fatalf("Auto = %+v, want HoldReason=stale_sync", e.Report().Auto)
	}
	if len(e.Report().Drift) == 0 {
		t.Error("Drift empty, want drift still reported during stale_sync")
	}
}

func TestAutoVersionChangedHold(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	e, cfg := newAutoTestEngine(t, clock)
	cfg.Desired = &csfsotwire.Managed{Ports: map[string]string{"TCP_IN": "22,80"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}}
	e.st.LastFork, e.st.LastVersion = "aetherinox", "15.00"

	var applyCalls int
	withSotSeams(t, driftingObserve(130), func(ctx context.Context, want map[string]string, obs sotObservation) SotApplyResult {
		applyCalls++

		return SotApplyResult{Result: "applied"}
	}, noopApplyLists)

	storeCSFSnapshotForTest(t, &CSFSnapshot{Fork: "aetherinox", Version: "15.10"})

	e.SetConfig(cfg)
	e.Cycle(context.Background())

	if applyCalls != 0 {
		t.Fatalf("applyCalls = %d, want 0 (version changed hold)", applyCalls)
	}
	if e.Report().Auto == nil || e.Report().Auto.HoldReason == nil || *e.Report().Auto.HoldReason != "version_changed" {
		t.Fatalf("Auto = %+v, want HoldReason=version_changed", e.Report().Auto)
	}

	clock.advance(11 * time.Minute)
	e.SetConfig(cfg)
	e.Cycle(context.Background())
	if applyCalls != 1 {
		t.Fatalf("applyCalls after hold expires = %d, want 1", applyCalls)
	}
}

func TestAutoForkUnknownReadonly(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	e, cfg := newAutoTestEngine(t, clock)
	cfg.Desired = &csfsotwire.Managed{Ports: map[string]string{"TCP_IN": "22,80"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}}

	var applyCalls int
	withSotSeams(t, driftingObserve(130), func(ctx context.Context, want map[string]string, obs sotObservation) SotApplyResult {
		applyCalls++

		return SotApplyResult{Result: "applied"}
	}, noopApplyLists)

	storeCSFSnapshotForTest(t, &CSFSnapshot{Fork: "unknown", Version: ""})

	e.SetConfig(cfg)
	e.Cycle(context.Background())

	if applyCalls != 0 {
		t.Fatalf("applyCalls = %d, want 0 (unknown fork)", applyCalls)
	}
	if e.Report().Status != "readonly" {
		t.Errorf("Status = %q, want readonly", e.Report().Status)
	}
}

func TestAutoRateLimitAndConflict(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	e, cfg := newAutoTestEngine(t, clock)
	cfg.Desired = &csfsotwire.Managed{Ports: map[string]string{"TCP_IN": "22,80"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}}

	var applyCalls int
	applyFn := func(ctx context.Context, want map[string]string, obs sotObservation) SotApplyResult {
		applyCalls++

		return SotApplyResult{Result: "applied"}
	}

	var allEvents []SotEvent
	runSettledCycle := func(confAge time.Duration) []SotEvent {
		withSotSeams(t, func() (sotObservation, error) {
			return sotObservation{Managed: csfsotwire.Managed{Ports: map[string]string{"TCP_IN": "80"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}}, ConfMtime: clock.now().Add(-confAge)}, nil
		}, applyFn, noopApplyLists)
		e.SetConfig(cfg)
		ev := e.Cycle(context.Background())
		allEvents = append(allEvents, ev...)

		return ev
	}

	// Cycle 1: not settled yet.
	runSettledCycle(130 * time.Second)
	// Cycle 2: settled (2 consecutive cycles seen) -> fix #1.
	clock.advance(time.Second)
	runSettledCycle(130 * time.Second)
	if applyCalls != 1 {
		t.Fatalf("after fix #1: applyCalls = %d, want 1", applyCalls)
	}

	// Fix #2: after the 60s backoff, re-settled.
	clock.advance(61 * time.Second)
	runSettledCycle(130 * time.Second)
	clock.advance(time.Second)
	runSettledCycle(130 * time.Second)
	if applyCalls != 2 {
		t.Fatalf("after fix #2: applyCalls = %d, want 2", applyCalls)
	}

	// Fix #3: after the 300s backoff. Once this 3rd fix lands, drift has
	// already been "seen" for many consecutive cycles (the mock keeps
	// re-presenting the same drift, simulating an external rewriter), so
	// the conflict can trip on the VERY NEXT evaluation after fix #3 --
	// not necessarily a distinct, later "4th drift incident" -- which is
	// why every event from here on is accumulated into allEvents instead
	// of checked per individual call.
	clock.advance(301 * time.Second)
	runSettledCycle(130 * time.Second)
	clock.advance(time.Second)
	runSettledCycle(130 * time.Second)
	if applyCalls != 3 {
		t.Fatalf("after fix #3: applyCalls = %d, want 3", applyCalls)
	}

	clock.advance(901 * time.Second)
	runSettledCycle(130 * time.Second)
	clock.advance(time.Second)
	runSettledCycle(130 * time.Second)

	if applyCalls != 3 {
		t.Fatalf("after the window fills: applyCalls = %d, want still 3", applyCalls)
	}
	if countType(allEvents, "csf_sot_conflict") != 1 {
		t.Fatalf("events = %+v, want exactly 1 csf_sot_conflict total", allEvents)
	}
	if e.Report().Status != "paused_conflict" {
		t.Errorf("Status = %q, want paused_conflict", e.Report().Status)
	}

	// Subsequent cycles: no apply, no repeated conflict event.
	clock.advance(time.Hour)
	runSettledCycle(130 * time.Second)
	if applyCalls != 3 || countType(allEvents, "csf_sot_conflict") != 1 {
		t.Errorf("subsequent cycle: applyCalls=%d totalConflictEvents=%d, want 3/1 (still no 2nd conflict)", applyCalls, countType(allEvents, "csf_sot_conflict"))
	}
}

func TestAutoWindowRolls(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	e, cfg := newAutoTestEngine(t, clock)
	cfg.Desired = &csfsotwire.Managed{Ports: map[string]string{"TCP_IN": "22,80"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}}

	var applyCalls int
	applyFn := func(ctx context.Context, want map[string]string, obs sotObservation) SotApplyResult {
		applyCalls++

		return SotApplyResult{Result: "applied"}
	}

	for i := 0; i < 5; i++ {
		withSotSeams(t, func() (sotObservation, error) {
			return sotObservation{Managed: csfsotwire.Managed{Ports: map[string]string{"TCP_IN": "80"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}}, ConfMtime: clock.now().Add(-130 * time.Second)}, nil
		}, applyFn, noopApplyLists)
		e.SetConfig(cfg)
		e.Cycle(context.Background())
		clock.advance(time.Second)
		e.SetConfig(cfg)
		e.Cycle(context.Background())
		clock.advance(2 * time.Hour) // well past the 1h window and any backoff
	}

	if applyCalls != 5 {
		t.Fatalf("applyCalls = %d, want 5 (corrections spaced > 1h never pause)", applyCalls)
	}
	if e.Report().Status == "paused_conflict" {
		t.Error("Status = paused_conflict, want never paused when spaced out")
	}
}

func TestAutoResumeToken(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	e, cfg := newAutoTestEngine(t, clock)
	e.st.Paused = true
	e.st.AutoFixes = []time.Time{clock.now(), clock.now(), clock.now()}

	withSotSeams(t, noopObserve, noopApplyPorts, noopApplyLists)
	e.SetConfig(cfg)
	events := e.Cycle(context.Background())
	if e.Report().Status != "paused_conflict" {
		t.Fatalf("Status = %q, want paused_conflict before resume", e.Report().Status)
	}
	_ = events

	tok := "R1"
	cfg2 := &csfsotwire.Config{Mode: "defensia", Correction: "auto", Generation: 1, ResumeToken: &tok}
	e.SetConfig(cfg2)
	e.Cycle(context.Background())

	if e.st.Paused {
		t.Error("st.Paused still true after resume_token")
	}
	if len(e.st.AutoFixes) != 0 {
		t.Errorf("AutoFixes = %v, want cleared", e.st.AutoFixes)
	}
	if e.Report().TokensAcked.Resume == nil || *e.Report().TokensAcked.Resume != "R1" {
		t.Errorf("TokensAcked.Resume = %v, want R1", e.Report().TokensAcked.Resume)
	}
}

func TestAutoGuardRefusalNoLoop(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	e, cfg := newAutoTestEngine(t, clock)
	cfg.Desired = &csfsotwire.Managed{Ports: map[string]string{"TCP_IN": "22,80"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}}

	var applyCalls int
	refusingApply := func(ctx context.Context, want map[string]string, obs sotObservation) SotApplyResult {
		applyCalls++

		return SotApplyResult{Result: "refused", Refusals: []csfsotwire.Refusal{{Reason: "ssh_port_in_use"}}}
	}

	withSotSeams(t, driftingObserve(130), refusingApply, noopApplyLists)
	e.SetConfig(cfg)
	e.Cycle(context.Background())
	clock.advance(time.Second)
	events := e.Cycle(context.Background())

	if applyCalls != 1 {
		t.Fatalf("applyCalls = %d, want 1 (counted as an attempt)", applyCalls)
	}
	if countType(events, "csf_sot_refused") != 1 {
		t.Fatalf("events = %+v, want 1 csf_sot_refused", events)
	}
}

func TestAutoScopeChangedNotCorrected(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	e, cfg := newAutoTestEngine(t, clock)
	cfg.Desired = &csfsotwire.Managed{Ports: map[string]string{"TCP_IN": "22,80"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}}

	// IPV6 toggled on since the last cycle: e.st.LastIPv6 disagrees with
	// the freshly observed obs.IPv6, which drives the scope_changed hint.
	ipv6Was := false
	e.st.LastIPv6 = &ipv6Was

	var applyCalls int
	withSotSeams(t, func() (sotObservation, error) {
		return sotObservation{
			Managed:   csfsotwire.Managed{Ports: map[string]string{"TCP_IN": "80"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}},
			ConfMtime: clock.now().Add(-130 * time.Second),
			IPv6:      true,
		}, nil
	}, func(ctx context.Context, want map[string]string, obs sotObservation) SotApplyResult {
		applyCalls++

		return SotApplyResult{Result: "applied"}
	}, noopApplyLists)

	// One cycle is enough: the hint is one-shot (LastIPv6 catches up to
	// the new scope right after this cycle), and the point of this test
	// is that scope_changed is never auto-corrected even once.
	e.SetConfig(cfg)
	e.Cycle(context.Background())

	if applyCalls != 0 {
		t.Errorf("applyCalls = %d, want 0 (scope_changed is reported, never auto-corrected)", applyCalls)
	}
	r := e.Report()
	found := false
	for _, d := range r.Drift {
		if d.Hint == "scope_changed" {
			found = true
		}
	}
	if !found {
		t.Errorf("Drift = %+v, want at least one item hinted scope_changed", r.Drift)
	}
}

func TestAutoOwnWriteNotCounted(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	e, cfg := newAutoTestEngine(t, clock)
	desired := &csfsotwire.Managed{Ports: map[string]string{"TCP_IN": "22,80"}, Allow: []csfsotwire.Entry{}, Deny: []csfsotwire.Entry{}}
	cfg.Desired = desired

	applyFn := func(ctx context.Context, want map[string]string, obs sotObservation) SotApplyResult {
		return SotApplyResult{Result: "applied", SelfWriteHash: sotHash(*desired)}
	}
	withSotSeams(t, driftingObserve(130), applyFn, noopApplyLists)
	e.SetConfig(cfg)
	e.Cycle(context.Background())
	clock.advance(time.Second)
	e.Cycle(context.Background())

	fixesAfterFirstFix := e.Report().Auto.FixesInWindow

	// Next cycle: observation now matches desired (the self-write landed).
	withSotSeams(t, func() (sotObservation, error) { return sotObservation{Managed: *desired}, nil }, noopApplyPorts, noopApplyLists)
	e.SetConfig(cfg)
	e.Cycle(context.Background())

	if e.Report().Auto.FixesInWindow != fixesAfterFirstFix {
		t.Errorf("FixesInWindow changed from %d to %d on a no-drift cycle", fixesAfterFirstFix, e.Report().Auto.FixesInWindow)
	}
}
