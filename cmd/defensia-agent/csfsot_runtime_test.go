package main

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defensia/agent/internal/api"
	"github.com/defensia/agent/internal/csfsotwire"
	"github.com/defensia/agent/internal/firewall"
)

// fakeSotEngine is a test double for csfSotEngineIface: Cycle can be made
// to block, and every call is counted, without needing a real CSF
// install or the real engine's persisted state file.
type fakeSotEngine struct {
	mu          sync.Mutex
	cfg         *csfsotwire.Config
	report      *csfsotwire.Report
	cycleDelay  time.Duration
	cycleCalls  int32
	cycleEvents []firewall.SotEvent
	needsSync   bool
}

func (f *fakeSotEngine) SetConfig(c *csfsotwire.Config) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cfg = c
}

func (f *fakeSotEngine) configSnapshot() *csfsotwire.Config {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cfg
}

func (f *fakeSotEngine) Report() *csfsotwire.Report {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.report
}

func (f *fakeSotEngine) NeedsSync(h *csfsotwire.Hint) bool {
	return f.needsSync
}

func (f *fakeSotEngine) Cycle(ctx context.Context) []firewall.SotEvent {
	atomic.AddInt32(&f.cycleCalls, 1)
	if f.cycleDelay > 0 {
		time.Sleep(f.cycleDelay)
	}
	return f.cycleEvents
}

func (f *fakeSotEngine) calls() int32 {
	return atomic.LoadInt32(&f.cycleCalls)
}

func withFakeEngine(t *testing.T, f *fakeSotEngine) {
	t.Helper()
	prev := csfSotEngine
	csfSotEngine = f
	t.Cleanup(func() { csfSotEngine = prev })
}

func drainKick() {
	select {
	case <-csfSotKick:
	default:
	}
}

func TestRuntimeOnSyncSetsConfig(t *testing.T) {
	f := &fakeSotEngine{}
	withFakeEngine(t, f)
	drainKick()

	onSyncCSFSot(nil)
	if f.configSnapshot() != nil {
		t.Errorf("onSyncCSFSot(nil) must SetConfig(nil), got %+v", f.configSnapshot())
	}
	select {
	case <-csfSotKick:
	default:
		t.Errorf("onSyncCSFSot must kick a cycle (non-blocking send)")
	}

	cfg := &csfsotwire.Config{Mode: "defensia", Generation: 3}
	before := csfSotLastSyncOK()
	time.Sleep(1 * time.Millisecond)
	onSyncCSFSot(cfg)
	if f.configSnapshot() != cfg {
		t.Errorf("onSyncCSFSot(cfg) must SetConfig(cfg)")
	}
	if !csfSotLastSyncOK().After(before) {
		t.Errorf("onSyncCSFSot must update lastSyncOK")
	}
	select {
	case <-csfSotKick:
	default:
		t.Errorf("onSyncCSFSot must kick a cycle (non-blocking send)")
	}
}

func TestRuntimeHeartbeatFields(t *testing.T) {
	f := &fakeSotEngine{report: &csfsotwire.Report{Active: true, Status: "in_sync"}}
	withFakeEngine(t, f)

	caps, report := csfSotHeartbeatFields()
	if len(caps) != 1 || caps[0] != "csf_sot" {
		t.Errorf("capabilities = %v, want [csf_sot]", caps)
	}
	if report == nil || report.Status != "in_sync" {
		t.Errorf("report = %+v, want the engine's report", report)
	}

	f.mu.Lock()
	f.report = nil
	f.mu.Unlock()

	caps2, report2 := csfSotHeartbeatFields()
	if len(caps2) != 1 || caps2[0] != "csf_sot" {
		t.Errorf("capabilities must still be [csf_sot] when report is nil, got %v", caps2)
	}
	if report2 != nil {
		t.Errorf("report = %+v, want nil", report2)
	}
}

func TestRuntimeHintTriggersSync(t *testing.T) {
	resetCSFSotHintDebounceForTest()
	f := &fakeSotEngine{needsSync: true}
	withFakeEngine(t, f)

	var calls int32
	csfSotTriggerSync = func() { atomic.AddInt32(&calls, 1) }
	t.Cleanup(func() { csfSotTriggerSync = nil })

	onHeartbeatResponseCSFSot(&csfsotwire.Hint{Mode: "defensia"})
	waitForCalls(t, &calls, 1)

	onHeartbeatResponseCSFSot(&csfsotwire.Hint{Mode: "defensia"})
	time.Sleep(20 * time.Millisecond)
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("second hint within the debounce window: calls = %d, want 1", got)
	}

	f.needsSync = false
	onHeartbeatResponseCSFSot(&csfsotwire.Hint{Mode: "defensia"})
	time.Sleep(20 * time.Millisecond)
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("a hint equal to the last config must not trigger a sync: calls = %d, want 1", got)
	}
}

func waitForCalls(t *testing.T, counter *int32, want int32) {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(counter) >= want {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("triggerSync calls = %d, want >= %d", atomic.LoadInt32(counter), want)
}

func TestRuntimeEventsForwarded(t *testing.T) {
	f := &fakeSotEngine{
		cycleEvents: []firewall.SotEvent{
			{Type: "csf_sot_drift_detected", Severity: "warning", Details: map[string]string{"key": "TCP_IN"}},
			{Type: "csf_sot_applied", Severity: "info", Details: map[string]string{"generation": "3"}},
		},
	}
	withFakeEngine(t, f)

	var mu sync.Mutex
	var got []api.EventRequest
	client := &api.Client{}
	_ = client

	// csfSotEventSink is the seam startCSFSot normally points at
	// client.QueueEvent; redirect it here so the test does not need a
	// live network client.
	prevSink := csfSotEventSink
	csfSotEventSink = func(e api.EventRequest) {
		mu.Lock()
		got = append(got, e)
		mu.Unlock()
	}
	t.Cleanup(func() { csfSotEventSink = prevSink })

	csfSotRunCycle(context.Background())

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("forwarded %d events, want 2: %+v", len(got), got)
	}
	for _, e := range got {
		if e.OccurredAt == "" {
			t.Errorf("event %+v missing OccurredAt", e)
		}
		if _, err := time.Parse(time.RFC3339, e.OccurredAt); err != nil {
			t.Errorf("OccurredAt %q is not RFC3339 UTC: %v", e.OccurredAt, err)
		}
	}
}

func TestRuntimeLoopNotOnHeartbeatPath(t *testing.T) {
	f := &fakeSotEngine{report: &csfsotwire.Report{Status: "in_sync"}, cycleDelay: 2 * time.Second}
	withFakeEngine(t, f)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	csfSotEventSink = func(api.EventRequest) {}
	go csfSotLoop(ctx)

	// Give the loop a moment to start its first (slow) cycle.
	time.Sleep(10 * time.Millisecond)

	start := time.Now()
	csfSotHeartbeatFields()
	elapsed := time.Since(start)
	if elapsed > 50*time.Millisecond {
		t.Errorf("csfSotHeartbeatFields took %s while a Cycle was in flight, want < 50ms", elapsed)
	}
}

func TestRuntimeSnapshotDeps(t *testing.T) {
	var gotReq csfsotwire.SnapshotRequest
	fakePost := func(req csfsotwire.SnapshotRequest) (csfsotwire.SnapshotResponse, int, error) {
		gotReq = req
		return csfsotwire.SnapshotResponse{Accepted: true, Generation: 2}, 200, nil
	}

	resp, status, err := fakePost(csfsotwire.SnapshotRequest{ObservedHash: "abc"})
	if err != nil || status != 200 || !resp.Accepted || resp.Generation != 2 {
		t.Fatalf("unexpected result: resp=%+v status=%d err=%v", resp, status, err)
	}
	if gotReq.ObservedHash != "abc" {
		t.Errorf("gotReq = %+v, want ObservedHash abc", gotReq)
	}
}
