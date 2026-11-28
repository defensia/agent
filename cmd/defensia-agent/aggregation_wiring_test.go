package main

import (
	"os"
	"strings"
	"testing"
)

// This file asserts the phase 19 AGG-02/AGG-04 wiring by reading main.go's
// own source rather than exercising runAgent (which dials real sockets,
// starts goroutines and reads the host's firewall/filesystem state) — the
// same structural-test approach register_test.go/geoban_test.go's siblings
// use for things that are easier to prove about the source than to run.

func readMainSource(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	return string(data)
}

// funcBody returns the source of the named top-level function, from its
// "func name(" line up to (but not including) the next top-level "func "
// at column 0 (Go's gofmt never indents a top-level func keyword).
func funcBody(t *testing.T, src, name string) string {
	t.Helper()
	start := strings.Index(src, "func "+name+"(")
	if start == -1 {
		t.Fatalf("could not find func %s( in main.go", name)
	}
	rest := src[start+len("func "+name+"("):]
	next := strings.Index(rest, "\nfunc ")
	if next == -1 {
		return rest
	}
	return rest[:next]
}

// TestConfigureAggregationWiredAfterSuspendedEarlyReturn proves the
// handshake is applied on every normal sync, but not for a suspended
// agent: a suspended agent keeps its last aggregation config rather than
// being silently reconfigured by a sync it otherwise ignores.
func TestConfigureAggregationWiredAfterSuspendedEarlyReturn(t *testing.T) {
	src := readMainSource(t)
	body := funcBody(t, src, "syncAndApply")

	const wiring = `ConfigureAggregation(api.AggregationConfigFromSync(sync.Config.EventAggregation))`
	wiringIdx := strings.Index(body, wiring)
	if wiringIdx == -1 {
		t.Fatalf("syncAndApply does not call %s", wiring)
	}

	suspendedIdx := strings.Index(body, "sync.Config.Suspended")
	if suspendedIdx == -1 {
		t.Fatal("syncAndApply no longer has the suspended branch this test anchors against")
	}
	// The suspended branch's own early return must come before the
	// aggregation wiring textually, so a suspended sync never reaches it.
	suspendedReturnIdx := strings.Index(body[suspendedIdx:], "return nil")
	if suspendedReturnIdx == -1 {
		t.Fatal("could not find the suspended branch's early return")
	}
	if wiringIdx < suspendedIdx+suspendedReturnIdx {
		t.Fatal("ConfigureAggregation must appear AFTER the suspended block's early return, not before it")
	}
}

func TestShutdownCalledAfterQuitSignal(t *testing.T) {
	src := readMainSource(t)
	body := funcBody(t, src, "runAgent")

	quitIdx := strings.Index(body, "<-quit")
	if quitIdx == -1 {
		t.Fatal("runAgent no longer has the <-quit signal wait this test anchors against")
	}

	shutdownIdx := strings.Index(body, "apiClient.Shutdown(10 * time.Second)")
	if shutdownIdx == -1 {
		t.Fatal(`runAgent does not call apiClient.Shutdown(10 * time.Second)`)
	}
	if shutdownIdx < quitIdx {
		t.Fatal("apiClient.Shutdown must be called AFTER <-quit, not before it")
	}
}

func TestBothHeartbeatLiteralsCarryEventPipeline(t *testing.T) {
	src := readMainSource(t)

	count := strings.Count(src, "EventPipeline: apiClient.EventPipelineStats()")
	if count != 2 {
		t.Fatalf(`found %d occurrences of "EventPipeline: apiClient.EventPipelineStats()", want 2 (one per heartbeat literal)`, count)
	}
}

// reportEventsCallSites is the number of direct client.ReportEvents(/
// apiClient.ReportEvents( call sites in main.go as of this plan (phase 19
// AGG-02/AGG-04, plan 12): pinned so nobody accidentally reroutes a direct
// critical report through the aggregating queue in a later change. If this
// genuinely needs to change, update the pinned constant deliberately.
//
// 22 as of the phase 18 x phase 19 merge: phase 18's ban-executor status
// reporting added one more direct call site on top of phase 19's own 21.
const reportEventsCallSites = 22

func TestReportEventsCallSitesUnchanged(t *testing.T) {
	src := readMainSource(t)

	got := strings.Count(src, "ReportEvents(")
	if got != reportEventsCallSites {
		t.Fatalf("ReportEvents( call sites = %d, want %d (pinned) — a drop means a direct/critical report path got silently rerouted through the aggregating queue; an increase is fine, update the pinned constant", got, reportEventsCallSites)
	}
}

// minQueueEventCallSites is a floor, not a pin: new watchers are expected
// to add more QueueEvent( call sites over time, but this plan's wiring
// must never reduce the count below what existed before it.
const minQueueEventCallSites = 12

func TestQueueEventCallSitesStillPresent(t *testing.T) {
	src := readMainSource(t)

	got := strings.Count(src, "QueueEvent(")
	if got < minQueueEventCallSites {
		t.Fatalf("QueueEvent( call sites = %d, want >= %d", got, minQueueEventCallSites)
	}
}

// TestStartEventConsumerStillCalledOnce guards against the aggregation
// wiring accidentally dropping (or duplicating) the one call that starts
// the background consumer goroutine every watcher's QueueEvent relies on.
func TestStartEventConsumerStillCalledOnce(t *testing.T) {
	src := readMainSource(t)

	got := strings.Count(src, "apiClient.StartEventConsumer()")
	if got != 1 {
		t.Fatalf("apiClient.StartEventConsumer() call sites = %d, want 1", got)
	}
}

