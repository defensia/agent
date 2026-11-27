//go:build integration

package integration

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defensia/agent/internal/api"
	"github.com/defensia/agent/internal/loadgen"
)

// TestLoadAggregation is the AGG-05 lab load test (19-13-PLAN.md): replay
// one virtual server-day of profile-shaped synthetic traffic through the
// REAL api.Client, against the REAL lab panel, via a REAL Sync handshake,
// and report exactly what the pipeline delivered — not a simulation of
// it. lab/load/run.sh runs this binary three times (LAB_LOAD_MODE=off,
// on, burst) from the SAME seed, and does the before/after row-count
// comparison itself by querying the panel's DB directly; this test's own
// job is only to drive the replay honestly and print one parseable
// LOAD_RESULT line of what happened on the wire.
func TestLoadAggregation(t *testing.T) {
	mode := requireEnv(t, "LAB_LOAD_MODE")
	switch mode {
	case "off", "on", "burst":
	default:
		t.Fatalf("LAB_LOAD_MODE must be off|on|burst, got %q", mode)
	}
	runID := requireEnv(t, "LAB_LOAD_RUN_ID")
	profilePath := requireEnv(t, "LAB_LOAD_PROFILE")
	panelURL := requireEnv(t, "LAB_PANEL_URL")
	token := readAgentToken(t)

	p, err := loadgen.LoadProfile(profilePath)
	if err != nil {
		t.Fatalf("load profile %s: %v", profilePath, err)
	}

	// dayStart anchors the virtual clock at today's UTC midnight — not
	// baseline's measured_at date, which has no bearing on correctness
	// here: every assertion (OFF vs ON, zero loss, criticals individual)
	// is keyed off details.load_run, not the calendar date the replayed
	// timestamps carry.
	dayStart := time.Now().UTC().Truncate(24 * time.Hour)

	var events []loadgen.Event
	if mode == "burst" {
		events = loadgen.Generate(p, 19, dayStart, runID, true)
	} else {
		events = loadgen.Generate(p, 19, dayStart, runID, false)
	}
	if len(events) == 0 {
		t.Fatalf("generator produced zero events for mode=%s", mode)
	}

	criticals := 0
	for _, e := range events {
		if e.Req.Severity == "critical" {
			criticals++
		}
	}

	c := api.New(panelURL, token)

	// vnow is the virtual clock driving the replay: it only ever moves
	// forward, to the timestamp of the event about to be queued, so the
	// Aggregator's window math and sendWithRetry's deadline math both see
	// the SAME simulated time the events themselves claim to occur at —
	// not the wall-clock time this test actually runs at.
	var vnowNano atomic.Int64
	vnowNano.Store(dayStart.UnixNano())
	c.SetClock(func() time.Time { return time.Unix(0, vnowNano.Load()).UTC() })

	c.StartEventConsumer()

	sync, err := c.Sync()
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	c.ConfigureAggregation(api.AggregationConfigFromSync(sync.Config.EventAggregation))

	// lab/load/run.sh turns aggregation ON for both mode=on and
	// mode=burst (burst is deliberately run WITH aggregation enabled —
	// it is the worst case precisely because even with the real
	// Aggregator active, IP-rotating traffic cannot be collapsed) and
	// OFF only for mode=off, so the expected handshake state is
	// "enabled unless mode==off", not "enabled only for mode==on".
	wantEnabled := mode != "off"
	if got := c.EventPipelineStats().AggregationEnabled; got != wantEnabled {
		t.Fatalf("after handshake: AggregationEnabled=%v, want %v (mode=%s)", got, wantEnabled, mode)
	}

	const maxQueueDepth = 1500
	for _, e := range events {
		for {
			depth, _ := c.EventQueueStats()
			if depth <= maxQueueDepth {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		vnowNano.Store(e.At.UnixNano())
		req := e.Req
		req.OccurredAt = e.At.UTC().Format(time.RFC3339)
		c.QueueEvent(req)
	}

	// Advance the virtual clock past the last event so every still-open
	// aggregation window closes, then give the 1s-cadence FlushDue
	// ticker time to actually pick it up before Shutdown's own forced
	// flush — proving the normal due-window path delivers, not just the
	// shutdown-time safety net.
	vnowNano.Store(events[len(events)-1].At.Add(10 * time.Minute).UnixNano())
	time.Sleep(2 * time.Second)

	c.Shutdown(120 * time.Second)

	stats := c.EventPipelineStats()

	cpuMS, rssKB := procSelfResourceUsage(t)

	fmt.Printf(
		"LOAD_RESULT mode=%s run=%s generated=%d criticals=%d batches=%d events_sent=%d retries=%d dropped_queue_full=%d dropped_send_failed=%d dropped_rejected=%d cpu_ms=%d rss_kb=%d\n",
		mode, runID, len(events), criticals,
		stats.BatchesSent, stats.EventsSent, stats.Retries,
		stats.DroppedQueueFull, stats.DroppedSendFailed, stats.DroppedRejected,
		cpuMS, rssKB,
	)

	if stats.DroppedQueueFull > 0 || stats.DroppedSendFailed > 0 || stats.DroppedRejected > 0 {
		t.Fatalf("event loss: dropped_queue_full=%d dropped_send_failed=%d dropped_rejected=%d",
			stats.DroppedQueueFull, stats.DroppedSendFailed, stats.DroppedRejected)
	}
	if stats.EventsSent == 0 {
		t.Fatalf("events_sent == 0 — nothing was actually delivered")
	}
}

// procSelfResourceUsage reads this process's own CPU time (user+system,
// in milliseconds) from /proc/self/stat and peak resident set size (in
// KB) from /proc/self/status — both Linux-only, which this test always
// is (it only ever runs inside a lab VM via lab/load/run.sh, never on
// the macOS host). Returns 0, 0 rather than failing the test if either
// file cannot be read, since these are reporting-only metrics, not
// correctness assertions.
func procSelfResourceUsage(t *testing.T) (cpuMS, rssKB int64) {
	t.Helper()

	if data, err := os.ReadFile("/proc/self/stat"); err == nil {
		// Field 2 (comm) may itself contain spaces inside parens, so
		// split on the closing paren first and then field-index from
		// there. utime is field 14, stime is field 15 (1-based, counting
		// from pid) i.e. indexes 11 and 12 in the post-")" field list.
		if close := strings.LastIndex(string(data), ")"); close != -1 {
			rest := strings.Fields(string(data)[close+1:])
			if len(rest) > 12 {
				utime, err1 := strconv.ParseInt(rest[11], 10, 64)
				stime, err2 := strconv.ParseInt(rest[12], 10, 64)
				if err1 == nil && err2 == nil {
					// Clock ticks to ms: sysconf(_SC_CLK_TCK) is 100 on
					// every lab VM kernel (standard for x86_64/arm64
					// Linux without CONFIG_HZ overrides) -> 10ms/tick.
					cpuMS = (utime + stime) * 10
				}
			}
		}
	}

	if f, err := os.Open("/proc/self/status"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "VmHWM:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if v, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
						rssKB = v
					}
				}
				break
			}
		}
	}

	return cpuMS, rssKB
}
