package firewall

import (
	"log"
	"os"
	"strconv"
	"sync"
	"time"
)

// sotTimings are the source-of-truth feature's timing constants
// (CONTRACT §7). Only Tick/Settle (and backoffs scaled proportionally
// to Settle) are lab-overridable via environment; Window/MaxAuto/
// StaleSync/Hold are never overridable -- the hourly automatic-fix limit
// in particular must stay a real safety rail even in the lab.
type sotTimings struct {
	Tick          time.Duration
	Settle        time.Duration
	AutoBackoff   []time.Duration
	IntentBackoff []time.Duration
	Window        time.Duration
	MaxAuto       int
	StaleSync     time.Duration
	Hold          time.Duration
}

var (
	sotTimingOnce   sync.Once
	sotTimingCached sotTimings
)

// sotTiming returns the (cached, computed once) timing constants,
// applying any lab-only environment overrides exactly once per process
// lifetime (sync.Once) and logging a single line when one is present.
func sotTiming() sotTimings {
	sotTimingOnce.Do(func() {
		sotTimingCached = computeSotTiming()
	})

	return sotTimingCached
}

// resetSotTimingForTest clears the sync.Once so tests can re-read
// environment overrides within the same process.
func resetSotTimingForTest() {
	sotTimingOnce = sync.Once{}
}

// SotTickInterval is the only piece of sotTiming() cmd/defensia-agent
// needs to run the reconcile loop's own ticker (CONTRACT §7) — exported
// because sotTiming itself stays package-private (every other field is
// an engine-internal policy constant the runtime has no business
// reading directly).
func SotTickInterval() time.Duration {
	return sotTiming().Tick
}

func computeSotTiming() sotTimings {
	const (
		defaultTick   = 60 * time.Second
		defaultSettle = 120 * time.Second
	)

	tick := defaultTick
	settle := defaultSettle
	overridden := false

	if v := os.Getenv("DEFENSIA_CSFSOT_TICK_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			d := time.Duration(n) * time.Second
			if d < 5*time.Second {
				d = 5 * time.Second
			}
			tick = d
			overridden = true
		}
	}

	if v := os.Getenv("DEFENSIA_CSFSOT_SETTLE_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			d := time.Duration(n) * time.Second
			if d < 10*time.Second {
				d = 10 * time.Second
			}
			settle = d
			overridden = true
		}
	}

	backoff := scaleBackoff(settle, defaultSettle)

	if overridden {
		log.Printf("[csf-sot] lab timing override tick=%s settle=%s", tick, settle)
	}

	return sotTimings{
		Tick:          tick,
		Settle:        settle,
		AutoBackoff:   backoff,
		IntentBackoff: backoff,
		Window:        time.Hour,
		MaxAuto:       3,
		StaleSync:     15 * time.Minute,
		Hold:          10 * time.Minute,
	}
}

// scaleBackoff scales the production backoff schedule (60s/300s/900s)
// proportionally to how much Settle was shortened, with a 5s floor per
// step -- so a lab run with SETTLE=12 (12/120 = 1/10th) gets
// 6s/30s/90s instead of waiting a real 60-900s between lab retries.
func scaleBackoff(settle, defaultSettle time.Duration) []time.Duration {
	base := []time.Duration{60 * time.Second, 300 * time.Second, 900 * time.Second}
	if settle == defaultSettle {
		return base
	}

	ratio := float64(settle) / float64(defaultSettle)
	out := make([]time.Duration, len(base))
	for i, b := range base {
		d := time.Duration(float64(b) * ratio)
		if d < 5*time.Second {
			d = 5 * time.Second
		}
		out[i] = d
	}

	return out
}
