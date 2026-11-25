package firewall

import (
	"os"
	"strconv"
	"time"
)

// Ban-executor tuning constants (SYNC-02, SYNC-04). Rate constants are
// derived from lab/reports/2026-11-25-1102-csf-td-bench.md
// (lab/csf-bench.sh), which measured real `csf -td`/`-tr` latency on 6 lab
// VMs across 4 CSF forks (original-15.00, aetherinox-15.10, sentinel-15.13,
// directadmin-15.12) at 100/500/1000 pre-existing temp bans — not guessed.
//
//	worst -td p95 @500 bans  = 188ms (alma9-csf-da, directadmin-15.12)
//	worst -td p95 @1000 bans = 229ms (alma9-csf-aetherinox, aetherinox-15.10)
//
// See that report for every per-fork/per-size p50/p95/max row.
const (
	// csfMinInterval: minimum spacing between consecutive csf -td/-tr
	// calls, so the ban queue never issues them back-to-back faster than
	// CSF itself can execute one. max(50ms, worst observed -td p95 @500
	// existing bans across all benchmarked forks), rounded up to 10ms:
	// max(50, 188) = 188, rounded up to 190ms.
	csfMinInterval = 190 * time.Millisecond

	// csfMaxOpsPerPass: how many ban ops the executor issues in one sync
	// pass before yielding, so a large backlog never blocks a sync cycle
	// for more than ~30s. floor(30s / (csfMinInterval + worst p95@500)),
	// clamped to [20, 200]: floor(30000 / (190 + 188)) = floor(79.4) = 79.
	csfMaxOpsPerPass = 79

	// csfMaxDefensiaTemp: hard cap on our OWN tagged (defensia:) temp
	// entries, independent of whatever DENY_TEMP_IP_LIMIT the customer has
	// configured (even if that's 0/unlimited) — a runaway ban storm must
	// not be able to grow CSF's own tempban file without bound. 500 since
	// worst p95@1000 (229ms) is well under the 2s threshold.
	csfMaxDefensiaTemp = 500

	csfReserveMin   = 10
	csfReserveRatio = 0.20

	csfMinTTL     = 60 * time.Second
	csfMaxTTL     = 30 * 24 * time.Hour
	csfRenewBelow = 7 * 24 * time.Hour
	csfLocalTTL   = 24 * time.Hour
	csfLocalGrace = 10 * time.Minute

	csfCmdTimeout = 10 * time.Second
	csfOutputCap  = 64 << 10 // 64 KiB

	csfDegradeAfter    = 3
	csfRecoverAfter    = 2
	csfRestartPatience = 90 * time.Second
)

// csfProbeEvery is a var (not a const) so the lab can shorten the probe
// interval (see defaultCSFProbeEvery) to prove recovery without waiting 5
// real minutes between probes — test override for the lab; production
// never sets the env var it reads, so it always gets the real default.
var csfProbeEvery = defaultCSFProbeEvery()

func defaultCSFProbeEvery() time.Duration {
	const def = 5 * time.Minute
	v := os.Getenv("DEFENSIA_CSF_PROBE_SECONDS")
	if v == "" {
		return def
	}
	secs, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	if secs < 5 {
		secs = 5
	}
	if secs > 3600 {
		secs = 3600
	}
	return time.Duration(secs) * time.Second
}

// MaxDefensiaTemp is a read-only accessor for integration tests asserting
// the hard cap on our own tagged temp entries is never exceeded.
func MaxDefensiaTemp() int { return csfMaxDefensiaTemp }

// SetCSFProbeInterval overrides csfProbeEvery at runtime, clamped the same
// way defaultCSFProbeEvery() clamps the env var — for the lab only. A
// DEFENSIA_CSF_PROBE_SECONDS env var is read exactly once, at package
// initialization (before any test function ever runs), so a test's own
// t.Setenv call has no effect on it whatsoever — every chaos/recovery test
// that needs a short probe cadence must call this instead (confirmed live
// in the lab, alma9-csf-orig, phase 18-10: a test that only called
// t.Setenv("DEFENSIA_CSF_PROBE_SECONDS", ...) silently kept the real
// 5-minute default the whole time, and recovery that needs
// csfRecoverAfter consecutive good probes never completed within any
// test's own short poll window). Returns a restore func so callers can
// t.Cleanup it back to whatever was active before.
func SetCSFProbeInterval(d time.Duration) (restore func()) {
	if d < 5*time.Second {
		d = 5 * time.Second
	}
	if d > time.Hour {
		d = time.Hour
	}
	old := csfProbeEvery
	csfProbeEvery = d
	return func() { csfProbeEvery = old }
}
