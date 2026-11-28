package firewall

import (
	"testing"
	"time"
)

// TestSetCSFProbeIntervalClampsAndRestores is the regression test for the
// t.Setenv("DEFENSIA_CSF_PROBE_SECONDS", ...) no-op discovered live in the
// lab (phase 18-10, alma9-csf-orig): csfProbeEvery is read from that env
// var exactly once, at package init, so any test needing a short probe
// cadence must go through this runtime seam instead.
func TestSetCSFProbeIntervalClampsAndRestores(t *testing.T) {
	old := csfProbeEvery
	t.Cleanup(func() { csfProbeEvery = old })

	restore := SetCSFProbeInterval(2 * time.Second)
	if csfProbeEvery != 5*time.Second {
		t.Errorf("csfProbeEvery = %v, want clamped to the 5s floor", csfProbeEvery)
	}

	restore2 := SetCSFProbeInterval(10 * time.Second)
	if csfProbeEvery != 10*time.Second {
		t.Errorf("csfProbeEvery = %v, want 10s (within range)", csfProbeEvery)
	}

	restore3 := SetCSFProbeInterval(2 * time.Hour)
	if csfProbeEvery != time.Hour {
		t.Errorf("csfProbeEvery = %v, want clamped to the 1h ceiling", csfProbeEvery)
	}

	restore3()
	if csfProbeEvery != 10*time.Second {
		t.Errorf("csfProbeEvery after restore3() = %v, want the pre-restore3 value (10s)", csfProbeEvery)
	}
	restore2()
	if csfProbeEvery != 5*time.Second {
		t.Errorf("csfProbeEvery after restore2() = %v, want 5s", csfProbeEvery)
	}
	restore()
	if csfProbeEvery != old {
		t.Errorf("csfProbeEvery after restore() = %v, want the original %v", csfProbeEvery, old)
	}
}
