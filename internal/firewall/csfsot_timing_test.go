package firewall

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
	"time"
)

func withTimingEnv(t *testing.T, env map[string]string) {
	t.Helper()
	for k, v := range env {
		prev, had := os.LookupEnv(k)
		os.Setenv(k, v)
		t.Cleanup(func() {
			if had {
				os.Setenv(k, prev)
			} else {
				os.Unsetenv(k)
			}
		})
	}
	resetSotTimingForTest()
	t.Cleanup(resetSotTimingForTest)
}

func TestTimingDefaults(t *testing.T) {
	withTimingEnv(t, map[string]string{})

	tm := sotTiming()

	if tm.Tick != 60*time.Second {
		t.Errorf("Tick = %v, want 60s", tm.Tick)
	}
	if tm.Settle != 120*time.Second {
		t.Errorf("Settle = %v, want 120s", tm.Settle)
	}
	want := []time.Duration{60 * time.Second, 300 * time.Second, 900 * time.Second}
	assertDurations(t, "AutoBackoff", tm.AutoBackoff, want)
	assertDurations(t, "IntentBackoff", tm.IntentBackoff, want)
	if tm.Window != time.Hour {
		t.Errorf("Window = %v, want 1h", tm.Window)
	}
	if tm.MaxAuto != 3 {
		t.Errorf("MaxAuto = %d, want 3", tm.MaxAuto)
	}
	if tm.StaleSync != 15*time.Minute {
		t.Errorf("StaleSync = %v, want 15m", tm.StaleSync)
	}
	if tm.Hold != 10*time.Minute {
		t.Errorf("Hold = %v, want 10m", tm.Hold)
	}
}

func assertDurations(t *testing.T, label string, got, want []time.Duration) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s = %v, want %v", label, got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("%s[%d] = %v, want %v", label, i, got[i], want[i])
		}
	}
}

func TestTimingOverrides(t *testing.T) {
	withTimingEnv(t, map[string]string{"DEFENSIA_CSFSOT_TICK_SECONDS": "2"})
	if tm := sotTiming(); tm.Tick != 5*time.Second {
		t.Errorf("TICK=2 -> Tick = %v, want 5s (clamped)", tm.Tick)
	}

	withTimingEnv(t, map[string]string{"DEFENSIA_CSFSOT_TICK_SECONDS": "10"})
	if tm := sotTiming(); tm.Tick != 10*time.Second {
		t.Errorf("TICK=10 -> Tick = %v, want 10s", tm.Tick)
	}

	withTimingEnv(t, map[string]string{"DEFENSIA_CSFSOT_SETTLE_SECONDS": "3"})
	if tm := sotTiming(); tm.Settle != 10*time.Second {
		t.Errorf("SETTLE=3 -> Settle = %v, want 10s (clamped)", tm.Settle)
	}

	withTimingEnv(t, map[string]string{"DEFENSIA_CSFSOT_SETTLE_SECONDS": "12"})
	tm := sotTiming()
	if tm.Settle != 12*time.Second {
		t.Errorf("SETTLE=12 -> Settle = %v, want 12s", tm.Settle)
	}
	assertDurations(t, "AutoBackoff (scaled)", tm.AutoBackoff, []time.Duration{6 * time.Second, 30 * time.Second, 90 * time.Second})
	if tm.Window != time.Hour || tm.MaxAuto != 3 || tm.StaleSync != 15*time.Minute || tm.Hold != 10*time.Minute {
		t.Errorf("non-overridable fields changed: %+v", tm)
	}

	withTimingEnv(t, map[string]string{"DEFENSIA_CSFSOT_TICK_SECONDS": "garbage"})
	if tm := sotTiming(); tm.Tick != 60*time.Second {
		t.Errorf("garbage TICK value changed Tick to %v, want default 60s", tm.Tick)
	}
}

func TestTimingLoggedOnce(t *testing.T) {
	withTimingEnv(t, map[string]string{"DEFENSIA_CSFSOT_TICK_SECONDS": "10"})

	var buf bytes.Buffer
	prevOut := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })

	sotTiming()
	sotTiming()
	sotTiming()

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	count := 0
	for _, l := range lines {
		if strings.Contains(l, "[csf-sot] lab timing override") {
			count++
		}
	}
	if count != 1 {
		t.Errorf("'[csf-sot] lab timing override' logged %d times across 3 sotTiming() calls, want exactly 1 (sync.Once)", count)
	}
}
