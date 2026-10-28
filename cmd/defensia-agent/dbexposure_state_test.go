package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defensia/agent/internal/monitor"
)

// withTempStatePath points the state file at a temp dir for the duration of a test.
func withTempStatePath(t *testing.T) string {
	t.Helper()
	original := dbExposureStatePath
	path := filepath.Join(t.TempDir(), "db-exposure.json")
	dbExposureStatePath = path
	t.Cleanup(func() { dbExposureStatePath = original })
	return path
}

// The regression this file exists for. The exposure map used to live only in
// memory, so every agent restart established a fresh baseline and re-reported
// whatever was already reachable. Shipping two agent versions in one afternoon
// restarted the agent twice and posted the same critical alert three times to a
// customer who had already queried the first one.
func TestDBExposureStateSurvivesARestart(t *testing.T) {
	withTempStatePath(t)

	saveDBExposureState(map[int]monitor.Exposure{
		3306: monitor.ExposureWildcard,
		6379: monitor.ExposureLoopback,
	})

	// A "restart" is just a fresh load.
	got := loadDBExposureState()

	if len(got) != 2 {
		t.Fatalf("loaded %d entries, want 2: %+v", len(got), got)
	}
	if got[3306] != monitor.ExposureWildcard {
		t.Errorf("port 3306 = %q, want %q — an unchanged exposure would be re-reported", got[3306], monitor.ExposureWildcard)
	}
	if got[6379] != monitor.ExposureLoopback {
		t.Errorf("port 6379 = %q, want %q", got[6379], monitor.ExposureLoopback)
	}
}

// A missing file must read as "nothing known", which re-reports current state
// once. That is the safe direction: a duplicate row costs an operator nothing,
// whereas assuming "already reported" with no record would hide a live finding.
func TestDBExposureStateMissingFileYieldsEmpty(t *testing.T) {
	withTempStatePath(t)

	got := loadDBExposureState()
	if len(got) != 0 {
		t.Errorf("missing file loaded %d entries, want 0: %+v", len(got), got)
	}
}

// Same for a corrupt file: fail towards reporting, never towards silence.
func TestDBExposureStateCorruptFileYieldsEmpty(t *testing.T) {
	path := withTempStatePath(t)

	if err := os.WriteFile(path, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}

	got := loadDBExposureState()
	if len(got) != 0 {
		t.Errorf("corrupt file loaded %d entries, want 0: %+v", len(got), got)
	}
}

func TestDBExposureStateSkipsNonNumericKeys(t *testing.T) {
	path := withTempStatePath(t)

	if err := os.WriteFile(path, []byte(`{"3306":"wildcard","nonsense":"wildcard"}`), 0600); err != nil {
		t.Fatal(err)
	}

	got := loadDBExposureState()
	if len(got) != 1 || got[3306] != monitor.ExposureWildcard {
		t.Errorf("got %+v, want only port 3306", got)
	}
}

// The file names which database ports the host listens on, so it must not be
// world-readable.
func TestDBExposureStateIsNotWorldReadable(t *testing.T) {
	path := withTempStatePath(t)

	saveDBExposureState(map[int]monitor.Exposure{3306: monitor.ExposureWildcard})

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("permissions are %04o, want 0600", perm)
	}
}

// A replaced state file must never be observable as truncated: a half-written
// file would read as "nothing known" and re-report everything.
func TestDBExposureStateOverwriteLeavesNoTempFile(t *testing.T) {
	path := withTempStatePath(t)

	saveDBExposureState(map[int]monitor.Exposure{3306: monitor.ExposureWildcard})
	saveDBExposureState(map[int]monitor.Exposure{3306: monitor.ExposureLoopback})

	if got := loadDBExposureState(); got[3306] != monitor.ExposureLoopback {
		t.Errorf("port 3306 = %q after overwrite, want %q", got[3306], monitor.ExposureLoopback)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Error("the temp file was left behind")
	}
}

// An empty map is a legitimate state — no database ports listening — and must
// round-trip rather than being indistinguishable from a missing file. It cannot
// be, in practice, because an absent port is reported as a resolution by the
// caller; this pins that saving it does not error or leave junk.
func TestDBExposureStateEmptyMapRoundTrips(t *testing.T) {
	path := withTempStatePath(t)

	saveDBExposureState(map[int]monitor.Exposure{})

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("saving an empty map wrote no file: %v", err)
	}
	if got := loadDBExposureState(); len(got) != 0 {
		t.Errorf("got %+v, want empty", got)
	}
}
