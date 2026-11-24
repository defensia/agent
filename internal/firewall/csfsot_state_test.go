package firewall

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func withSotStatePath(t *testing.T, path string) {
	t.Helper()
	prev := csfSotStatePath
	csfSotStatePath = path
	t.Cleanup(func() { csfSotStatePath = prev })
}

func TestStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	withSotStatePath(t, filepath.Join(dir, "nested", "csf_sot.json"))

	want := &sotLocalState{
		GenerationSeen:  3,
		GenerationAcked: 3,
		LastRevertToken: "T1",
		DriftFirstSeen:  map[string]time.Time{"TCP_IN": time.Now().Truncate(time.Second).UTC()},
		DriftSeenCycles: map[string]int{"TCP_IN": 2},
		Adopted:         true,
	}

	if err := saveSotState(want); err != nil {
		t.Fatalf("saveSotState: %v", err)
	}

	st, err := os.Stat(csfSotStatePath)
	if err != nil {
		t.Fatalf("stat state file: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("state file mode = %o, want 0600", st.Mode().Perm())
	}
	dirSt, err := os.Stat(filepath.Dir(csfSotStatePath))
	if err != nil {
		t.Fatalf("stat state dir: %v", err)
	}
	if dirSt.Mode().Perm() != 0o700 {
		t.Errorf("state dir mode = %o, want 0700", dirSt.Mode().Perm())
	}

	got, exists, err := loadSotState()
	if err != nil {
		t.Fatalf("loadSotState: %v", err)
	}
	if !exists {
		t.Fatal("exists = false, want true")
	}
	if got.GenerationAcked != 3 || got.LastRevertToken != "T1" || !got.Adopted {
		t.Errorf("loaded state = %+v, want matching want", got)
	}
	if got.DriftSeenCycles["TCP_IN"] != 2 {
		t.Errorf("DriftSeenCycles[TCP_IN] = %d, want 2", got.DriftSeenCycles["TCP_IN"])
	}
}

func TestStateLoadMissingIsNotAnError(t *testing.T) {
	withSotStatePath(t, filepath.Join(t.TempDir(), "absent", "csf_sot.json"))

	st, exists, err := loadSotState()
	if err != nil {
		t.Fatalf("loadSotState: %v", err)
	}
	if exists {
		t.Error("exists = true, want false for a missing file")
	}
	if st == nil {
		t.Fatal("state = nil, want a fresh zero-value state")
	}
}

func TestStateLoadCorruptNeverPanics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "csf_sot.json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0o600); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}
	withSotStatePath(t, path)

	st, exists, err := loadSotState()
	if err != nil {
		t.Fatalf("loadSotState returned an error for corrupt JSON, want nil (log + fresh state): %v", err)
	}
	if !exists {
		t.Error("exists = false, want true (the file DID exist, just unreadable)")
	}
	if st == nil {
		t.Fatal("state = nil, want a fresh zero-value state")
	}
}

func TestStateDelete(t *testing.T) {
	dir := t.TempDir()
	withSotStatePath(t, filepath.Join(dir, "csf_sot.json"))

	if err := saveSotState(&sotLocalState{GenerationAcked: 1}); err != nil {
		t.Fatalf("saveSotState: %v", err)
	}

	existed, err := deleteSotState()
	if err != nil {
		t.Fatalf("deleteSotState: %v", err)
	}
	if !existed {
		t.Error("existed = false, want true")
	}
	if _, err := os.Stat(csfSotStatePath); !os.IsNotExist(err) {
		t.Errorf("state file still exists after delete: %v", err)
	}

	existed2, err := deleteSotState()
	if err != nil {
		t.Fatalf("deleteSotState (missing file): %v", err)
	}
	if existed2 {
		t.Error("existed = true on a second delete, want false")
	}
}

func TestStateAtomicNoPartialFileOnWriteError(t *testing.T) {
	dir := t.TempDir()
	withSotStatePath(t, filepath.Join(dir, "csf_sot.json"))

	if err := saveSotState(&sotLocalState{GenerationAcked: 5}); err != nil {
		t.Fatalf("saveSotState (baseline): %v", err)
	}
	baseline, err := os.ReadFile(csfSotStatePath)
	if err != nil {
		t.Fatalf("read baseline: %v", err)
	}

	// Simulate a write failure by making the directory read-only so the
	// temp-file create fails; the final file must be untouched.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	defer os.Chmod(dir, 0o700)

	err = saveSotState(&sotLocalState{GenerationAcked: 99})
	if err == nil {
		t.Fatal("saveSotState with a read-only dir = nil error, want an error")
	}

	os.Chmod(dir, 0o700)
	after, err := os.ReadFile(csfSotStatePath)
	if err != nil {
		t.Fatalf("read after failed save: %v", err)
	}
	if string(after) != string(baseline) {
		t.Error("state file changed despite the simulated write failure (no atomicity)")
	}

	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != filepath.Base(csfSotStatePath) {
			t.Errorf("leftover temp file after a failed save: %s", e.Name())
		}
	}
}
