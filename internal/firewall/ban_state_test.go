package firewall

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBanStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "ban_executor.json")

	s := banState{Mode: "csf", Migrating: true, MigrationTarget: "csf", LastUndoToken: "abc", LastUndoRemoved: 3, UpdatedAt: "2026-11-25T00:00:00Z"}
	if err := saveBanState(path, s); err != nil {
		t.Fatalf("saveBanState: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}

	got := loadBanState(path)
	if got != s {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got, s)
	}

	// atomic: no leftover .tmp after a successful save
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf(".tmp file should not remain after a successful save")
	}

	// a stale .tmp from a previous crash is ignored and overwritten on the
	// next save, never read as if it were the real state.
	if err := os.WriteFile(path+".tmp", []byte("garbage-from-a-crash"), 0o600); err != nil {
		t.Fatal(err)
	}
	s2 := banState{Mode: "defensia"}
	if err := saveBanState(path, s2); err != nil {
		t.Fatalf("saveBanState (over stale .tmp): %v", err)
	}
	if got := loadBanState(path); got.Mode != "defensia" {
		t.Errorf("after overwriting stale .tmp: Mode = %q, want defensia", got.Mode)
	}
}

func TestBanStateMissingFile(t *testing.T) {
	dir := t.TempDir()
	got := loadBanState(filepath.Join(dir, "does-not-exist.json"))
	if got.Mode != "" {
		t.Errorf("Mode = %q, want \"\" (= defensia)", got.Mode)
	}
}

func TestBanStateCorruptJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ban_executor.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := loadBanState(path) // must not panic
	if got.Mode != "" {
		t.Errorf("Mode = %q, want \"\" after corrupt JSON", got.Mode)
	}
}
