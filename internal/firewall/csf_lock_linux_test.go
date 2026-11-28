//go:build linux

package firewall

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestCSFRestartingExistenceAloneIsNotRestarting is the regression test for
// the lab-measured bug (plan 18-10, alma9-csf-orig): csf.lock is created
// once and never removed, so its mere existence must NOT be read as
// "restarting" — only an active exclusive lock on it should be.
func TestCSFRestartingExistenceAloneIsNotRestarting(t *testing.T) {
	old := csfVarDir
	dir := t.TempDir()
	csfVarDir = dir
	t.Cleanup(func() { csfVarDir = old })

	path := filepath.Join(dir, "csf.lock")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	if got := csfRestarting(); got {
		t.Error("csfRestarting() = true for a csf.lock that exists but is not actively locked by anyone")
	}
}

// TestCSFRestartingTrueWhileActivelyLocked proves the other half: while
// another process (standing in for a real `csf -r`) holds an exclusive
// lock on csf.lock, csfRestarting() must report true.
func TestCSFRestartingTrueWhileActivelyLocked(t *testing.T) {
	old := csfVarDir
	dir := t.TempDir()
	csfVarDir = dir
	t.Cleanup(func() { csfVarDir = old })

	path := filepath.Join(dir, "csf.lock")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	locker, err := os.OpenFile(path, os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Close()
	if err := syscall.Flock(int(locker.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatalf("flock: %v", err)
	}

	done := make(chan struct{})
	go func() {
		time.Sleep(200 * time.Millisecond)
		syscall.Flock(int(locker.Fd()), syscall.LOCK_UN)
		close(done)
	}()

	if got := csfRestarting(); !got {
		t.Error("csfRestarting() = false while another process actively holds an exclusive lock")
	}
	<-done

	if got := csfRestarting(); got {
		t.Error("csfRestarting() = true after the lock was released")
	}
}

// TestCSFRestartingMissingFile proves a missing csf.lock (never created, or
// removed) is treated as "not restarting" — fail open on the read side, the
// breaker's own evidence-based rules are what catch a genuinely misbehaving
// CSF, not this best-effort heuristic.
func TestCSFRestartingMissingFile(t *testing.T) {
	old := csfVarDir
	csfVarDir = t.TempDir()
	t.Cleanup(func() { csfVarDir = old })

	if got := csfRestarting(); got {
		t.Error("csfRestarting() = true for a missing csf.lock, want false")
	}
}
