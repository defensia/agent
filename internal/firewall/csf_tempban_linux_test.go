//go:build linux

package firewall

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestReadTempBansLocked proves readTempBans() never returns an empty
// successful read while another process holds an exclusive lock on
// csf.tempban — it waits out the retry window and then reports
// ErrTempBanBusy. Runs only on Linux (flock semantics); exercised for real
// in the lab by plan 10.
func TestReadTempBansLocked(t *testing.T) {
	old := csfVarDir
	dir := t.TempDir()
	csfVarDir = dir
	t.Cleanup(func() { csfVarDir = old })

	path := filepath.Join(dir, "csf.tempban")
	if err := os.WriteFile(path, []byte("1730700000|203.0.113.7||in|3600|defensia:x\n"), 0o644); err != nil {
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
		time.Sleep(3 * time.Second)
		syscall.Flock(int(locker.Fd()), syscall.LOCK_UN)
		close(done)
	}()

	start := time.Now()
	_, err = readTempBans()
	elapsed := time.Since(start)

	if !errors.Is(err, ErrTempBanBusy) {
		t.Fatalf("err = %v, want ErrTempBanBusy", err)
	}
	if elapsed < 1800*time.Millisecond {
		t.Errorf("returned too early (%v) — did not really retry", elapsed)
	}

	<-done
}
