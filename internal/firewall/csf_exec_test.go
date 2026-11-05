package firewall

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestRunCmdTimeout proves a hung command is bounded: `sleep 5` under a 200ms
// timeout must return (with a non-nil error) well before the 5s the command
// would otherwise block for. This is the bug this task exists to fix — the
// original csfExec had no timeout and ran inside the heartbeat goroutine.
func TestRunCmdTimeout(t *testing.T) {
	start := time.Now()
	_, err := run(context.Background(), 200*time.Millisecond, "sleep", "5")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("run() with a 200ms timeout against `sleep 5` returned nil error, want timeout error")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("run() took %s to return after a 200ms timeout, want well under 3s", elapsed)
	}
}

// TestRunCmdObserver proves ObserveCommands sees every command run() executes,
// and that restore() detaches it again.
func TestRunCmdObserver(t *testing.T) {
	var gotName string
	var gotArgs []string

	restore := ObserveCommands(func(name string, args []string) {
		gotName = name
		gotArgs = args
	})

	if _, err := run(context.Background(), time.Second, "true"); err != nil {
		t.Fatalf("run(true) error = %v", err)
	}
	if gotName != "true" {
		t.Errorf("observer name = %q, want %q", gotName, "true")
	}
	if len(gotArgs) != 0 {
		t.Errorf("observer args = %v, want empty", gotArgs)
	}

	restore()
	gotName = ""
	if _, err := run(context.Background(), time.Second, "true"); err != nil {
		t.Fatalf("run(true) error = %v", err)
	}
	if gotName != "" {
		t.Errorf("observer still called after restore(): name = %q", gotName)
	}
}

// TestHostPath proves hostPath joins onto hostRoot — a no-op in production
// (hostRoot == "/") and a prefix onto a fixture tree in tests.
func TestHostPath(t *testing.T) {
	prev := hostRoot
	t.Cleanup(func() { hostRoot = prev })

	hostRoot = "/"
	if got := hostPath("/var/run/lfd.pid"); got != "/var/run/lfd.pid" {
		t.Errorf("hostPath(/var/run/lfd.pid) with hostRoot=/ = %q, want /var/run/lfd.pid", got)
	}

	tmp := t.TempDir()
	hostRoot = tmp
	want := filepath.Join(tmp, "var/run/lfd.pid")
	if got := hostPath("/var/run/lfd.pid"); got != want {
		t.Errorf("hostPath(/var/run/lfd.pid) with hostRoot=%s = %q, want %q", tmp, got, want)
	}
}

// TestCSFBinaryPathUncached proves csfBinaryPath re-checks the filesystem on
// every call (no sync.Once-style caching): with lookPath stubbed to fail and
// an empty fixture tree it returns "", and after a csf binary materializes at
// <hostRoot>/usr/sbin/csf a later call (same test run, no restart) finds it.
func TestCSFBinaryPathUncached(t *testing.T) {
	prevLookPath := lookPath
	prevHostRoot := hostRoot
	t.Cleanup(func() {
		lookPath = prevLookPath
		hostRoot = prevHostRoot
	})

	lookPath = func(string) (string, error) { return "", exec.ErrNotFound }
	tmp := t.TempDir()
	hostRoot = tmp

	if got := csfBinaryPath(); got != "" {
		t.Fatalf("csfBinaryPath() with no binary anywhere = %q, want empty", got)
	}

	binDir := filepath.Join(tmp, "usr/sbin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	binPath := filepath.Join(binDir, "csf")
	if err := os.WriteFile(binPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if got := csfBinaryPath(); got != binPath {
		t.Fatalf("csfBinaryPath() after creating %s = %q, want %q", binPath, got, binPath)
	}
}
