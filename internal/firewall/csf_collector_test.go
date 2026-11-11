package firewall

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// withCollectorMarkers points csfSeenMarker/csfPausedMarker at a fresh temp
// directory, resets the in-memory paused flag and stored snapshot, and
// drains csfRefreshCh — all restored/cleared at test end. Every collector
// test uses this so none of them observe another test's state.
func withCollectorMarkers(t *testing.T) {
	t.Helper()
	tmp := t.TempDir()

	prevSeen, prevPaused := csfSeenMarker, csfPausedMarker
	csfSeenMarker = filepath.Join(tmp, "csf-seen")
	csfPausedMarker = filepath.Join(tmp, "csf-paused")

	prevPausedFlag := csfPaused.Load()
	prevSnapshot := csfSnapshot.Load()
	csfPaused.Store(false)
	csfSnapshot.Store(nil)
	drainRefreshCh()

	t.Cleanup(func() {
		csfSeenMarker = prevSeen
		csfPausedMarker = prevPaused
		csfPaused.Store(prevPausedFlag)
		csfSnapshot.Store(prevSnapshot)
		drainRefreshCh()
	})
}

func drainRefreshCh() {
	select {
	case <-csfRefreshCh:
	default:
	}
}

// withLookPath replaces the lookPath seam for the duration of the test.
func withLookPath(t *testing.T, fn func(string) (string, error)) {
	t.Helper()
	prev := lookPath
	lookPath = fn
	t.Cleanup(func() { lookPath = prev })
}

// withCSFExecTimeout overrides csfExecTimeout for the duration of the test.
func withCSFExecTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	prev := csfExecTimeout
	csfExecTimeout = d
	t.Cleanup(func() { csfExecTimeout = prev })
}

// storeCSFSnapshotForTest stores snap directly, bypassing CollectCSF — used
// to prove FirewallStatus() reads only the snapshot, never CSF itself.
func storeCSFSnapshotForTest(t *testing.T, snap *CSFSnapshot) {
	t.Helper()
	prev := csfSnapshot.Load()
	csfSnapshot.Store(snap)
	t.Cleanup(func() { csfSnapshot.Store(prev) })
}

// noRPMLookPath makes csfBinaryPath find the fixture binary (not on PATH,
// found via the hostRoot fallback) while rpm stays genuinely absent.
func noRPMLookPath(string) (string, error) { return "", exec.ErrNotFound }

// TestCollectCSFFixture proves a full collection pass against a real
// fixture (sentinel-15.13): fork/version/testing/lists/hash all come out
// correctly, including the Sentinel-specific version-string lag
// (csf -v says 15.11 though the release is 15.13 — pinned independently by
// TestFixtureSentinelVersionQuirk).
func TestCollectCSFFixture(t *testing.T) {
	withCollectorMarkers(t)
	tmp := t.TempDir()
	withHostRoot(t, tmp)
	withCSFDir(t, "testdata/sentinel-15.13")
	mustWriteFile(t, filepath.Join(tmp, "usr/sbin/csf"), "#!/bin/sh\n")
	withLookPath(t, noRPMLookPath)

	csfVOut, err := os.ReadFile(filepath.Join("testdata", "sentinel-15.13", "csf-v.txt"))
	if err != nil {
		t.Fatalf("read csf-v.txt: %v", err)
	}

	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		if name == "systemctl" {
			return []byte("active\n"), nil
		}
		return csfVOut, nil
	})

	snap := CollectCSF(context.Background())
	if snap == nil {
		t.Fatal("CollectCSF() = nil, want a snapshot")
	}
	if !snap.Installed {
		t.Error("snap.Installed = false, want true")
	}
	if snap.Fork != ForkSentinel {
		t.Errorf("snap.Fork = %q, want %q", snap.Fork, ForkSentinel)
	}
	if snap.Version != "15.11" {
		t.Errorf("snap.Version = %q, want %q (version.txt, the known Sentinel lag)", snap.Version, "15.11")
	}
	if snap.Testing == nil || *snap.Testing != false {
		t.Errorf("snap.Testing = %v, want *false", snap.Testing)
	}
	if snap.Deny.Total < 1 {
		t.Errorf("snap.Deny.Total = %d, want >= 1", snap.Deny.Total)
	}
	if snap.Allow.Total < 1 {
		t.Errorf("snap.Allow.Total = %d, want >= 1", snap.Allow.Total)
	}
	if len(snap.ListsHash) != 64 {
		t.Errorf("len(snap.ListsHash) = %d, want 64", len(snap.ListsHash))
	}
	if snap.CollectedAt.IsZero() {
		t.Error("snap.CollectedAt is zero, want set")
	}
}

// TestCollectorNonBlocking proves the heartbeat path can never be blocked
// by a slow collection: StartCSFCollector returns immediately (its first
// pass runs in the background goroutine too), and while that pass is stuck
// behind a runCmd stub that blocks until its context is done,
// CurrentCSFSnapshot() keeps returning instantly.
func TestCollectorNonBlocking(t *testing.T) {
	withCollectorMarkers(t)
	tmp := t.TempDir()
	withHostRoot(t, tmp)
	withCSFDir(t, "testdata/original-15.00")
	mustWriteFile(t, filepath.Join(tmp, "usr/sbin/csf"), "#!/bin/sh\n")
	withLookPath(t, noRPMLookPath)
	withCSFExecTimeout(t, 300*time.Millisecond)

	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})

	// Not deferred: this test explicitly waits for the background goroutine
	// to fully finish (see below) before returning, so it can never race
	// the next test's withHostRoot/withCSFDir t.Cleanup swaps.
	ctx, cancel := context.WithCancel(context.Background())

	start := time.Now()
	StartCSFCollector(ctx, time.Hour)
	if since := time.Since(start); since > 50*time.Millisecond {
		t.Fatalf("StartCSFCollector() blocked the caller for %s, want < 50ms", since)
	}

	for i := 0; i < 20; i++ {
		readStart := time.Now()
		_ = CurrentCSFSnapshot()
		if elapsed := time.Since(readStart); elapsed > 50*time.Millisecond {
			t.Fatalf("CurrentCSFSnapshot() call %d took %s while a collection was in progress, want < 50ms", i, elapsed)
		}
	}

	// Release the stuck collection and wait for it to actually finish
	// (ctx cancellation unblocks the stub, then CollectCSF still does a
	// little more pure-Go/file-read work under the current csfDir/hostRoot
	// seams before storing a snapshot and looping back to its select,
	// where it exits on ctx.Done()). Waiting for a non-nil snapshot here
	// is what prevents this goroutine from outliving the test and racing
	// the next test's seam swaps.
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for CurrentCSFSnapshot() == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if CurrentCSFSnapshot() == nil {
		t.Fatal("collector goroutine never finished after cancel — would leak past this test")
	}
}

// TestCollectCSFTimeoutBounded proves a hung CSF/systemctl does not hang
// CollectCSF forever: every command the stub is asked to run blocks for
// exactly the timeout it is handed, and the whole pass still finishes
// within a small bounded multiple of that timeout, falling back to
// version.txt (no exec) and reporting LFDRunning as unknown.
func TestCollectCSFTimeoutBounded(t *testing.T) {
	withCollectorMarkers(t)
	tmp := t.TempDir()
	withHostRoot(t, tmp)
	withCSFDir(t, "testdata/original-15.00")
	mustWriteFile(t, filepath.Join(tmp, "usr/sbin/csf"), "#!/bin/sh\n")
	withLookPath(t, noRPMLookPath)
	withCSFExecTimeout(t, 50*time.Millisecond)

	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-timer.C:
			return nil, fmt.Errorf("%s timed out after %s", name, d)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})

	start := time.Now()
	snap := CollectCSF(context.Background())
	elapsed := time.Since(start)

	if bound := 4*csfExecTimeout + time.Second; elapsed > bound {
		t.Fatalf("CollectCSF() took %s, want <= %s", elapsed, bound)
	}
	if snap == nil {
		t.Fatal("CollectCSF() = nil, want a snapshot (binary present, version.txt readable)")
	}
	if snap.Version != "15.00" {
		t.Errorf("snap.Version = %q, want %q (from version.txt despite every exec hanging)", snap.Version, "15.00")
	}
	if snap.LFDRunning != nil {
		t.Errorf("snap.LFDRunning = %v, want nil (systemctl hung too)", *snap.LFDRunning)
	}
}

// TestNoCSFNoExec is the COL-06 guarantee: on a server without CSF (and
// that has never had it), CollectCSF runs zero commands and opens no file
// under csfDir. Asserted by counting every command run(), not by eyeballing
// output — a stub that silently did nothing would still have to be
// *called* zero times to pass this.
func TestNoCSFNoExec(t *testing.T) {
	withCollectorMarkers(t)
	withHostRoot(t, t.TempDir())
	withCSFDir(t, filepath.Join(t.TempDir(), "does-not-exist"))
	withLookPath(t, func(string) (string, error) { return "", exec.ErrNotFound })

	var calls int
	var mu sync.Mutex
	restore := ObserveCommands(func(name string, args []string) {
		mu.Lock()
		calls++
		mu.Unlock()
	})
	t.Cleanup(restore)

	snap := CollectCSF(context.Background())
	if snap != nil {
		t.Fatalf("CollectCSF() = %#v, want nil", snap)
	}
	mu.Lock()
	got := calls
	mu.Unlock()
	if got != 0 {
		t.Errorf("observed %d commands, want 0", got)
	}
}

// TestCSFRemovedReportedOnce proves removed-after-seen: a host that had a
// seen marker but no binary reports Installed:false exactly once; after
// AckCSFRemovalReported() the marker is gone and CollectCSF goes back to
// returning nil (indistinguishable from "never had CSF").
func TestCSFRemovedReportedOnce(t *testing.T) {
	withCollectorMarkers(t)
	withHostRoot(t, t.TempDir())
	withCSFDir(t, t.TempDir())
	withLookPath(t, func(string) (string, error) { return "", exec.ErrNotFound })

	if err := writeMarker(csfSeenMarker); err != nil {
		t.Fatalf("writeMarker: %v", err)
	}

	snap := CollectCSF(context.Background())
	if snap == nil {
		t.Fatal("CollectCSF() = nil, want &CSFSnapshot{Installed:false}")
	}
	if snap.Installed {
		t.Errorf("snap.Installed = true, want false")
	}

	AckCSFRemovalReported()

	if seenMarkerExists() {
		t.Error("csfSeenMarker still exists after AckCSFRemovalReported()")
	}

	snap2 := CollectCSF(context.Background())
	if snap2 != nil {
		t.Fatalf("CollectCSF() after ack = %#v, want nil", snap2)
	}
}

// TestCSFSeenMarkerWritten proves the seen marker is created (mode 0600)
// the first time CSF is found present.
func TestCSFSeenMarkerWritten(t *testing.T) {
	withCollectorMarkers(t)
	tmp := t.TempDir()
	withHostRoot(t, tmp)
	withCSFDir(t, "testdata/original-15.00")
	mustWriteFile(t, filepath.Join(tmp, "usr/sbin/csf"), "#!/bin/sh\n")
	withLookPath(t, noRPMLookPath)

	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		return []byte("inactive\n"), nil
	})

	if seenMarkerExists() {
		t.Fatal("seen marker exists before any collection")
	}

	snap := CollectCSF(context.Background())
	if snap == nil {
		t.Fatal("CollectCSF() = nil, want a snapshot")
	}

	info, err := os.Stat(csfSeenMarker)
	if err != nil {
		t.Fatalf("stat csfSeenMarker: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("csfSeenMarker mode = %o, want 0600", info.Mode().Perm())
	}
}

// TestCSFPausedNoExecNoReads covers the full kill-switch lifecycle:
// SetCSFPaused(true) creates the marker and stops all collection (zero
// commands observed); LoadCSFPaused() on a fresh in-memory flag picks the
// marker back up (pause survives a restart); SetCSFPaused(false) removes
// the marker and triggers a refresh.
func TestCSFPausedNoExecNoReads(t *testing.T) {
	withCollectorMarkers(t)
	withHostRoot(t, t.TempDir())
	withCSFDir(t, t.TempDir())
	withLookPath(t, func(string) (string, error) { return "", exec.ErrNotFound })

	var calls int
	var mu sync.Mutex
	restore := ObserveCommands(func(name string, args []string) {
		mu.Lock()
		calls++
		mu.Unlock()
	})
	t.Cleanup(restore)

	if err := SetCSFPaused(true); err != nil {
		t.Fatalf("SetCSFPaused(true): %v", err)
	}
	if !CSFPaused() {
		t.Fatal("CSFPaused() = false after SetCSFPaused(true)")
	}
	if _, err := os.Stat(csfPausedMarker); err != nil {
		t.Fatalf("csfPausedMarker not created: %v", err)
	}

	snap := CollectCSF(context.Background())
	if snap != nil {
		t.Fatalf("CollectCSF() while paused = %#v, want nil", snap)
	}
	mu.Lock()
	got := calls
	mu.Unlock()
	if got != 0 {
		t.Errorf("observed %d commands while paused, want 0", got)
	}

	// Fresh in-memory state: LoadCSFPaused must pick the on-disk marker
	// back up — this is the "survives an agent restart" guarantee.
	csfPaused.Store(false)
	LoadCSFPaused()
	if !CSFPaused() {
		t.Error("LoadCSFPaused() did not pick up the on-disk pause marker")
	}

	if err := SetCSFPaused(false); err != nil {
		t.Fatalf("SetCSFPaused(false): %v", err)
	}
	if CSFPaused() {
		t.Error("CSFPaused() = true after SetCSFPaused(false)")
	}
	if _, err := os.Stat(csfPausedMarker); !os.IsNotExist(err) {
		t.Error("csfPausedMarker still exists after SetCSFPaused(false)")
	}
	select {
	case <-csfRefreshCh:
	default:
		t.Error("SetCSFPaused(false) did not request a refresh (csfRefreshCh empty)")
	}
}

// TestCollectorReadOnlyCommands records every command a full collection
// pass runs and asserts none of them is a mutating CSF flag — this package
// never writes to CSF, by design.
func TestCollectorReadOnlyCommands(t *testing.T) {
	withCollectorMarkers(t)
	tmp := t.TempDir()
	withHostRoot(t, tmp)
	withCSFDir(t, "testdata/original-15.00")
	mustWriteFile(t, filepath.Join(tmp, "usr/sbin/csf"), "#!/bin/sh\n")
	withLookPath(t, func(bin string) (string, error) {
		if bin == "rpm" {
			return "/usr/bin/rpm", nil
		}
		return "", exec.ErrNotFound
	})

	csfVOut, err := os.ReadFile(filepath.Join("testdata", "original-15.00", "csf-v.txt"))
	if err != nil {
		t.Fatalf("read csf-v.txt: %v", err)
	}

	var mu sync.Mutex
	var commands [][]string
	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		mu.Lock()
		commands = append(commands, append([]string{name}, args...))
		mu.Unlock()
		switch name {
		case "rpm":
			return nil, errors.New("package not installed")
		case "systemctl":
			return []byte("inactive\n"), nil
		default:
			return csfVOut, nil
		}
	})

	snap := CollectCSF(context.Background())
	if snap == nil {
		t.Fatal("CollectCSF() = nil, want a snapshot")
	}

	disallowed := []string{
		"-r", "-ra", "-f", "--flush", "-x", "--disable",
		"-e", "-d", "-a", "-dr", "-ar", "-td", "-tr",
	}

	for _, cmd := range commands {
		base := filepath.Base(cmd[0])
		switch base {
		case "csf", "rpm", "systemctl":
		default:
			t.Errorf("unexpected command name %q (full: %v)", cmd[0], cmd)
		}
		for _, arg := range cmd[1:] {
			for _, bad := range disallowed {
				if arg == bad {
					t.Errorf("observed disallowed mutating flag %q in command %v", bad, cmd)
				}
			}
		}
	}
	if len(commands) == 0 {
		t.Fatal("no commands were observed at all — the stub wiring is broken, not the guarantee")
	}
}

// TestFirewallStatusUsesSnapshot proves FirewallStatus() never runs a csf
// command: its CSF field comes entirely from whatever CSFSnapshot is
// already stored.
func TestFirewallStatusUsesSnapshot(t *testing.T) {
	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		if strings.Contains(strings.ToLower(name), "csf") {
			t.Fatalf("FirewallStatus() ran a csf command: %s %v", name, args)
		}
		return nil, nil
	})

	want := &CSFSnapshot{
		Installed: true,
		Version:   "15.99",
		PortsIn:   "22,80,443",
		PortsOut:  "80,443",
		Deny:      CSFList{Entries: []CSFListEntry{}, Total: 3},
		Allow:     CSFList{Entries: []CSFListEntry{}, Total: 1},
	}
	storeCSFSnapshotForTest(t, want)

	status := FirewallStatus()
	if status.CSF.Version != "15.99" {
		t.Errorf("FirewallStatus().CSF.Version = %q, want %q", status.CSF.Version, "15.99")
	}
	if status.CSF.DenyCount != 3 {
		t.Errorf("FirewallStatus().CSF.DenyCount = %d, want 3", status.CSF.DenyCount)
	}
	if status.CSF.AllowCount != 1 {
		t.Errorf("FirewallStatus().CSF.AllowCount = %d, want 1", status.CSF.AllowCount)
	}
}

// TestCSFInfoCompat proves CSFInfo() — the synchronous path Phase 14's lab
// integration tests call directly inside real VMs — still works end to end
// against a fixture.
func TestCSFInfoCompat(t *testing.T) {
	withCollectorMarkers(t)
	tmp := t.TempDir()
	withHostRoot(t, tmp)
	withCSFDir(t, "testdata/original-15.00")
	mustWriteFile(t, filepath.Join(tmp, "usr/sbin/csf"), "#!/bin/sh\n")
	withLookPath(t, noRPMLookPath)

	csfVOut, err := os.ReadFile(filepath.Join("testdata", "original-15.00", "csf-v.txt"))
	if err != nil {
		t.Fatalf("read csf-v.txt: %v", err)
	}

	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		if name == "systemctl" {
			return []byte("inactive\n"), nil
		}
		return csfVOut, nil
	})

	info := CSFInfo()
	if !info.Installed {
		t.Fatal("CSFInfo().Installed = false, want true")
	}
	if info.Version != "15.00" {
		t.Errorf("CSFInfo().Version = %q, want %q", info.Version, "15.00")
	}
	if info.PortsIn == "" {
		t.Error("CSFInfo().PortsIn is empty, want non-empty")
	}
	if info.DenyCount < 1 {
		t.Errorf("CSFInfo().DenyCount = %d, want >= 1", info.DenyCount)
	}
}

// TestCollectCSFDetectsCPanelViaRPM covers the one fork rule nothing else
// touches. detectFork's cpanel branch has two paths: `rpm -q cpanel-csf`
// succeeding, which is version-independent, and version >= 16 plus
// /usr/local/cpanel, which is only a fallback. Every other test in this
// package either injects RPMHasCPanelCSF already resolved
// (TestDetectForkSynthetic) or deliberately keeps rpm absent
// (noRPMLookPath), so the probe that produces that boolean — lookPath("rpm")
// then run(rpm -q cpanel-csf) — was never executed by any test, and there is
// no cpanel fixture or cpanel VM either.
//
// That matters because of what the fallback does not cover: cPanel ships CSF
// 15.x, and the version>=16 path cannot fire on it. So if the probe ever
// stops working — renamed package, moved call, rpm missing — a cPanel host
// does not degrade to "unknown", it is confidently reported as
// original-15.00, and phase 16's "fork has no maintainer" health rule would
// warn the largest installed base in the market. Forcing the boolean to false
// keeps this whole suite green, which is how that went unnoticed.
func TestCollectCSFDetectsCPanelViaRPM(t *testing.T) {
	// A cPanel host running CSF 15.00: the version fallback cannot save it,
	// so the rpm probe is the only thing standing between this and a wrong
	// fork. Uses the original-15.00 fixture because that is literally what
	// cPanel ships.
	setup := func(t *testing.T, rpmHasPackage bool) (*CSFSnapshot, func() [][]string) {
		t.Helper()
		withCollectorMarkers(t)
		tmp := t.TempDir()
		withHostRoot(t, tmp)
		withCSFDir(t, "testdata/original-15.00")
		mustWriteFile(t, filepath.Join(tmp, "usr/sbin/csf"), "#!/bin/sh\n")

		// rpm IS on this host (that is the point); csf is not on PATH, so
		// csfBinaryPath falls back to the fixture tree exactly as in
		// TestCollectCSFFixture.
		withLookPath(t, func(name string) (string, error) {
			if name == "rpm" {
				return "/usr/bin/rpm", nil
			}
			return "", exec.ErrNotFound
		})

		csfVOut, err := os.ReadFile(filepath.Join("testdata", "original-15.00", "csf-v.txt"))
		if err != nil {
			t.Fatalf("read csf-v.txt: %v", err)
		}

		var mu sync.Mutex
		var seen [][]string
		restore := ObserveCommands(func(name string, args []string) {
			mu.Lock()
			defer mu.Unlock()
			seen = append(seen, append([]string{name}, args...))
		})
		t.Cleanup(restore)

		withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
			if name == "rpm" {
				if rpmHasPackage {
					return []byte("cpanel-csf-15.00-1.noarch\n"), nil
				}
				return []byte("package cpanel-csf is not installed\n"), errors.New("exit status 1")
			}
			if name == "systemctl" {
				return []byte("active\n"), nil
			}
			return csfVOut, nil
		})

		snap := CollectCSF(context.Background())
		if snap == nil {
			t.Fatal("CollectCSF() = nil, want a snapshot")
		}
		return snap, func() [][]string {
			mu.Lock()
			defer mu.Unlock()
			return seen
		}
	}

	t.Run("package present", func(t *testing.T) {
		snap, calls := setup(t, true)

		if snap.Fork != ForkCPanel {
			t.Errorf("snap.Fork = %q, want %q — the rpm probe is the only cpanel signal on CSF 15.x", snap.Fork, ForkCPanel)
		}
		if !containsString(snap.ForkEvidence, "rpm:cpanel-csf") {
			t.Errorf("snap.ForkEvidence = %v, want it to cite rpm:cpanel-csf", snap.ForkEvidence)
		}

		// Pin the exact command, not just the outcome: querying the wrong
		// package name would silently stop detecting cPanel forever.
		var found bool
		for _, c := range calls() {
			if len(c) == 3 && c[0] == "rpm" && c[1] == "-q" && c[2] == "cpanel-csf" {
				found = true
			}
		}
		if !found {
			t.Errorf("commands run = %v, want one of them to be exactly [rpm -q cpanel-csf]", calls())
		}
	})

	t.Run("package absent", func(t *testing.T) {
		snap, _ := setup(t, false)

		// Same host, probe says no: this must NOT be cpanel, or the test
		// above would pass for the wrong reason.
		if snap.Fork == ForkCPanel {
			t.Errorf("snap.Fork = %q with cpanel-csf absent, want anything but cpanel", snap.Fork)
		}
	})
}
