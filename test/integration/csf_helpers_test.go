//go:build integration

package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"sync"
	"testing"

	"github.com/defensia/agent/internal/firewall"
)

// csfConfPath is the one absolute path every helper in this file reads or
// writes — never a relative path, since the integration binary is pushed to
// and run from /root inside each lab VM, not from a checkout of this repo.
const csfConfPath = "/etc/csf/csf.conf"

// isCSFVM reports whether this VM is expected to have CSF installed at all
// (LAB_EXPECT_CSF=="1"). Every CSF-specific test in this package checks
// this first via requireEnv and returns early — never skips the test —
// when it is false: a non-CSF VM still counts as a PASS for every CSF-only
// assertion, exactly like the Phase 14 lab_csf_test.go tests already do
// for LAB_EXPECT_CSF.
func isCSFVM() bool {
	return env("LAB_EXPECT_CSF") == "1"
}

// confSHA returns the sha256 (hex) of /etc/csf/csf.conf's current bytes —
// the "did this round-trip byte-identically" check every port-change test
// in csf_ports_test.go relies on.
func confSHA(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(csfConfPath)
	if err != nil {
		t.Fatalf("read %s: %v", csfConfPath, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// snapshotConf backs up /etc/csf/csf.conf's current bytes+mode and
// registers a t.Cleanup that restores them, runs a real `csf -r` and
// asserts the LOCALINPUT chain is present again — but ONLY when the file
// still differs from the snapshot at test-end. A test whose own add+remove
// round-trip already restored csf.conf byte-for-byte triggers no extra
// restart here; a test that deliberately leaves csf.conf corrupted (the
// fault-injection rollback tests) gets exactly the real restore+restart+
// health-check this comment promises, proving the VM is left healthy no
// matter how the test ended.
func snapshotConf(t *testing.T) []byte {
	t.Helper()
	orig, err := os.ReadFile(csfConfPath)
	if err != nil {
		t.Fatalf("read %s: %v", csfConfPath, err)
	}
	info, err := os.Stat(csfConfPath)
	if err != nil {
		t.Fatalf("stat %s: %v", csfConfPath, err)
	}
	mode := info.Mode()

	t.Cleanup(func() {
		cur, err := os.ReadFile(csfConfPath)
		if err != nil {
			t.Errorf("snapshotConf cleanup: read %s: %v", csfConfPath, err)
			return
		}
		if string(cur) == string(orig) {
			return
		}
		if err := os.WriteFile(csfConfPath, orig, mode); err != nil {
			t.Errorf("snapshotConf cleanup: restore %s: %v", csfConfPath, err)
			return
		}
		if out, err := sh(t, "csf", "-r"); err != nil {
			t.Errorf("snapshotConf cleanup: csf -r after restore: %v (%s)", err, out)
		}
		if !chainPresent(t) {
			t.Errorf("snapshotConf cleanup: LOCALINPUT chain missing after restore+restart")
		}
		// A test that forces a failed restart (TestLabCSFPortRollback,
		// TestLabCSFPortRollbackFailed) can leave lfd dead even after
		// csf.conf is restored and csf -r succeeds again — observed live
		// in both the OrbStack lab (17-07-SUMMARY.md) and this suite's own
		// CI container run, and flagged twice now without ever being fixed
		// (Phase 15's independent review WARN-06; phase 17's independent
		// review WARN-09, 2026-11-18: "so a lab failure downstream can't be
		// laundered into 'environmental.'"). Only self-heal, never fail
		// THIS test over it: lfd's expected steady state varies by VM
		// (LAB_EXPECT_LFD is "inactive" on the deliberately-orphaned
		// alma8-csf-cwp-orphan, and TestLabCSFPortRollbackFailed already
		// has its own dedicated, lfdBefore-aware cleanup for the exact
		// "we just forced this" case) — a bare "want active" assertion
		// here would wrongly fail both of those. Restoring lfd quietly
		// when it was supposed to be active is what actually prevents the
		// downstream-test corruption WARN-09 is about; failing loudly on
		// every VM/test combination is not required for that and is what
		// broke this fix's first version (it tried to force lfd active on
		// the orphan VM and left it worse: inactive -> failed).
		if want := env("LAB_EXPECT_LFD"); want == "active" {
			if out, err := sh(t, "systemctl", "is-active", "lfd"); err != nil || out != "active" {
				t.Logf("snapshotConf cleanup: lfd is %q (err=%v), want %q — restarting", out, err, want)
				sh(t, "rm", "-f", "/etc/csf/csf.error")
				if out, err := sh(t, "systemctl", "restart", "lfd"); err != nil {
					t.Errorf("snapshotConf cleanup: systemctl restart lfd failed: %v (%s)", err, out)
				}
			}
		}
	})

	return orig
}

// backupFile is snapshotConf's sibling for a file that only needs its bytes
// restored — never a csf -r — because the test that uses it (the lists-cap
// test against csf.deny) only ever READS through the list, never applies
// it via CSF.
func backupFile(t *testing.T, path string) []byte {
	t.Helper()
	orig, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	mode := info.Mode()
	t.Cleanup(func() {
		if err := os.WriteFile(path, orig, mode); err != nil {
			t.Errorf("backupFile cleanup: restore %s: %v", path, err)
		}
	})
	return orig
}

// countCommands registers a firewall.ObserveCommands observer for the
// remainder of the test (restored via t.Cleanup) and returns a live counter
// plus a snapshot-of-calls-so-far accessor, both safe to call concurrently
// with the observer itself firing from other goroutines (StartCSFCollector
// runs on its own goroutine in the tests that use it).
func countCommands(t *testing.T) (count func() int, calls func() [][]string) {
	t.Helper()
	var mu sync.Mutex
	var recorded [][]string
	restore := firewall.ObserveCommands(func(name string, args []string) {
		mu.Lock()
		defer mu.Unlock()
		recorded = append(recorded, append([]string{name}, args...))
	})
	t.Cleanup(restore)
	count = func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(recorded)
	}
	calls = func() [][]string {
		mu.Lock()
		defer mu.Unlock()
		out := make([][]string, len(recorded))
		copy(out, recorded)
		return out
	}
	return count, calls
}

// forbiddenCSFArgs mirrors internal/firewall/csf_ports.go's own documented
// invariant: SafePortChange must never pass any of these to any executed
// command, on any path, including the critical rollback-failed one. This is
// the real-VM proof that the stubbed-only unit-test assertion of the same
// name (requireNeverFlush, 15-05) actually holds against a live csf -r.
var forbiddenCSFArgs = []string{"-f", "--flush", "-x", "--disable", "-e", "--enable", "-ra"}

// assertNoForbidden fails the test if any observed command (from
// countCommands' calls()) ever carried a forbiddenCSFArgs token.
func assertNoForbidden(t *testing.T, calls [][]string) {
	t.Helper()
	for _, call := range calls {
		for _, arg := range call {
			for _, forbidden := range forbiddenCSFArgs {
				if arg == forbidden {
					t.Fatalf("forbidden CSF argument %q observed in a real command: %v", forbidden, call)
				}
			}
		}
	}
}

// chainPresent reports whether `iptables -S LOCALINPUT` succeeds — the same
// health signal internal/firewall/csf_ports.go's healthCheckAfterRestart
// checks (outside TESTING mode).
func chainPresent(t *testing.T) bool {
	t.Helper()
	_, err := sh(t, "iptables", "-S", "LOCALINPUT")
	return err == nil
}

// defensiaBanRulePresent reports whether the defensia-bans ipset DROP rule
// is present in INPUT — the rule afterCSFRestart (internal/firewall/
// csf_ports.go) re-asserts after every completed csf -r, proven here
// against a real ipset-mode VM rather than a stub.
func defensiaBanRulePresent(t *testing.T) bool {
	t.Helper()
	_, err := sh(t, "iptables", "-C", "INPUT", "-m", "set", "--match-set", "defensia-bans", "src", "-j", "DROP")
	return err == nil
}
