//go:build integration

package integration

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/defensia/agent/internal/firewall"
)

// tcpInRe/tcp6InRe extract the raw TCP_IN/TCP6_IN value from a csf.conf
// byte slice this test package has already read off disk — kept local to
// this file (not exported by internal/firewall) since these tests assert
// against the real on-disk file independently of whatever the production
// parser decides to expose.
var (
	tcpInRe    = regexp.MustCompile(`(?m)^TCP_IN\s*=\s*"([^"]*)"`)
	tcp6InRe   = regexp.MustCompile(`(?m)^TCP6_IN\s*=\s*"([^"]*)"`)
	ipv6FlagRe = regexp.MustCompile(`(?m)^IPV6\s*=\s*"[^"]*"`)

	// corruptTCPInRe/corruptTCPInVal: the one fault-injection corruption
	// used by both rollback tests below. Verified live against all 6 lab
	// CSF forks before being written into this test (see 15-07-SUMMARY.md):
	// `csf -r` with TCP_IN containing the out-of-range port 99999 exits 1
	// and prints "Error: FASTSTART: (TCP_IN IPv4) ... invalid port/service
	// `99999' specified" on original-15.00, aetherinox, sentinel,
	// directadmin and the cwp-orphan (TESTING=1) VM alike — one
	// deterministic corruption, same in every VM, no per-fork branching.
	corruptTCPInRe  = regexp.MustCompile(`(?m)^TCP_IN\s*=\s*"[^"]*"`)
	corruptTCPInVal = `TCP_IN = "22,99999"`
)

func tcpInValue(t *testing.T, data []byte) string {
	t.Helper()
	m := tcpInRe.FindSubmatch(data)
	if m == nil {
		t.Fatalf("no TCP_IN line found in csf.conf")
	}
	return string(m[1])
}

func tcp6InValue(t *testing.T, data []byte) string {
	t.Helper()
	m := tcp6InRe.FindSubmatch(data)
	if m == nil {
		t.Fatalf("no TCP6_IN line found in csf.conf")
	}
	return string(m[1])
}

// corruptTCPIn is the integration-only fault function installed via
// firewall.SetCSFFaultHook: it rewrites TCP_IN to a value every one of the
// lab's CSF forks rejects (see corruptTCPInVal's doc comment above),
// preserving the file's existing mode bits.
func corruptTCPIn(confPath string) error {
	info, err := os.Stat(confPath)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(confPath)
	if err != nil {
		return err
	}
	corrupted := corruptTCPInRe.ReplaceAll(data, []byte(corruptTCPInVal))
	return os.WriteFile(confPath, corrupted, info.Mode())
}

// portInList reports whether port (as a bare decimal string) appears as a
// standalone, comma-separated token in value.
func portInList(value, port string) bool {
	for _, tok := range strings.Split(value, ",") {
		if strings.TrimSpace(tok) == port {
			return true
		}
	}
	return false
}

// TestLabCSFPortAddRemove proves SafePortChange's full happy path against a
// real csf.conf and a real `csf -r`: add applies, TCP_IN actually contains
// the new port, the LOCALINPUT chain survives, the defensia-bans DROP rule
// survives the restart on ipset-mode VMs, lfd's running state is
// unperturbed, a backup file lands on disk, and remove round-trips
// csf.conf back to byte-identical. Non-CSF VMs: not applicable, PASS.
func TestLabCSFPortAddRemove(t *testing.T) {
	requireRoot(t)
	if requireEnv(t, "LAB_EXPECT_CSF") != "1" {
		return
	}
	snapshotConf(t)
	ctx := context.Background()

	pre := confSHA(t)
	var lfdBefore *bool
	if s := firewall.CollectCSF(ctx); s != nil {
		lfdBefore = s.LFDRunning
	}

	res := firewall.SafePortChange(ctx, firewall.PortChangeRequest{Port: 48211, Direction: "in", Action: "add"}, firewall.PortChangeOptions{})
	if res.Result != "applied" {
		t.Fatalf("add 48211 in = %+v, want applied", res)
	}

	data, err := os.ReadFile(csfConfPath)
	if err != nil {
		t.Fatalf("read %s: %v", csfConfPath, err)
	}
	if tcpIn := tcpInValue(t, data); !portInList(tcpIn, "48211") {
		t.Fatalf("TCP_IN = %q after add, want it to contain 48211", tcpIn)
	}
	if !chainPresent(t) {
		t.Fatalf("LOCALINPUT chain missing after add")
	}

	if env("LAB_EXPECT_FW_MODE") == "ipset" {
		if !defensiaBanRulePresent(t) {
			t.Fatalf("defensia-bans DROP rule missing after csf -r (ipset mode)")
		}
	}

	if lfdBefore != nil {
		s := firewall.CollectCSF(ctx)
		if s == nil || s.LFDRunning == nil {
			t.Fatalf("lfd running state unreadable after the port add (before=%v)", *lfdBefore)
		}
		if *s.LFDRunning != *lfdBefore {
			t.Fatalf("lfd running state changed by the port add: before=%v after=%v", *lfdBefore, *s.LFDRunning)
		}
	}

	entries, err := os.ReadDir("/etc/defensia/csf-backups")
	if err != nil || len(entries) < 1 {
		t.Fatalf("csf-backups dir empty or unreadable after a successful change: %v (entries=%d)", err, len(entries))
	}

	res2 := firewall.SafePortChange(ctx, firewall.PortChangeRequest{Port: 48211, Direction: "in", Action: "remove"}, firewall.PortChangeOptions{})
	if res2.Result != "applied" {
		t.Fatalf("remove 48211 in = %+v, want applied", res2)
	}

	if got := confSHA(t); got != pre {
		t.Fatalf("csf.conf sha = %s after add+remove round-trip, want original %s", got, pre)
	}
}

// TestLabCSFPortIdempotent proves adding a port already present in TCP_IN
// (every lab CSF VM ships 22 in TCP_IN by default) is reported "unchanged"
// and never runs `csf -r` at all — a real-VM proof of 15-05's
// guard-before-write ordering, not just a stub assertion.
func TestLabCSFPortIdempotent(t *testing.T) {
	requireRoot(t)
	if requireEnv(t, "LAB_EXPECT_CSF") != "1" {
		return
	}
	snapshotConf(t)
	_, calls := countCommands(t)

	res := firewall.SafePortChange(context.Background(), firewall.PortChangeRequest{Port: 22, Direction: "in", Action: "add"}, firewall.PortChangeOptions{})
	if res.Result != "unchanged" {
		t.Fatalf("add 22 in (already present) = %+v, want unchanged", res)
	}
	for _, call := range calls() {
		for _, arg := range call {
			if arg == "-r" {
				t.Fatalf("csf -r observed for a no-op port change: %v", call)
			}
		}
	}
}

// TestLabCSFPortSSHGuard proves the SSH lockout guard against a real
// `sshd -T`/`ss` on this VM: removing port 22 (the SSH port every lab VM
// actually listens on) is rejected, csf.conf is left byte-identical, and
// `csf -r` never runs — activeSSHPorts' union-of-sources design (15-05)
// exercised against the real binaries for the first time.
func TestLabCSFPortSSHGuard(t *testing.T) {
	requireRoot(t)
	if requireEnv(t, "LAB_EXPECT_CSF") != "1" {
		return
	}
	snapshotConf(t)
	pre := confSHA(t)
	_, calls := countCommands(t)

	res := firewall.SafePortChange(context.Background(), firewall.PortChangeRequest{Port: 22, Direction: "in", Action: "remove"}, firewall.PortChangeOptions{})
	if res.Result != "rejected" || res.Reason != "ssh_port_in_use" {
		t.Fatalf("remove 22 in = %+v, want rejected/ssh_port_in_use", res)
	}
	if got := confSHA(t); got != pre {
		t.Fatalf("csf.conf sha changed on a rejected SSH-guard removal: %s -> %s", pre, got)
	}
	for _, call := range calls() {
		for _, arg := range call {
			if arg == "-r" {
				t.Fatalf("csf -r observed for a rejected SSH-guard removal: %v", call)
			}
		}
	}
}

// TestLabCSFPortRollback is the plan's central real-VM proof: inject a
// fault AFTER the atomic write (corruptTCPIn, verified live against every
// lab fork to make a real `csf -r` fail — see corruptTCPInVal's comment)
// and prove SafePortChange actually rolls csf.conf back to the
// byte-identical original, restarts CSF successfully, leaves the
// LOCALINPUT chain present and `systemctl is-active csf` == active, and
// never once passes a forbidden (flush/disable) argument to any command —
// a rollback proven against a real csf -r that half-applied, not a stub.
func TestLabCSFPortRollback(t *testing.T) {
	requireRoot(t)
	if requireEnv(t, "LAB_EXPECT_CSF") != "1" {
		return
	}
	snapshotConf(t)
	ctx := context.Background()
	pre := confSHA(t)
	_, calls := countCommands(t)

	restore := firewall.SetCSFFaultHook(func(stage, confPath string) error {
		if stage != "after_write" {
			return nil
		}
		return corruptTCPIn(confPath)
	})
	t.Cleanup(restore)

	res := firewall.SafePortChange(ctx, firewall.PortChangeRequest{Port: 48213, Direction: "in", Action: "add"}, firewall.PortChangeOptions{})
	if res.Result != "failed" || !res.RolledBack {
		t.Fatalf("add 48213 in with a fault at after_write = %+v, want failed/RolledBack=true", res)
	}
	if got := confSHA(t); got != pre {
		t.Fatalf("csf.conf sha after a rolled-back change = %s, want original %s", got, pre)
	}
	if !chainPresent(t) {
		t.Fatalf("LOCALINPUT chain missing after rollback")
	}
	if out, err := sh(t, "systemctl", "is-active", "csf"); out != "active" {
		t.Fatalf("systemctl is-active csf = %q (err=%v), want active after rollback", out, err)
	}
	assertNoForbidden(t, calls())
}

// TestLabCSFPortRollbackFailed corrupts BOTH the main write and the
// rollback's own write, proving the CRITICAL path: rollback_failed,
// RolledBack=false, never a forbidden argument (csf -f is structurally
// unreachable even here), and csf.conf left in a known-corrupted state on
// disk exactly as csf_ports.go's own comment documents — snapshotConf's
// t.Cleanup (registered before this test's fault-hook-restore Cleanup, so
// it runs AFTER the hook is torn down, per Go's LIFO Cleanup order) is what
// actually restores the real file and leaves the VM healthy afterward.
func TestLabCSFPortRollbackFailed(t *testing.T) {
	requireRoot(t)
	if requireEnv(t, "LAB_EXPECT_CSF") != "1" {
		return
	}
	snapshotConf(t)
	ctx := context.Background()
	_, calls := countCommands(t)

	restore := firewall.SetCSFFaultHook(func(stage, confPath string) error {
		return corruptTCPIn(confPath)
	})
	t.Cleanup(restore)

	res := firewall.SafePortChange(ctx, firewall.PortChangeRequest{Port: 48215, Direction: "in", Action: "add"}, firewall.PortChangeOptions{})
	if res.Result != "rollback_failed" || res.RolledBack {
		t.Fatalf("add 48215 in with a fault at both after_write and after_rollback_write = %+v, want rollback_failed/RolledBack=false", res)
	}
	assertNoForbidden(t, calls())
}

// TestLabCSFPortIPv6Mirror proves IPv6 mirroring against a real csf.conf:
// with IPV6="1" (already the lab default on every CSF VM) an add mirrors
// into TCP6_IN and a remove clears it from both keys. Gated on
// LAB_CSF_IPV6_TEST (2 of 6 CSF VMs, one per distro family) — every other
// CSF VM returns immediately, a PASS not a SKIP.
func TestLabCSFPortIPv6Mirror(t *testing.T) {
	requireRoot(t)
	if requireEnv(t, "LAB_EXPECT_CSF") != "1" {
		return
	}
	if requireEnv(t, "LAB_CSF_IPV6_TEST") != "1" {
		return
	}
	snapshotConf(t)
	ctx := context.Background()

	data, err := os.ReadFile(csfConfPath)
	if err != nil {
		t.Fatalf("read %s: %v", csfConfPath, err)
	}
	info, err := os.Stat(csfConfPath)
	if err != nil {
		t.Fatalf("stat %s: %v", csfConfPath, err)
	}
	withIPv6 := ipv6FlagRe.ReplaceAll(data, []byte(`IPV6 = "1"`))
	if err := os.WriteFile(csfConfPath, withIPv6, info.Mode()); err != nil {
		t.Fatalf("write %s: %v", csfConfPath, err)
	}
	if out, err := sh(t, "csf", "-r"); err != nil {
		t.Fatalf("csf -r after ensuring IPV6=1: %v (%s)", err, out)
	}
	if !chainPresent(t) {
		t.Fatalf("LOCALINPUT chain missing after ensuring IPV6=1")
	}

	res := firewall.SafePortChange(ctx, firewall.PortChangeRequest{Port: 48214, Direction: "in", Action: "add"}, firewall.PortChangeOptions{})
	if res.Result != "applied" {
		t.Fatalf("add 48214 in with IPV6=1 = %+v, want applied", res)
	}
	if !res.IPv6Mirrored {
		t.Fatalf("add 48214 in with IPV6=1: IPv6Mirrored = false, want true")
	}
	cur, err := os.ReadFile(csfConfPath)
	if err != nil {
		t.Fatalf("read %s: %v", csfConfPath, err)
	}
	if tcp6 := tcp6InValue(t, cur); !portInList(tcp6, "48214") {
		t.Fatalf("TCP6_IN = %q after add, want it to contain 48214", tcp6)
	}

	res2 := firewall.SafePortChange(ctx, firewall.PortChangeRequest{Port: 48214, Direction: "in", Action: "remove"}, firewall.PortChangeOptions{})
	if res2.Result != "applied" {
		t.Fatalf("remove 48214 in = %+v, want applied", res2)
	}
	cur2, err := os.ReadFile(csfConfPath)
	if err != nil {
		t.Fatalf("read %s: %v", csfConfPath, err)
	}
	if tcpIn, tcp6 := tcpInValue(t, cur2), tcp6InValue(t, cur2); portInList(tcpIn, "48214") || portInList(tcp6, "48214") {
		t.Fatalf("48214 still present after remove: TCP_IN=%q TCP6_IN=%q", tcpIn, tcp6)
	}
	if !chainPresent(t) {
		t.Fatalf("LOCALINPUT chain missing after the IPv6-mirror round-trip")
	}
}
