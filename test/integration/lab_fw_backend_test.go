//go:build integration

package integration

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/defensia/agent/internal/firewall"
)

// backendCapacity mirrors backend_*.go's Capacity() per backend name.
func backendCapacity(mode string) int {
	switch mode {
	case "ipset", "nftables":
		return 65536
	case "iptables":
		return 500
	default:
		return 0
	}
}

// TestLabFwBackendStatus runs on EVERY agent VM: the live, currently-running
// agent's selected backend must match the matrix's expectation.
func TestLabFwBackendStatus(t *testing.T) {
	requireRoot(t)
	want := fwMode(t)

	st := firewall.FirewallStatus()
	if st.Mode != want {
		t.Fatalf("FirewallStatus().Mode = %q, want %q (LAB_EXPECT_FW_MODE)", st.Mode, want)
	}
	if wantCap := backendCapacity(want); st.Capacity != wantCap {
		t.Fatalf("FirewallStatus().Capacity = %d, want %d for mode %q", st.Capacity, wantCap, want)
	}
	if st.Reason == "" && want == "none" {
		t.Fatalf("FirewallStatus().Reason is empty in none mode, want a reason")
	}
}

// TestLabFwBanUnbanKernel proves a ban/unban round-trip actually lands in
// (and leaves) the kernel on every VM, for both IPv4 and IPv6.
func TestLabFwBanUnbanKernel(t *testing.T) {
	requireRoot(t)
	mode := fwMode(t)
	pauseAgent(t)

	v4, v6 := "198.51.100.77", "2001:db8:dfa::77"

	if err := firewall.BanIP(v4); err != nil {
		t.Fatalf("BanIP(%s): %v", v4, err)
	}
	if err := firewall.BanIP(v6); err != nil {
		t.Fatalf("BanIP(%s): %v", v6, err)
	}
	if !kernelHasBan(t, mode, v4) {
		t.Fatalf("kernel does not show %s banned after BanIP (mode=%s)", v4, mode)
	}
	if !kernelHasBan(t, mode, v6) {
		t.Fatalf("kernel does not show %s banned after BanIP (mode=%s)", v6, mode)
	}

	if err := firewall.UnbanIP(v4); err != nil {
		t.Fatalf("UnbanIP(%s): %v", v4, err)
	}
	if err := firewall.UnbanIP(v6); err != nil {
		t.Fatalf("UnbanIP(%s): %v", v6, err)
	}
	if kernelHasBan(t, mode, v4) {
		t.Fatalf("kernel still shows %s banned after UnbanIP (mode=%s)", v4, mode)
	}
	if kernelHasBan(t, mode, v6) {
		t.Fatalf("kernel still shows %s banned after UnbanIP (mode=%s)", v6, mode)
	}

	if mode == "ipset" || mode == "nftables" {
		if err := firewall.UnbanIP(v4); err != nil {
			t.Fatalf("second UnbanIP(%s) on %s = %v, want nil (unban of an absent element is not an error)", v4, mode, err)
		}
	}
}

// TestLabFwFallbackIptablesWhenNftHidden proves that hiding nft from PATH
// on an nftables VM falls through to iptables, and restoring it recovers.
// Applies only to nftables VMs with a real iptables also present.
func TestLabFwFallbackIptablesWhenNftHidden(t *testing.T) {
	requireRoot(t)
	if fwMode(t) != "nftables" {
		t.Logf("n/a: fallback test only applies to nftables VMs")
		return
	}
	iptablesPath, err := exec.LookPath("iptables")
	if err != nil {
		t.Logf("n/a: no iptables binary on this VM")
		return
	}
	ip6tablesPath, err := exec.LookPath("ip6tables")
	if err != nil {
		t.Logf("n/a: no ip6tables binary on this VM")
		return
	}
	pauseAgent(t)

	tmp := t.TempDir()
	if err := os.Symlink(iptablesPath, filepath.Join(tmp, "iptables")); err != nil {
		t.Fatalf("symlink iptables: %v", err)
	}
	if err := os.Symlink(ip6tablesPath, filepath.Join(tmp, "ip6tables")); err != nil {
		t.Fatalf("symlink ip6tables: %v", err)
	}

	origPath := os.Getenv("PATH")
	os.Setenv("PATH", tmp)
	defer os.Setenv("PATH", origPath)

	if got := firewall.Reselect(); got != "iptables" {
		t.Fatalf("Reselect() with nft hidden = %q, want iptables", got)
	}

	ip := "198.51.100.78"
	if err := firewall.BanIP(ip); err != nil {
		t.Fatalf("BanIP(%s) on iptables fallback: %v", ip, err)
	}
	if _, err := sh(t, iptablesPath, "-C", "INPUT", "-s", ip, "-j", "DROP"); err != nil {
		t.Fatalf("%s -C INPUT -s %s -j DROP: %v (ban did not land)", iptablesPath, ip, err)
	}
	if err := firewall.UnbanIP(ip); err != nil {
		t.Fatalf("UnbanIP(%s): %v", ip, err)
	}

	os.Setenv("PATH", origPath)
	if got := firewall.Reselect(); got != "nftables" {
		t.Fatalf("Reselect() after restoring PATH = %q, want nftables", got)
	}
}

// TestLabFwNoneWhenNothingUsable proves that with no backend binaries
// available at all, the agent reports none loudly instead of pretending.
// Applies only to nftables VMs (the VMs where this phase changed detection).
func TestLabFwNoneWhenNothingUsable(t *testing.T) {
	requireRoot(t)
	want := fwMode(t)
	if want != "nftables" {
		t.Logf("n/a: none-mode test only applies to nftables VMs")
		return
	}
	pauseAgent(t)

	tmp := t.TempDir() // empty: no ipset, nft, or iptables reachable
	origPath := os.Getenv("PATH")
	os.Setenv("PATH", tmp)
	defer os.Setenv("PATH", origPath)

	if got := firewall.Reselect(); got != "none" {
		t.Fatalf("Reselect() with nothing on PATH = %q, want none", got)
	}
	if err := firewall.BanIP("198.51.100.79"); !errors.Is(err, firewall.ErrNoBackend) {
		t.Fatalf("BanIP in none mode: err = %v, want ErrNoBackend", err)
	}
	st := firewall.FirewallStatus()
	if st.Mode != "none" || st.Capacity != 0 {
		t.Fatalf("FirewallStatus() in none mode = %+v, want Mode=none Capacity=0", st)
	}

	os.Setenv("PATH", origPath)
	if got := firewall.Reselect(); got != want {
		t.Fatalf("Reselect() after restoring PATH = %q, want %q", got, want)
	}
}
