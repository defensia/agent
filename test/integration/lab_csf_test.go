//go:build integration

package integration

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/defensia/agent/internal/firewall"
)

// TestLabCSFDetection asserts firewall.HasCSF() matches LAB_EXPECT_CSF.
func TestLabCSFDetection(t *testing.T) {
	requireRoot(t)
	want := requireEnv(t, "LAB_EXPECT_CSF") == "1"
	if got := firewall.HasCSF(); got != want {
		t.Fatalf("firewall.HasCSF() = %v, want %v (LAB_EXPECT_CSF=%s)", got, want, env("LAB_EXPECT_CSF"))
	}
}

// TestLabCSFVersion asserts the detected CSF version matches the fork's
// pinned version (lab/matrix.sh's vm_csf_version). On VMs where CSF is
// not expected at all this test is not applicable and simply returns —
// it must count as a pass, not a skipped test.
func TestLabCSFVersion(t *testing.T) {
	requireRoot(t)
	if requireEnv(t, "LAB_EXPECT_CSF") != "1" {
		return
	}
	want := requireEnv(t, "LAB_EXPECT_CSF_VERSION")

	info := firewall.CSFInfo()
	if !info.Installed {
		t.Fatalf("firewall.CSFInfo().Installed = false, want true (LAB_EXPECT_CSF=1)")
	}
	if info.Version != want {
		t.Fatalf("firewall.CSFInfo().Version = %q, want %q", info.Version, want)
	}

	raw, _ := sh(t, "csf", "-v")
	t.Logf("csf -v: %s", raw)
}

// TestLabCSFListsReadable asserts /etc/csf/csf.allow and csf.deny exist
// and firewall.CSFAllowList()/CSFDenyList() parse them without panicking,
// on CSF VMs only. When a lab panel is present (LAB_PANEL_URL set), also
// asserts lab/provision/csf.sh's own panel-allow entry landed in the
// allow list. In CI (LAB_PANEL_URL empty, no panel to add an allow entry)
// the os.Stat + non-panicking parse is the whole assertion and must PASS.
func TestLabCSFListsReadable(t *testing.T) {
	requireRoot(t)
	if requireEnv(t, "LAB_EXPECT_CSF") != "1" {
		return
	}

	if _, err := os.Stat("/etc/csf/csf.allow"); err != nil {
		t.Fatalf("stat /etc/csf/csf.allow: %v", err)
	}
	if _, err := os.Stat("/etc/csf/csf.deny"); err != nil {
		t.Fatalf("stat /etc/csf/csf.deny: %v", err)
	}

	allow := firewall.CSFAllowList()
	_ = firewall.CSFDenyList()

	if env("LAB_PANEL_URL") == "" {
		return // CI: no panel, nothing else to assert
	}

	found := false
	for _, e := range allow {
		if strings.Contains(e.Comment, "lab-panel") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("firewall.CSFAllowList() has no entry with a lab-panel comment: %#v", allow)
	}
	if info := firewall.CSFInfo(); info.AllowCount < 1 {
		t.Fatalf("firewall.CSFInfo().AllowCount = %d, want >= 1", info.AllowCount)
	}
}

var testingLineRe = regexp.MustCompile(`(?m)^TESTING\s*=\s*"(\d)"`)

// TestLabCSFTestingFlag asserts /etc/csf/csf.conf's TESTING value matches
// LAB_EXPECT_TESTING, on CSF VMs only.
func TestLabCSFTestingFlag(t *testing.T) {
	requireRoot(t)
	if requireEnv(t, "LAB_EXPECT_CSF") != "1" {
		return
	}
	want := requireEnv(t, "LAB_EXPECT_TESTING")

	data, err := os.ReadFile("/etc/csf/csf.conf")
	if err != nil {
		t.Fatalf("read /etc/csf/csf.conf: %v", err)
	}
	m := testingLineRe.FindStringSubmatch(string(data))
	if m == nil {
		t.Fatalf("no TESTING line found in /etc/csf/csf.conf")
	}
	if m[1] != want {
		t.Fatalf("TESTING = %q, want %q", m[1], want)
	}
}

// TestLabLFDState asserts lfd's systemd state matches LAB_EXPECT_LFD, on
// CSF VMs only.
func TestLabLFDState(t *testing.T) {
	requireRoot(t)
	if requireEnv(t, "LAB_EXPECT_CSF") != "1" {
		return
	}
	want := requireEnv(t, "LAB_EXPECT_LFD")

	out, _ := sh(t, "systemctl", "is-active", "lfd")
	if out != want {
		t.Fatalf("systemctl is-active lfd = %q, want %q", out, want)
	}
}

// TestLabFirewallMode asserts firewall.FirewallStatus().Mode matches
// LAB_EXPECT_FW_MODE (ipset or iptables).
func TestLabFirewallMode(t *testing.T) {
	requireRoot(t)
	want := requireEnv(t, "LAB_EXPECT_FW_MODE")
	if got := firewall.FirewallStatus().Mode; got != want {
		t.Fatalf("firewall.FirewallStatus().Mode = %q, want %q", got, want)
	}
}

// TestLabHarnessForcedFailure is the harness's own self-test: setting
// LAB_FORCE_FAIL=1 makes this test (and only this test) fail, proving
// `make lab-test` actually propagates a non-zero exit instead of always
// reporting green. Passes otherwise.
func TestLabHarnessForcedFailure(t *testing.T) {
	if env("LAB_FORCE_FAIL") == "1" {
		t.Fatal("LAB_FORCE_FAIL=1: harness self-test failure")
	}
}
