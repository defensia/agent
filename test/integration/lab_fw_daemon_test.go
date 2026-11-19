//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// restartAgent restarts the real defensia-agent systemd service and waits
// up to 30s for it to report active again.
func restartAgent(t *testing.T) {
	t.Helper()
	if _, err := sh(t, "systemctl", "restart", "defensia-agent"); err != nil {
		t.Fatalf("systemctl restart defensia-agent: %v", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if out, _ := sh(t, "systemctl", "is-active", "defensia-agent"); out == "active" {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("defensia-agent did not become active within 30s after restart")
}

// poll calls fn every `every` until it returns true or `timeout` elapses,
// Fataling with `what` on timeout.
func poll(t *testing.T, timeout, every time.Duration, fn func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(every)
	}
	t.Fatalf("timed out after %s waiting for: %s", timeout, what)
}

// journalSince returns the defensia-agent journal for the last 5 minutes.
func journalSince(t *testing.T) string {
	t.Helper()
	out, _ := sh(t, "journalctl", "-u", "defensia-agent", "--since", "-5min", "--no-pager")
	return out
}

type serverResponse struct {
	FirewallMode string `json:"firewall_mode"`
	BanCapacity  int    `json:"ban_capacity"`
}

// TestLabDaemonHeartbeatMode runs on every agent VM: the running agent must
// report its real firewall_mode and ban_capacity to the panel.
func TestLabDaemonHeartbeatMode(t *testing.T) {
	requireEnv(t, "LAB_PANEL_URL")
	requireRoot(t)
	id := readAgentConfig(t)
	mode := fwMode(t)

	var srv serverResponse
	poll(t, 120*time.Second, 10*time.Second, func() bool {
		panelGet(t, "/api/v1/servers/"+id, &srv)
		return srv.FirewallMode == mode
	}, fmt.Sprintf("panel firewall_mode == %q", mode))

	wantCap := backendCapacity(mode)
	if srv.BanCapacity != wantCap {
		t.Fatalf("panel ban_capacity = %d, want %d for mode %q", srv.BanCapacity, wantCap, mode)
	}
}

// TestLabDaemonPanelBanEnforced runs on every agent VM: a panel-side ban
// must be enforced at the kernel level (via the next sync/startup sync),
// carry a kernel TTL on nftables, and be cleaned up when deleted.
func TestLabDaemonPanelBanEnforced(t *testing.T) {
	requireEnv(t, "LAB_PANEL_URL")
	requireRoot(t)
	id := readAgentConfig(t)
	mode := fwMode(t)

	ip4, _ := pickBannableIP(t, id, false)
	ip6, _ := pickBannableIP(t, id, true)

	restartAgent(t)
	poll(t, 120*time.Second, 5*time.Second, func() bool {
		return kernelHasBan(t, mode, ip4) && kernelHasBan(t, mode, ip6)
	}, fmt.Sprintf("kernel shows %s and %s banned (mode=%s)", ip4, ip6, mode))

	if mode == "nftables" {
		out, err := sh(t, "nft", "-j", "list", "set", "inet", "defensia", "bans4")
		if err != nil {
			t.Fatalf("nft -j list set inet defensia bans4: %v", err)
		}
		if !strings.Contains(out, ip4) {
			t.Fatalf("bans4 does not contain %s: %s", ip4, out)
		}
		var top struct {
			Nftables []struct {
				Set *struct {
					Elem []json.RawMessage `json:"elem"`
				} `json:"set"`
			} `json:"nftables"`
		}
		if err := json.Unmarshal([]byte(out), &top); err != nil {
			t.Fatalf("parse bans4 JSON: %v", err)
		}
		foundTimeout := false
		for _, entry := range top.Nftables {
			if entry.Set == nil {
				continue
			}
			for _, raw := range entry.Set.Elem {
				var obj struct {
					Elem struct {
						Val     string `json:"val"`
						Timeout int    `json:"timeout"`
					} `json:"elem"`
				}
				if err := json.Unmarshal(raw, &obj); err == nil && obj.Elem.Val == ip4 {
					if obj.Elem.Timeout < 1 || obj.Elem.Timeout > 900 {
						t.Fatalf("%s has timeout=%d, want between 1 and 900 (TTL from expires_at)", ip4, obj.Elem.Timeout)
					}
					foundTimeout = true
				}
			}
		}
		if !foundTimeout {
			t.Fatalf("%s has no timeout element in bans4 (expected a TTL from expires_at): %s", ip4, out)
		}
	}

	// Delete both bans from the panel, restart, and confirm the kernel
	// forgets them (CleanupStaleBans path on the next startup sync).
	if status := panelDelete(t, fmt.Sprintf("/api/v1/bans/%d", mustBanID(t, id, ip4))); status != 200 {
		t.Fatalf("panelDelete ip4: status %d", status)
	}
	if status := panelDelete(t, fmt.Sprintf("/api/v1/bans/%d", mustBanID(t, id, ip6))); status != 200 {
		t.Fatalf("panelDelete ip6: status %d", status)
	}

	restartAgent(t)
	poll(t, 120*time.Second, 5*time.Second, func() bool {
		return !kernelHasBan(t, mode, ip4) && !kernelHasBan(t, mode, ip6)
	}, fmt.Sprintf("kernel no longer shows %s/%s banned after panel delete", ip4, ip6))
}

// TestLabDaemonSelfHealTableDeleted (nftables only): the RUNNING daemon,
// without a restart, must notice its table is gone (heartbeat Ensure) and
// re-apply bans within ~150s.
func TestLabDaemonSelfHealTableDeleted(t *testing.T) {
	requireEnv(t, "LAB_PANEL_URL")
	requireRoot(t)
	id := readAgentConfig(t)
	mode := fwMode(t)
	if mode != "nftables" {
		t.Logf("n/a: self-heal-after-table-delete only applies to nftables VMs")
		return
	}

	ip4, _ := pickBannableIP(t, id, false)
	restartAgent(t)
	poll(t, 120*time.Second, 5*time.Second, func() bool {
		return kernelHasBan(t, mode, ip4)
	}, fmt.Sprintf("kernel shows %s banned", ip4))

	if _, err := sh(t, "nft", "delete", "table", "inet", "defensia"); err != nil {
		t.Fatalf("nft delete table inet defensia: %v", err)
	}

	poll(t, 150*time.Second, 5*time.Second, func() bool {
		if _, err := sh(t, "nft", "list", "table", "inet", "defensia"); err != nil {
			return false
		}
		return kernelHasBan(t, mode, ip4)
	}, "table recreated and ban re-applied WITHOUT restarting the agent")

	if !strings.Contains(journalSince(t), "re-applying bans and country blocks now") {
		t.Fatalf("journal does not contain the self-heal resync log line")
	}
}

// TestLabDaemonNoneReportedAndRecovers (only LAB_FW_VARIANT == "nft-b"):
// hiding nft makes the running agent report none + a firewall_unavailable
// event, and restoring it recovers to nftables without a restart.
func TestLabDaemonNoneReportedAndRecovers(t *testing.T) {
	requireEnv(t, "LAB_PANEL_URL")
	requireRoot(t)
	id := readAgentConfig(t)
	if env("LAB_FW_VARIANT") != "nft-b" {
		t.Logf("n/a: only applies to the nft-b lab variant")
		return
	}

	nftPath, err := exec.LookPath("nft")
	if err != nil {
		t.Fatalf("nft not found: %v", err)
	}
	info, err := os.Stat(nftPath)
	if err != nil {
		t.Fatalf("stat %s: %v", nftPath, err)
	}
	origMode := info.Mode()

	t.Cleanup(func() {
		_ = os.Chmod(nftPath, origMode)
		restartAgent(t)
	})

	if err := os.Chmod(nftPath, 0o000); err != nil {
		t.Fatalf("chmod 000 %s: %v", nftPath, err)
	}
	restartAgent(t)

	var srv serverResponse
	poll(t, 120*time.Second, 5*time.Second, func() bool {
		panelGet(t, "/api/v1/servers/"+id, &srv)
		return srv.FirewallMode == "none"
	}, "panel firewall_mode == none")

	poll(t, 120*time.Second, 5*time.Second, func() bool {
		return hasFirewallUnavailableEvent(t, id, "bans")
	}, "a firewall_unavailable event with scope=bans")

	if !strings.Contains(journalSince(t), "no usable firewall backend") {
		t.Fatalf("journal does not contain 'no usable firewall backend'")
	}

	if err := os.Chmod(nftPath, origMode); err != nil {
		t.Fatalf("restore %s mode: %v", nftPath, err)
	}

	poll(t, 180*time.Second, 5*time.Second, func() bool {
		panelGet(t, "/api/v1/servers/"+id, &srv)
		if srv.FirewallMode != "nftables" {
			return false
		}
		_, err := sh(t, "nft", "list", "table", "inet", "defensia")
		return err == nil
	}, "panel firewall_mode == nftables and table recreated, WITHOUT restarting the agent")
}

// TestLabDaemonCSFRestartKeepsBans (CSF VMs only): an external `csf -r`
// must not leave a panel ban unenforced for more than one heartbeat cycle.
func TestLabDaemonCSFRestartKeepsBans(t *testing.T) {
	requireEnv(t, "LAB_PANEL_URL")
	requireRoot(t)
	id := readAgentConfig(t)
	mode := fwMode(t)

	if _, err := exec.LookPath("csf"); err != nil {
		t.Logf("n/a: no CSF")
		return
	}
	if _, err := sh(t, "csf", "-v"); err != nil {
		t.Logf("n/a: no CSF")
		return
	}

	ip4, _ := pickBannableIP(t, id, false)
	restartAgent(t)

	enforced := func() bool {
		if !kernelHasBan(t, mode, ip4) {
			return false
		}
		switch mode {
		case "ipset":
			return fwOK2(t, "iptables", "-C", "INPUT", "-m", "set", "--match-set", "defensia-bans", "src", "-j", "DROP")
		case "nftables":
			out, err := sh(t, "nft", "list", "chain", "inet", "defensia", "input")
			return err == nil && strings.Contains(out, "@bans4") && strings.Contains(out, "drop")
		default:
			return true
		}
	}

	poll(t, 120*time.Second, 5*time.Second, enforced, fmt.Sprintf("%s enforced (ban + drop path) before csf -r", ip4))

	if _, err := shTimeout(t, 120*time.Second, "csf", "-r"); err != nil {
		t.Fatalf("csf -r: %v", err)
	}

	start := time.Now()
	poll(t, 90*time.Second, 5*time.Second, enforced,
		"Defensia ban not enforced 90s after csf -r (heartbeat Ensure / afterCSFRestart re-assert missing)")
	t.Logf("re-enforced %s after csf -r in %s", ip4, time.Since(start))
}

// TestLabDaemonGeoblockNotSilent: deliberately NOT implemented here. Setting
// blocked countries requires panel-side config this in-VM test cannot
// drive; the equivalent assertion (geoblock verdict must be ENFORCED or
// REPORTED, never SILENT) is covered by `lab/diagnose-firewall.sh
// --expect-enforced` in plan 17-07's phase gate.

func fwOK2(t *testing.T, name string, args ...string) bool {
	t.Helper()
	_, err := sh(t, name, args...)
	return err == nil
}

// mustBanID re-discovers the ban id the panel assigned to ip, used after
// pickBannableIP already registered a cleanup for it (looking it up again
// rather than threading it through is simplest given the current helper
// signatures). serverID is unused but kept for call-site readability.
func mustBanID(t *testing.T, serverID, ip string) int64 {
	t.Helper()
	var resp struct {
		Data []struct {
			ID        int64  `json:"id"`
			IPAddress string `json:"ip_address"`
		} `json:"data"`
	}
	panelGet(t, "/api/v1/bans?ip="+ip, &resp)
	for _, b := range resp.Data {
		if b.IPAddress == ip {
			return b.ID
		}
	}
	t.Fatalf("no ban found for %s via GET /api/v1/bans?ip=%s", ip, ip)
	return 0
}

// hasFirewallUnavailableEvent reports whether the panel has recorded at
// least one firewall_unavailable event for id with the given scope within
// the last hour.
func hasFirewallUnavailableEvent(t *testing.T, id, scope string) bool {
	t.Helper()
	var resp struct {
		Data []struct {
			Type    string            `json:"type"`
			Details map[string]string `json:"details"`
		} `json:"data"`
	}
	path := fmt.Sprintf("/api/v1/events?server_id=%s&type=firewall_unavailable&since=%s&per_page=100", id, url.QueryEscape("1 hour"))
	panelGet(t, path, &resp)
	for _, e := range resp.Data {
		if e.Type == "firewall_unavailable" && e.Details["scope"] == scope {
			return true
		}
	}
	return false
}
