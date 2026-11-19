//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fwMode returns the backend mode this VM is expected to select
// (LAB_EXPECT_FW_MODE, set by lab/matrix.sh's vm_fw_mode via lab/test.sh).
func fwMode(t *testing.T) string {
	return requireEnv(t, "LAB_EXPECT_FW_MODE")
}

// pauseAgent stops defensia-agent so a test can drive the firewall package
// directly without racing the running daemon, and restarts it (waiting up
// to 30s for systemd to report it active again) on cleanup.
func pauseAgent(t *testing.T) {
	t.Helper()
	if _, err := sh(t, "systemctl", "stop", "defensia-agent"); err != nil {
		t.Fatalf("systemctl stop defensia-agent: %v", err)
	}
	t.Cleanup(func() {
		if _, err := sh(t, "systemctl", "start", "defensia-agent"); err != nil {
			t.Fatalf("systemctl start defensia-agent: %v", err)
		}
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			if out, _ := sh(t, "systemctl", "is-active", "defensia-agent"); out == "active" {
				return
			}
			time.Sleep(time.Second)
		}
		t.Fatalf("defensia-agent did not become active within 30s after pauseAgent cleanup")
	})
}

// kernelHasBan reports whether ip is currently banned at the kernel level
// for the given backend mode, probing the same structures the backend
// itself manages (not the agent's own bookkeeping).
func kernelHasBan(t *testing.T, mode, ip string) bool {
	t.Helper()
	parsed := net.ParseIP(ip)
	if parsed == nil {
		t.Fatalf("kernelHasBan: invalid IP %q", ip)
	}
	v6 := parsed.To4() == nil

	switch mode {
	case "ipset":
		set := "defensia-bans"
		if v6 {
			set = "defensia-bans6"
		}
		_, err := sh(t, "ipset", "test", set, ip)
		return err == nil
	case "nftables":
		set := "bans4"
		if v6 {
			set = "bans6"
		}
		_, err := sh(t, "nft", "get", "element", "inet", "defensia", set, "{", ip, "}")
		return err == nil
	case "iptables":
		bin := "iptables"
		if v6 {
			bin = "ip6tables"
		}
		_, err := sh(t, bin, "-C", "INPUT", "-s", ip, "-j", "DROP")
		return err == nil
	default:
		t.Fatalf("kernelHasBan: unknown mode %q", mode)
		return false
	}
}

// netns harness constants. Private/documentation ranges only (RFC 5737
// TEST-NET-2, RFC 3849 documentation IPv6) — never routable.
const (
	hostV4Addr = "198.51.100.1"
	nsV4Addr   = "198.51.100.10"
	hostV6Addr = "2001:db8:dfa::1"
	nsV6Addr   = "2001:db8:dfa::10"
	httpPort   = "18080"
)

// netnsSeq makes every setupNetns call use uniquely-named interfaces
// (dfhN/dfnN/dfnftN) instead of fixed names reused across every test in the
// binary. Fixed names forced each test's setup to race the PREVIOUS test's
// teardown (veth/netns deletion is RCU-deferred at the kernel level, not
// always complete the instant `ip link del` returns) — observed as
// intermittent "cannot assign requested address" on a listener the SAME
// address had just been happily serving moments before, with no amount of
// retrying making it reliably go away. Unique names per call make that
// whole class of race structurally impossible: there is never a name for
// the new call to collide with.
var netnsSeq atomic.Int64

// currentNetns is set by the most recent setupNetns call; nsReach (and
// anything else that needs to `ip netns exec` into the active namespace)
// reads it. Safe without synchronization: these tests never run with
// t.Parallel().
var currentNetns string

// sweepNetnsLeftovers deletes every dfnft*/dfh* namespace/interface left
// over by any previous setupNetns call in this process, regardless of its
// sequence number — not just a specific name. `ip netns list`/`ip -o link
// show` output is parsed with simple prefix matching; errors on individual
// deletes are ignored (a leftover that is already gone is not an error).
func sweepNetnsLeftovers(t *testing.T) {
	t.Helper()

	if out, err := sh(t, "ip", "netns", "list"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			name := strings.Fields(strings.TrimSpace(line))
			if len(name) == 0 {
				continue
			}
			if strings.HasPrefix(name[0], "dfnft") {
				_, _ = sh(t, "ip", "netns", "del", name[0])
			}
		}
	}

	if out, err := sh(t, "ip", "-o", "link", "show"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			// "N: dfh3@if7: <FLAGS> ..." — ifname is fields[1] up to ':' or '@'.
			ifName := strings.TrimSuffix(fields[1], ":")
			if at := strings.Index(ifName, "@"); at >= 0 {
				ifName = ifName[:at]
			}
			if strings.HasPrefix(ifName, "dfh") {
				_, _ = sh(t, "ip", "link", "del", ifName)
			}
		}
	}
}

// setupNetns builds a network namespace connected to the host via a veth
// pair, starts an HTTP server on the host side (v4 and v6) that the
// namespace can reach unless something in the host's firewall drops it, and
// registers full cleanup (listeners, firewall exceptions, netns, veth).
// Returns the four addresses callers ban/unban against and probe with.
func setupNetns(t *testing.T) (hostV4, nsV4, hostV6, nsV6 string) {
	t.Helper()

	n := netnsSeq.Add(1)
	netnsName := fmt.Sprintf("dfnft%d", n)
	hostVeth := fmt.Sprintf("dfh%d", n)
	nsVeth := fmt.Sprintf("dfn%d", n)
	currentNetns = netnsName

	// This call's interface name is unique, but it reuses the SAME
	// hostV4Addr/hostV6Addr/nsV4Addr/nsV6Addr every time. If an EARLIER
	// call's interface is still being torn down (RCU-deferred at the kernel
	// level), it can still hold those exact addresses for a moment — sweep
	// every dfh*/dfnft*/dfn* leftover from any previous call, not just
	// "the one with this exact name", before claiming the addresses again.
	sweepNetnsLeftovers(t)

	must := func(step string, args ...string) {
		if _, err := sh(t, args[0], args[1:]...); err != nil {
			t.Fatalf("setupNetns: %s: %v", step, err)
		}
	}

	must("ip netns add", "ip", "netns", "add", netnsName)
	// Register netns/veth cleanup IMMEDIATELY, before any further step that
	// could Fatal (including the listener setup below) — a failure partway
	// through must still tear down what was already created.
	t.Cleanup(func() {
		_, _ = sh(t, "ip", "netns", "del", netnsName)
		_, _ = sh(t, "ip", "link", "del", hostVeth)
	})

	must("ip link add veth pair", "ip", "link", "add", hostVeth, "type", "veth", "peer", "name", nsVeth)
	// NetworkManager auto-manages any interface it doesn't have an explicit
	// "unmanaged" rule for, and starts a DHCP negotiation on it within
	// ~1s of creation — observed overwriting/contending with our manual
	// address assignment moments later (root cause of an intermittent
	// "cannot assign requested address" that no amount of retrying or
	// unique naming fixed, since the interference was real, not stale
	// leftover state). Tell it to leave both veth ends alone before adding
	// any address. If NetworkManager isn't running, nmcli fails harmlessly.
	_, _ = sh(t, "nmcli", "device", "set", hostVeth, "managed", "no")
	must("ip link set ns veth into netns", "ip", "link", "set", nsVeth, "netns", netnsName)
	_, _ = sh(t, "ip", "netns", "exec", netnsName, "nmcli", "device", "set", nsVeth, "managed", "no")
	must("ip addr add host v4", "ip", "addr", "add", hostV4Addr+"/24", "dev", hostVeth)
	must("ip -6 addr add host v6", "ip", "-6", "addr", "add", hostV6Addr+"/64", "dev", hostVeth, "nodad")
	must("ip link set host veth up", "ip", "link", "set", hostVeth, "up")
	must("ip netns addr add ns v4", "ip", "netns", "exec", netnsName, "ip", "addr", "add", nsV4Addr+"/24", "dev", nsVeth)
	must("ip netns addr add ns v6", "ip", "netns", "exec", netnsName, "ip", "-6", "addr", "add", nsV6Addr+"/64", "dev", nsVeth, "nodad")
	must("ip netns link set ns veth up", "ip", "netns", "exec", netnsName, "ip", "link", "set", nsVeth, "up")
	must("ip netns lo up", "ip", "netns", "exec", netnsName, "ip", "link", "set", "lo", "up")

	// A veth's host side stays NO-CARRIER/LOWERLAYERDOWN until BOTH ends are
	// up, and binding to an address on an interface still in that state can
	// fail with EADDRNOTAVAIL even though `ip addr add`/`ip link set up`
	// already returned success — wait for the kernel to actually report
	// LOWER_UP before attempting to listen.
	for i := 0; i < 100; i++ {
		if out, err := sh(t, "ip", "link", "show", hostVeth); err == nil && strings.Contains(out, "LOWER_UP") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if out, err := sh(t, "firewall-cmd", "--state"); err == nil && out == "running" {
		// A freshly created veth is auto-bound to firewalld's default zone
		// (usually "public", which drops unsolicited traffic by policy) —
		// --add-interface fails with ZONE_CONFLICT on an interface already
		// bound elsewhere. --change-interface reassigns it regardless.
		if _, err := sh(t, "firewall-cmd", "--zone=trusted", "--change-interface="+hostVeth); err == nil {
			t.Cleanup(func() { _, _ = sh(t, "firewall-cmd", "--zone=public", "--change-interface="+hostVeth) })
		}
	}

	if _, err := exec.LookPath("iptables"); err == nil {
		// CSF's default DROP would otherwise hide our control traffic; an
		// ACCEPT in table ip filter cannot override a DROP in inet defensia,
		// so this never masks what we are actually testing.
		_, _ = sh(t, "iptables", "-I", "INPUT", "1", "-i", hostVeth, "-j", "ACCEPT")
		_, _ = sh(t, "ip6tables", "-I", "INPUT", "1", "-i", hostVeth, "-j", "ACCEPT")
		t.Cleanup(func() {
			_, _ = sh(t, "iptables", "-D", "INPUT", "-i", hostVeth, "-j", "ACCEPT")
			_, _ = sh(t, "ip6tables", "-D", "INPUT", "-i", hostVeth, "-j", "ACCEPT")
		})
	}

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	ln4 := listenRetry(t, "tcp", hostV4Addr+":"+httpPort)
	t.Cleanup(func() { _ = ln4.Close() })
	go func() { _ = http.Serve(ln4, okHandler) }()

	ln6 := listenRetry(t, "tcp", "["+hostV6Addr+"]:"+httpPort)
	t.Cleanup(func() { _ = ln6.Close() })
	go func() { _ = http.Serve(ln6, okHandler) }()

	return hostV4Addr, nsV4Addr, hostV6Addr, nsV6Addr
}

// startExtraListener opens one more HTTP 200 listener on the host side of
// the netns (used by tests that need a second port, e.g. rule lifecycle).
// Returns a cleanup func; callers should register it with t.Cleanup.
func startExtraListener(t *testing.T, addr string) func() {
	t.Helper()
	ln := listenRetry(t, "tcp", addr)
	go func() {
		_ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	}()
	return func() { _ = ln.Close() }
}

// listenRetry retries net.Listen briefly (up to 2s) before failing. A
// freshly `ip addr add`ed address is occasionally not yet bindable the
// instant the command returns (observed as "cannot assign requested
// address" under back-to-back test runs in this harness) — that is a
// kernel-timing artifact, not a real setup error worth failing on.
func listenRetry(t *testing.T, network, addr string) net.Listener {
	t.Helper()
	var lastErr error
	for i := 0; i < 100; i++ {
		ln, err := net.Listen(network, addr)
		if err == nil {
			return ln
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("listen %s %s after retrying: %v", network, addr, lastErr)
	return nil
}

// nsReach reports whether url is reachable (HTTP 200) from inside the dfnft
// namespace. Any non-200 outcome (timeout, connection refused, DROP) is
// false — curl's own exit code is not checked, only the status code it
// prints, since a dropped connection still prints "000" rather than erroring
// in a way this harness needs to distinguish.
func nsReach(t *testing.T, url string) bool {
	t.Helper()
	out, _ := sh(t, "ip", "netns", "exec", currentNetns, "curl", "-s", "-o", "/dev/null", "-m", "3", "-w", "%{http_code}", url)
	return out == "200"
}

// panelPost POSTs body (marshalled as JSON) to LAB_PANEL_URL+path with a
// Sanctum bearer token, decodes the response into out on a 2xx status, and
// returns the status code either way.
func panelPost(t *testing.T, path string, body any, out any) int {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("panelPost %s: marshal body: %v", path, err)
	}

	req, err := http.NewRequest(http.MethodPost, env("LAB_PANEL_URL")+path, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("panelPost %s: build request: %v", path, err)
	}
	req.Header.Set("Authorization", "Bearer "+requireEnv(t, "LAB_PANEL_TOKEN"))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("panelPost %s: %v", path, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && out != nil {
		if err := json.Unmarshal(respBody, out); err != nil {
			t.Fatalf("panelPost %s: decode: %v (body: %s)", path, err, respBody)
		}
	}
	return resp.StatusCode
}

// panelDelete DELETEs LAB_PANEL_URL+path with a Sanctum bearer token and
// returns the response status code.
func panelDelete(t *testing.T, path string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, env("LAB_PANEL_URL")+path, nil)
	if err != nil {
		t.Fatalf("panelDelete %s: build request: %v", path, err)
	}
	req.Header.Set("Authorization", "Bearer "+requireEnv(t, "LAB_PANEL_TOKEN"))
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("panelDelete %s: %v", path, err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)
	return resp.StatusCode
}

// pickBannableIP asks the panel to ban one of several TEST-NET/documentation
// IPs for serverID until one succeeds (201), registering its own cleanup
// (DELETE the ban). If the panel's BanService rejects every candidate as an
// invalid/reserved range, this is a blocker in the panel, not something to
// retry around — it fails loudly rather than silently trying forever.
func pickBannableIP(t *testing.T, serverID string, v6 bool) (string, int64) {
	t.Helper()

	n := 20 + rand.Intn(231) // 20..250
	var candidates []string
	if v6 {
		candidates = []string{
			fmt.Sprintf("2001:db8:d17::%x", n),
			fmt.Sprintf("3fff:d17::%x", n),
		}
	} else {
		candidates = []string{
			fmt.Sprintf("198.51.100.%d", n),
			fmt.Sprintf("203.0.113.%d", n),
			fmt.Sprintf("192.0.2.%d", n),
		}
	}

	type banResp struct {
		ID int64 `json:"id"`
	}

	for _, ip := range candidates {
		body := map[string]any{
			"ip_address": ip,
			"server_id":  serverID,
			"reason":     "phase17-lab",
			"expires_at": time.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339),
		}
		var resp banResp
		status := panelPost(t, "/api/v1/bans", body, &resp)
		if status == 201 {
			id := resp.ID
			t.Cleanup(func() { panelDelete(t, fmt.Sprintf("/api/v1/bans/%d", id)) })
			return ip, id
		}
		if status != 422 {
			t.Fatalf("pickBannableIP: POST /api/v1/bans %s: unexpected status %d", ip, status)
		}
	}
	t.Fatalf("panel refuses every TEST-NET candidate (BanService reserved-range check) — blocker, do not change panel code")
	return "", 0
}
