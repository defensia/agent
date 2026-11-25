//go:build integration

package integration

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defensia/agent/internal/firewall"
)

// csfChaosPreamble is shared by every TestLabBanChaos* test: requires root,
// returns early (PASS) on a VM that either has no CSF or is permanently in
// TESTING=1 (chaos scenarios need a CSF that can genuinely restart/degrade
// and recover, which a TESTING=1 VM by design never does).
func csfChaosPreamble(t *testing.T) (applicable bool) {
	t.Helper()
	requireRoot(t)
	if !csfWritable() {
		t.Log("not a writable CSF VM (no CSF, or permanently TESTING=1)")
		return false
	}
	stopAgent(t)
	cleanupTagged(t)
	return true
}

// TestLabBanChaosCSFRestartMidBurst: a real `csf -r` mid-burst must never
// cause a write storm, a duplicate tempban row, or leave the breaker
// thinking CSF misbehaved.
func TestLabBanChaosCSFRestartMidBurst(t *testing.T) {
	if !csfChaosPreamble(t) {
		return
	}
	statePath := filepath.Join(t.TempDir(), "ban_executor.json")
	withCSFConf(t, "DENY_TEMP_IP_LIMIT", "1500")
	// Single-octet banIPs (the configured LAB_BAN_PREFIX) only has 254
	// unique suffixes — not enough for 300 unique bans. See
	// TestLabBanSyncBurst1000's matching comment (phase 18-10,
	// alma9-csf-orig): without this, tagged plateaus at exactly 254 and
	// the "convergence after csf -r" poll below can never reach wantMin.
	t.Setenv("LAB_BAN_PREFIX", "11.22.")

	m, ev := newManager(t, statePath)
	ips := banIPs(t, 300)
	var bans []firewall.DesiredBan
	for _, ip := range ips {
		bans = append(bans, firewall.DesiredBan{IP: ip, Reason: "r", TTL: time.Hour})
	}
	m.ApplySync(firewall.SyncInput{Executor: "csf", Bans: bans})

	poll(t, 120*time.Second, time.Second, func() bool {
		return len(taggedSet(readTempban(t))) >= 50
	}, "tagged >= 50 before csf -r")

	start := time.Now()
	out, err := sh(t, "csf", "-r")
	t.Logf("csf -r took %s (err=%v): %s", time.Since(start), err, out)
	if err != nil {
		t.Fatalf("csf -r: %v (%s)", err, out)
	}

	wantMin := 300
	if firewall.MaxDefensiaTemp() < wantMin {
		wantMin = firewall.MaxDefensiaTemp()
	}
	poll(t, 300*time.Second, 2*time.Second, func() bool {
		return len(taggedSet(readTempban(t))) >= wantMin
	}, "convergence after csf -r")

	lines := readTempban(t)
	seen := map[string]int{}
	for _, l := range lines {
		seen[l.IP]++
	}
	for ip, n := range seen {
		if n > 1 {
			t.Errorf("%s appears %d times in tempban (duplicate row)", ip, n)
		}
	}
	tagged := taggedSet(lines)
	for _, ip := range ips {
		if tagged[ip] && !denyinHas(t, ip) {
			t.Errorf("%s tagged but missing from DENYIN", ip)
		}
	}

	if st := m.Status(); st == nil || st.State != "ok" {
		t.Errorf("final Status = %+v, want State ok", st)
	}
	if ev.hasType("csf_executor_degraded") {
		t.Error("breaker reported degraded during a normal csf -r (iptables_error during a restart must not count)")
	}
}

// TestLabBanChaosLFDRewriting: lfd repeatedly rewriting csf.tempban (its
// own foreign entries expiring on staggered TTLs) while the executor
// reconciles must never trigger a re-add storm from a torn read.
func TestLabBanChaosLFDRewriting(t *testing.T) {
	if !csfChaosPreamble(t) {
		return
	}
	statePath := filepath.Join(t.TempDir(), "ban_executor.json")

	foreignIPs := banIPs(t, 50)
	for i, ip := range foreignIPs {
		ttl := 60 + (i % 30) // staggered 60..89s so lfd's own expiry rewrites csf.tempban repeatedly
		if out, err := sh(t, "csf", "-td", ip, strconv.Itoa(ttl), "lab-lfd-churn"); err != nil {
			t.Fatalf("csf -td %s (seed lfd churn): %v (%s)", ip, err, out)
		}
	}

	_, readArgv := argvLog(t)
	m, _ := newManager(t, statePath)
	ips := banIPs(t, 60)
	var bans []firewall.DesiredBan
	for _, ip := range ips {
		bans = append(bans, firewall.DesiredBan{IP: ip, Reason: "r", TTL: time.Hour})
	}
	m.ApplySync(firewall.SyncInput{Executor: "csf", Bans: bans})

	deadline := time.Now().Add(150 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(5 * time.Second)
	}

	tdCount := 0
	for _, a := range readArgv() {
		if strings.HasPrefix(a, "-td") {
			tdCount++
		}
	}
	if tdCount > 65 {
		t.Errorf("-td count = %d, want <= 65 (no re-add storm from a torn read)", tdCount)
	}

	if got := len(taggedSet(readTempban(t))); got != 60 {
		t.Errorf("final tagged = %d, want 60", got)
	}

	foreignSet := make(map[string]bool, len(foreignIPs))
	for _, ip := range foreignIPs {
		foreignSet[ip] = true
	}
	for _, a := range readArgv() {
		if !strings.HasPrefix(a, "-tr") {
			continue
		}
		fields := strings.Fields(a)
		if len(fields) >= 2 && foreignSet[fields[1]] {
			t.Errorf("foreign %s removed via -tr in argv log (should only ever expire, not be removed)", fields[1])
		}
	}
}

// TestLabBanChaosLFDStopped: lfd down must be reported as
// unavailable/lfd_not_running with zero writes, and recover once lfd is
// running again.
func TestLabBanChaosLFDStopped(t *testing.T) {
	if !csfChaosPreamble(t) {
		return
	}
	statePath := filepath.Join(t.TempDir(), "ban_executor.json")

	m, _ := newManager(t, statePath)
	ips := banIPs(t, 5)
	var bans []firewall.DesiredBan
	for _, ip := range ips {
		bans = append(bans, firewall.DesiredBan{IP: ip, Reason: "r", TTL: time.Hour})
	}
	m.ApplySync(firewall.SyncInput{Executor: "csf", Bans: bans})
	poll(t, 60*time.Second, time.Second, func() bool {
		tagged := taggedSet(readTempban(t))
		for _, ip := range ips {
			if !tagged[ip] {
				return false
			}
		}
		return true
	}, "5 converged")

	if out, err := sh(t, "systemctl", "stop", "lfd"); err != nil {
		t.Fatalf("systemctl stop lfd: %v (%s)", err, out)
	}
	t.Cleanup(func() { sh(t, "systemctl", "start", "lfd") })

	poll(t, 90*time.Second, time.Second, func() bool {
		st := m.Status()
		return st != nil && st.State == "unavailable" && st.Reason == "lfd_not_running"
	}, "State unavailable/lfd_not_running")

	more := banIPs(t, 5)
	for _, ip := range more {
		bans = append(bans, firewall.DesiredBan{IP: ip, Reason: "r", TTL: time.Hour})
	}
	_, readArgv := argvLog(t)
	m.ApplySync(firewall.SyncInput{Executor: "csf", Bans: bans})
	time.Sleep(60 * time.Second)
	for _, a := range readArgv() {
		if strings.HasPrefix(a, "-td") {
			t.Errorf("unexpected -td while lfd is stopped: %q", a)
		}
	}

	if out, err := sh(t, "systemctl", "start", "lfd"); err != nil {
		t.Fatalf("systemctl start lfd: %v (%s)", err, out)
	}

	poll(t, 120*time.Second, time.Second, func() bool {
		st := m.Status()
		return st != nil && st.State == "ok" && len(taggedSet(readTempban(t))) == 10
	}, "State ok and 10 tagged after lfd restart")
}

// TestLabBanChaosTestingMode: flipping TESTING=1 mid-run must make the
// executor unavailable/testing_mode, and flipping it back must recover.
func TestLabBanChaosTestingMode(t *testing.T) {
	if !csfChaosPreamble(t) {
		return
	}
	statePath := filepath.Join(t.TempDir(), "ban_executor.json")

	m, _ := newManager(t, statePath)
	withCSFConf(t, "TESTING", "1")

	poll(t, 120*time.Second, time.Second, func() bool {
		st := m.Status()
		return st != nil && st.State == "unavailable" && st.Reason == "testing_mode"
	}, "unavailable/testing_mode")

	withCSFConf(t, "TESTING", "0")
	ips := banIPs(t, 3)
	var bans []firewall.DesiredBan
	for _, ip := range ips {
		bans = append(bans, firewall.DesiredBan{IP: ip, Reason: "r", TTL: time.Hour})
	}
	m.ApplySync(firewall.SyncInput{Executor: "csf", Bans: bans})
	poll(t, 60*time.Second, time.Second, func() bool {
		st := m.Status()
		return st != nil && st.State == "ok"
	}, "ok after TESTING restored to 0")
}

// TestLabBanChaosSwitchBothWaysCrash: the same invariant as
// TestLabBanSyncSwitchRoundTrip's crash subtest, but TWO crashes in a row
// in EACH direction before it is ever allowed to converge.
func TestLabBanChaosSwitchBothWaysCrash(t *testing.T) {
	if !csfChaosPreamble(t) {
		return
	}
	statePath := filepath.Join(t.TempDir(), "ban_executor.json")
	firewall.Init()

	ips := banIPs(t, 30)
	var bans []firewall.DesiredBan
	for _, ip := range ips {
		bans = append(bans, firewall.DesiredBan{IP: ip, Reason: "r", TTL: time.Hour})
	}

	spawn := func() (*firewall.BanManager, context.CancelFunc) {
		ctx, cancel := context.WithCancel(context.Background())
		ev := &managerEvents{}
		mgr := firewall.NewBanManager(firewall.ManagerOptions{StatePath: statePath, Emit: ev.emit})
		mgr.Start(ctx)
		return mgr, cancel
	}

	m, cancel := spawn()
	m.ApplySync(firewall.SyncInput{Executor: "defensia", Bans: bans})
	poll(t, 30*time.Second, time.Second, func() bool {
		members := backendMembers(t)
		for _, ip := range ips {
			if !members[ip] {
				return false
			}
		}
		return true
	}, "baseline 30 in backendMembers")

	// Direction 1: defensia -> csf, crashed twice before it ever converges.
	m.ApplySync(firewall.SyncInput{Executor: "csf", Bans: bans})
	poll(t, 60*time.Second, 200*time.Millisecond, func() bool {
		return len(taggedSet(readTempban(t))) >= 5
	}, "tagged >= 5 (crash 1, direction 1)")
	cancel()

	// The desired ban list lives only in the worker's memory, never in the
	// persisted state file — a fresh manager resupplies it immediately
	// after every spawn(), just like a real restarted agent's own next
	// sync would (see TestLabBanSyncSwitchRoundTrip/crash_mid_switch's
	// matching comment).
	m, cancel = spawn()
	m.ApplySync(firewall.SyncInput{Executor: "csf", Bans: bans})
	poll(t, 30*time.Second, 200*time.Millisecond, func() bool {
		return len(taggedSet(readTempban(t))) >= 10
	}, "tagged >= 10 (crash 2, direction 1)")
	cancel()

	m, cancel = spawn()
	m.ApplySync(firewall.SyncInput{Executor: "csf", Bans: bans})
	poll(t, 90*time.Second, time.Second, func() bool {
		tagged := taggedSet(readTempban(t))
		members := backendMembers(t)
		for _, ip := range ips {
			if !tagged[ip] || members[ip] {
				return false
			}
		}
		return true
	}, "converged to csf after two crashes")

	// Direction 2: csf -> defensia, crashed twice before it ever converges.
	m.ApplySync(firewall.SyncInput{Executor: "defensia", Bans: bans})
	poll(t, 60*time.Second, 200*time.Millisecond, func() bool {
		members := backendMembers(t)
		n := 0
		for _, ip := range ips {
			if members[ip] {
				n++
			}
		}
		return n >= 5
	}, "backendMembers >= 5 (crash 1, direction 2)")
	cancel()

	m, cancel = spawn()
	m.ApplySync(firewall.SyncInput{Executor: "defensia", Bans: bans})
	poll(t, 30*time.Second, 200*time.Millisecond, func() bool {
		members := backendMembers(t)
		n := 0
		for _, ip := range ips {
			if members[ip] {
				n++
			}
		}
		return n >= 10
	}, "backendMembers >= 10 (crash 2, direction 2)")
	cancel()

	m, cancel = spawn()
	t.Cleanup(cancel)
	m.ApplySync(firewall.SyncInput{Executor: "defensia", Bans: bans})

	poll(t, 90*time.Second, time.Second, func() bool {
		members := backendMembers(t)
		tagged := taggedSet(readTempban(t))
		for _, ip := range ips {
			if !members[ip] || tagged[ip] {
				return false
			}
		}
		return true
	}, "final convergence to defensia after four total crashes")
}
