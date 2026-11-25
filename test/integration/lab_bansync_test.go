//go:build integration

package integration

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defensia/agent/internal/firewall"
)

// csfFunctionalPreamble is shared by every TestLabBanSync* functional test
// except TestLabBanSyncNoCSF: requires root, returns early (PASS, not a
// skip) on a non-CSF VM, otherwise stops the real agent and registers the
// tagged-entry cleanup safety net. The second return value reports whether
// this VM is in TESTING=1 (the executor must only ever reach "unavailable"
// there, never attempt a real write).
func csfFunctionalPreamble(t *testing.T) (testingMode bool, applicable bool) {
	t.Helper()
	requireRoot(t)
	if !isCSFVM() {
		t.Log("not a CSF VM")
		return false, false
	}
	stopAgent(t)
	cleanupTagged(t)
	return env("LAB_EXPECT_TESTING") == "1", true
}

// assertUnavailableTestingMode is the TESTING=1 variant every functional
// test falls back to on alma8-csf-cwp-orphan: the executor must reach
// "unavailable"/"testing_mode" and never write a single -td/-tr.
func assertUnavailableTestingMode(t *testing.T, statePath string) {
	t.Helper()
	m, _ := newManager(t, statePath)
	ips := banIPs(t, 3)
	var bans []firewall.DesiredBan
	for _, ip := range ips {
		bans = append(bans, firewall.DesiredBan{IP: ip, Reason: "r", TTL: time.Hour})
	}
	m.ApplySync(firewall.SyncInput{Executor: "csf", Bans: bans})

	poll(t, 30*time.Second, time.Second, func() bool {
		st := m.Status()
		return st != nil && st.State == "unavailable" && st.Reason == "testing_mode"
	}, "State unavailable/testing_mode")

	if tagged := taggedSet(readTempban(t)); len(tagged) != 0 {
		t.Errorf("tagged = %v, want none (TESTING=1)", tagged)
	}
}

var denyTempLimitRe = regexp.MustCompile(`(?m)^DENY_TEMP_IP_LIMIT\s*=\s*"(-?\d+)"`)

func readDenyTempIPLimit(t *testing.T) int {
	t.Helper()
	data, err := os.ReadFile(csfConfPath)
	if err != nil {
		t.Fatalf("read csf.conf: %v", err)
	}
	m := denyTempLimitRe.FindSubmatch(data)
	if m == nil {
		t.Fatalf("DENY_TEMP_IP_LIMIT not found in csf.conf")
	}
	n, err := strconv.Atoi(string(m[1]))
	if err != nil {
		t.Fatalf("parse DENY_TEMP_IP_LIMIT %q: %v", m[1], err)
	}
	return n
}

// TestLabBanSyncTempBanCycle (SYNC-02): a ban applied through the executor
// shows up as a real, correctly-tagged CSF temp ban and in DENYIN, and
// disappears cleanly on unban — without ever restarting CSF.
func TestLabBanSyncTempBanCycle(t *testing.T) {
	testingMode, ok := csfFunctionalPreamble(t)
	if !ok {
		return
	}
	statePath := filepath.Join(t.TempDir(), "ban_executor.json")
	if testingMode {
		assertUnavailableTestingMode(t, statePath)
		return
	}

	_, readArgv := argvLog(t)
	before := csfActiveSince(t)

	m, _ := newManager(t, statePath)
	ips := banIPs(t, 3)
	now := time.Now()
	plus2h := now.Add(2 * time.Hour)
	plus30m := now.Add(30 * time.Minute)
	bans := []firewall.DesiredBan{
		{IP: ips[0], Reason: "brute_force", TTL: time.Hour, ExpiresAt: &plus2h},
		{IP: ips[1], Reason: "wp_bruteforce", TTL: time.Hour},
		{IP: ips[2], Reason: "", TTL: 30 * time.Minute, ExpiresAt: &plus30m},
	}
	m.ApplySync(firewall.SyncInput{Executor: "csf", Bans: bans})

	poll(t, 60*time.Second, time.Second, func() bool {
		tagged := taggedSet(readTempban(t))
		return tagged[ips[0]] && tagged[ips[1]] && tagged[ips[2]]
	}, "all 3 bans tagged")

	byIP := map[string]tempLine{}
	for _, l := range readTempban(t) {
		byIP[l.IP] = l
	}
	wantComment := map[string]string{ips[0]: "defensia:brute_force", ips[1]: "defensia:wp_bruteforce", ips[2]: "defensia:ban"}
	for ip, want := range wantComment {
		if got := byIP[ip].Comment; got != want {
			t.Errorf("%s comment = %q, want %q", ip, got, want)
		}
		if !denyinHas(t, ip) {
			t.Errorf("%s missing from DENYIN", ip)
		}
	}

	if out, err := sh(t, "csf", "-t"); err != nil {
		t.Errorf("csf -t: %v", err)
	} else {
		for _, ip := range ips {
			if !strings.Contains(out, ip) {
				t.Errorf("csf -t output missing %s", ip)
			}
		}
	}

	// TTL field sanity for the +2h ban: within [7000, 7200] seconds.
	for _, l := range rawTempbanLines(t) {
		fields := strings.SplitN(l, "|", 6)
		if len(fields) == 6 && fields[1] == ips[0] {
			ttl, _ := strconv.Atoi(fields[4])
			if ttl < 7000 || ttl > 7200 {
				t.Errorf("%s TTL = %d, want [7000,7200]", ips[0], ttl)
			}
		}
	}

	// Unban ips[0]; the other two must stay.
	m.ApplySync(firewall.SyncInput{Executor: "csf", Bans: bans[1:]})
	poll(t, 60*time.Second, time.Second, func() bool {
		tagged := taggedSet(readTempban(t))
		return !tagged[ips[0]] && tagged[ips[1]] && tagged[ips[2]]
	}, "ips[0] gone, others intact")
	if denyinHas(t, ips[0]) {
		t.Errorf("%s still in DENYIN after unban", ips[0])
	}

	if after := csfActiveSince(t); after != before {
		t.Errorf("csf restarted (ActiveEnterTimestampMonotonic %s -> %s)", before, after)
	}

	for _, argv := range readArgv() {
		fields := strings.Fields(argv)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "-v", "-t", "-td", "-tr":
		default:
			t.Errorf("unexpected csf flag in argv log: %q", argv)
		}
	}
}

// rawTempbanLines reads csf.tempban's raw (unsplit) lines, used only where
// the TTL (fields[4]) is needed — taggedSet/foreignSet only expose IP+Comment.
func rawTempbanLines(t *testing.T) []string {
	t.Helper()
	const path = "/var/lib/csf/csf.tempban"
	out, err := sh(t, "flock", "-s", path, "-c", "cat "+path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

// TestLabBanSyncGuard (SYNC-03): csf.allow, csf.ignore and the Defensia
// whitelist each protect an IP, on both the csf path (argv log, tempban,
// backend) and the direct BanIP/BanIPFor choke point.
func TestLabBanSyncGuard(t *testing.T) {
	testingMode, ok := csfFunctionalPreamble(t)
	if !ok {
		return
	}
	statePath := filepath.Join(t.TempDir(), "ban_executor.json")
	if testingMode {
		assertUnavailableTestingMode(t, statePath)
		return
	}

	ips := banIPs(t, 5)
	A, B, C, D, E := ips[0], ips[1], ips[2], ips[3], ips[4]

	if out, err := sh(t, "csf", "-a", A, "lab-guard"); err != nil {
		t.Fatalf("csf -a %s: %v (%s)", A, err, out)
	}
	t.Cleanup(func() { sh(t, "csf", "-ar", A) })

	const ignorePath = "/etc/csf/csf.ignore"
	origIgnore, err := os.ReadFile(ignorePath)
	if err != nil {
		t.Fatalf("read csf.ignore: %v", err)
	}
	t.Cleanup(func() {
		os.WriteFile(ignorePath, origIgnore, 0o644)
		sh(t, "csf", "-r")
	})
	if err := os.WriteFile(ignorePath, append(append([]byte{}, origIgnore...), []byte("\n"+B+"\n")...), 0o644); err != nil {
		t.Fatalf("write csf.ignore: %v", err)
	}
	if out, err := sh(t, "csf", "-r"); err != nil {
		t.Fatalf("csf -r: %v (%s)", err, out)
	}

	// guardCheck caches csf.allow/csf.ignore mtimes and only re-stats them
	// once per guardListRefreshEvery (5s, see guard.go) — a deliberate,
	// documented staleness bound to keep the hot ban path from stat()-ing on
	// every single call, not a bug. A prior test in this same binary process
	// can have primed that cache within the last 5s, so without this wait
	// the just-written csf.allow/csf.ignore entries above are invisible to
	// guardCheck for up to 5s and A/B slip through on the very first pass
	// (lab-measured, alma9-csf-orig, phase 18-10).
	time.Sleep(6 * time.Second)

	m, _ := newManager(t, statePath)
	firewall.SetWhitelist([]string{C}, []string{D + "/32"})
	t.Cleanup(func() { firewall.SetWhitelist(nil, nil) })

	_, readArgv := argvLog(t)

	bans := []firewall.DesiredBan{
		{IP: A, Reason: "r", TTL: time.Hour}, {IP: B, Reason: "r", TTL: time.Hour},
		{IP: C, Reason: "r", TTL: time.Hour}, {IP: D, Reason: "r", TTL: time.Hour},
		{IP: E, Reason: "r", TTL: time.Hour},
	}
	m.ApplySync(firewall.SyncInput{Executor: "csf", Bans: bans})
	poll(t, 60*time.Second, time.Second, func() bool {
		return taggedSet(readTempban(t))[E]
	}, "E tagged")

	// A second pass must not let a guarded IP slip through either.
	m.ApplySync(firewall.SyncInput{Executor: "csf", Bans: bans})
	time.Sleep(2 * time.Second)

	tagged := taggedSet(readTempban(t))
	members := backendMembers(t)
	argv := readArgv()
	for _, ip := range []string{A, B, C, D} {
		if tagged[ip] {
			t.Errorf("%s should never be tagged (guarded)", ip)
		}
		if members[ip] {
			t.Errorf("%s should never be in the Defensia backend (guarded)", ip)
		}
		for _, a := range argv {
			if strings.Contains(a, ip) {
				t.Errorf("guarded IP %s appeared in csf argv: %q", ip, a)
			}
		}
	}

	if status := m.Status(); status == nil || status.SkippedProtected < 4 {
		t.Errorf("Status().SkippedProtected = %+v, want >= 4", status)
	}

	if err := firewall.BanIP(C); err == nil || !errors.Is(err, firewall.ErrProtectedIP) {
		t.Errorf("BanIP(C) = %v, want ErrProtectedIP", err)
	}
	if err := firewall.BanIPFor(A, time.Hour); err == nil || !errors.Is(err, firewall.ErrProtectedIP) {
		t.Errorf("BanIPFor(A) = %v, want ErrProtectedIP", err)
	}
	members = backendMembers(t)
	if members[C] || members[A] {
		t.Error("A/C must not be in backendMembers after guarded BanIP/BanIPFor attempts")
	}
}

// TestLabBanSyncBurst1000 (SYNC-04): a 1,000-ban burst never exceeds
// DENY_TEMP_IP_LIMIT, never touches pre-existing foreign entries, never
// reaches the Defensia backend, and reports the rest as deferred.
func TestLabBanSyncBurst1000(t *testing.T) {
	testingMode, ok := csfFunctionalPreamble(t)
	if !ok {
		return
	}
	statePath := filepath.Join(t.TempDir(), "ban_executor.json")
	if testingMode {
		assertUnavailableTestingMode(t, statePath)
		return
	}

	// banIPs' single-octet mode (the configured LAB_BAN_PREFIX, "11.22.0.")
	// only has 254 possible unique suffixes — nowhere near enough for a
	// 1,000-ban burst, and banIPCounter is shared process-wide across every
	// test, so collisions compound further still. Switch to the two-octet
	// form (up to 254*254 unique addresses) for this test only — lab-
	// measured, alma9-csf-orig, phase 18-10: without this override,
	// desiredByIP (a map, keyed by IP) silently deduplicated ~750+ of the
	// "1,000" requested bans down to a few hundred unique IPs, making the
	// planner's own Deferred accounting correct for far fewer candidates
	// than the test assumed and failing every count-based assertion below.
	t.Setenv("LAB_BAN_PREFIX", "11.22.")

	limit := readDenyTempIPLimit(t)
	t.Logf("DENY_TEMP_IP_LIMIT = %d", limit)

	foreign := banIPs(t, 5)
	seedForeign(t, foreign, time.Hour, "lab-foreign")

	m, _, stopM := newManagerStoppable(t, statePath)
	burstIPs := banIPs(t, 1000)
	var bans []firewall.DesiredBan
	burstSet := make(map[string]bool, 1000)
	for _, ip := range burstIPs {
		bans = append(bans, firewall.DesiredBan{IP: ip, Reason: "r", TTL: time.Hour})
		burstSet[ip] = true
	}

	start := time.Now()
	m.ApplySync(firewall.SyncInput{Executor: "csf", Bans: bans})
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Errorf("ApplySync took %s, want < 50ms (must never block)", d)
	}

	maxTotal := 0
	lastTagged := -1
	var stableSince time.Time
	deadline := time.Now().Add(180 * time.Second)
	for time.Now().Before(deadline) {
		lines := readTempban(t)
		if len(lines) > maxTotal {
			maxTotal = len(lines)
		}
		members := backendMembers(t)
		for ip := range burstSet {
			if members[ip] {
				t.Errorf("burst IP %s reached the Defensia backend", ip)
			}
		}
		tagged := taggedSet(lines)
		// Real CSF rate-limits each -td to csfMinInterval (190ms), so the
		// very first pass reads 0/0/0 for well over a second before the
		// worker's cold-start (checkVersionOnce + first exec) even lands its
		// first entry — "stable at 0" must never count as converged, only
		// as "hasn't started yet" (lab-measured, alma9-csf-orig, phase
		// 18-10: without the len(tagged)>0 guard this loop broke out after
		// ~2s, long before a real burst could possibly have converged).
		if len(tagged) == lastTagged && len(tagged) > 0 {
			if stableSince.IsZero() {
				stableSince = time.Now()
			}
			if time.Since(stableSince) > 1500*time.Millisecond {
				break
			}
		} else {
			stableSince = time.Time{}
		}
		lastTagged = len(tagged)
		time.Sleep(500 * time.Millisecond)
	}

	if maxTotal > limit {
		t.Errorf("max total tempban entries = %d, want <= %d", maxTotal, limit)
	}
	finalForeign := foreignSet(readTempban(t))
	for _, ip := range foreign {
		if !finalForeign[ip] {
			t.Errorf("pre-existing foreign %s missing at the end", ip)
		}
	}

	reserve := 10
	if r := limit / 5; r > reserve {
		reserve = r
	}
	wantTagged := 1000
	if budget := limit - 5 - reserve; budget < wantTagged {
		wantTagged = budget
	}
	if cap := firewall.MaxDefensiaTemp(); cap < wantTagged {
		wantTagged = cap
	}
	if wantTagged < 0 {
		wantTagged = 0
	}

	gotTagged := len(taggedSet(readTempban(t)))
	if gotTagged != wantTagged {
		t.Errorf("tagged = %d, want %d", gotTagged, wantTagged)
	}

	st := m.Status()
	if st == nil {
		t.Fatal("Status() = nil")
	}
	wantDeferred := 1000 - gotTagged
	if st.Deferred != wantDeferred {
		t.Errorf("Deferred = %d, want %d", st.Deferred, wantDeferred)
	}
	t.Logf("final State=%s Deferred=%d", st.State, st.Deferred)

	// Stop this manager's worker before high_limit starts a second one
	// against the same real CSF host — see newManagerStoppable's doc
	// comment for why this is required, not just tidy.
	stopM()

	t.Run("high_limit", func(t *testing.T) {
		withCSFConf(t, "DENY_TEMP_IP_LIMIT", "1500")

		statePath2 := filepath.Join(t.TempDir(), "ban_executor.json")
		m2, _ := newManager(t, statePath2)
		ips2 := banIPs(t, 1000)
		var bans2 []firewall.DesiredBan
		for _, ip := range ips2 {
			bans2 = append(bans2, firewall.DesiredBan{IP: ip, Reason: "r", TTL: time.Hour})
		}
		m2.ApplySync(firewall.SyncInput{Executor: "csf", Bans: bans2})

		// Real CSF (not the fake binary) needs ~9 self-woken passes to reach
		// MaxDefensiaTemp (500) at csfMaxOpsPerPass (79) per pass, each pass
		// also paying real exec/conf/temp-reread overhead beyond the pure
		// csfMinInterval rate limit — lab-measured, alma9-csf-orig, phase
		// 18-10: convergence genuinely completes (505 tagged, matching
		// budget) but took ~230s wall-clock, comfortably exceeding the
		// original 180s poll window even though nothing was actually wrong.
		poll(t, 6*time.Minute, time.Second, func() bool {
			return len(taggedSet(readTempban(t))) >= firewall.MaxDefensiaTemp()
		}, "tagged reaches MaxDefensiaTemp")

		maxTotal2 := 0
		for i := 0; i < 20; i++ {
			if n := len(readTempban(t)); n > maxTotal2 {
				maxTotal2 = n
			}
			time.Sleep(500 * time.Millisecond)
		}
		if maxTotal2 > 1500 {
			t.Errorf("max total = %d, want <= 1500", maxTotal2)
		}
		if got := len(taggedSet(readTempban(t))); got != firewall.MaxDefensiaTemp() {
			t.Errorf("tagged = %d, want exactly MaxDefensiaTemp() = %d", got, firewall.MaxDefensiaTemp())
		}
	})
}

// TestLabBanSyncSwitchRoundTrip (SYNC-05): defensia -> csf -> defensia
// never leaves a desired IP unblocked, including across an in-process
// "crash" (context cancellation + a fresh manager on the same StatePath).
func TestLabBanSyncSwitchRoundTrip(t *testing.T) {
	testingMode, ok := csfFunctionalPreamble(t)
	if !ok {
		return
	}
	statePath := filepath.Join(t.TempDir(), "ban_executor.json")
	if testingMode {
		assertUnavailableTestingMode(t, statePath)
		return
	}

	m, _, stopM := newManagerStoppable(t, statePath)
	ips := banIPs(t, 50)
	var bans []firewall.DesiredBan
	for _, ip := range ips {
		bans = append(bans, firewall.DesiredBan{IP: ip, Reason: "r", TTL: time.Hour})
	}

	m.ApplySync(firewall.SyncInput{Executor: "defensia", Bans: bans})
	poll(t, 30*time.Second, time.Second, func() bool {
		members := backendMembers(t)
		for _, ip := range ips {
			if !members[ip] {
				return false
			}
		}
		return true
	}, "50 bans in backendMembers")

	violations := 0
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				members := backendMembers(t)
				tagged := taggedSet(readTempban(t))
				for _, ip := range ips {
					if !members[ip] && !tagged[ip] {
						violations++
					}
				}
			}
		}
	}()

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
	}, "tagged 50, backendMembers clear of desired")

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
	}, "backendMembers 50, tagged 0")

	close(stop)
	wg.Wait()
	if violations > 0 {
		t.Errorf("gap violations = %d, want 0", violations)
	}

	// Stop this manager's worker before crash_mid_switch starts its own
	// independent managers against the SAME 50 IPs on the same real CSF
	// host — see newManagerStoppable's doc comment.
	stopM()

	t.Run("crash_mid_switch", func(t *testing.T) {
		statePath2 := filepath.Join(t.TempDir(), "ban_executor.json")
		firewall.Init()

		ctx1, cancel1 := context.WithCancel(context.Background())
		ev1 := &managerEvents{}
		m1 := firewall.NewBanManager(firewall.ManagerOptions{StatePath: statePath2, Emit: ev1.emit})
		m1.Start(ctx1)

		m1.ApplySync(firewall.SyncInput{Executor: "defensia", Bans: bans})
		poll(t, 30*time.Second, time.Second, func() bool {
			members := backendMembers(t)
			for _, ip := range ips {
				if !members[ip] {
					return false
				}
			}
			return true
		}, "initial 50 in backendMembers (crash subtest)")

		m1.ApplySync(firewall.SyncInput{Executor: "csf", Bans: bans})
		poll(t, 60*time.Second, 200*time.Millisecond, func() bool {
			return len(taggedSet(readTempban(t))) >= 20
		}, "tagged >= 20 before first crash")
		cancel1() // "crash" #1: drop the manager mid-switch

		ctx2, cancel2 := context.WithCancel(context.Background())
		ev2 := &managerEvents{}
		m2 := firewall.NewBanManager(firewall.ManagerOptions{StatePath: statePath2, Emit: ev2.emit})
		m2.Start(ctx2)
		// The desired ban list lives only in the worker's memory, never in
		// the persisted state file (only Mode/Migrating/Degraded survive a
		// restart) — a freshly started process has zero desired bans until
		// its first real sync. In production that first sync follows
		// Start() almost immediately (the agent's own main loop), so this
		// re-supply is simulating that, not working around a real bug.
		m2.ApplySync(firewall.SyncInput{Executor: "csf", Bans: bans})

		poll(t, 90*time.Second, time.Second, func() bool {
			tagged := taggedSet(readTempban(t))
			members := backendMembers(t)
			for _, ip := range ips {
				if !tagged[ip] || members[ip] {
					return false
				}
			}
			return true
		}, "post-crash convergence to csf")

		m2.ApplySync(firewall.SyncInput{Executor: "defensia", Bans: bans})
		poll(t, 60*time.Second, 200*time.Millisecond, func() bool {
			return len(taggedSet(readTempban(t))) <= 30
		}, "tagged <= 30 before second crash")
		cancel2() // "crash" #2: drop it again, the other direction

		ctx3, cancel3 := context.WithCancel(context.Background())
		ev3 := &managerEvents{}
		m3 := firewall.NewBanManager(firewall.ManagerOptions{StatePath: statePath2, Emit: ev3.emit})
		m3.Start(ctx3)
		t.Cleanup(cancel3)
		m3.ApplySync(firewall.SyncInput{Executor: "defensia", Bans: bans}) // see m2's resupply comment above

		poll(t, 90*time.Second, time.Second, func() bool {
			members := backendMembers(t)
			tagged := taggedSet(readTempban(t))
			for _, ip := range ips {
				if !members[ip] || tagged[ip] {
					return false
				}
			}
			return true
		}, "final convergence to defensia after two crashes")
	})
}

// TestLabBanSyncUndoAll (SYNC-06): undo-all removes only defensia: entries,
// is idempotent per token, and is acked via persisted state + the event.
func TestLabBanSyncUndoAll(t *testing.T) {
	testingMode, ok := csfFunctionalPreamble(t)
	if !ok {
		return
	}
	statePath := filepath.Join(t.TempDir(), "ban_executor.json")
	if testingMode {
		assertUnavailableTestingMode(t, statePath)
		return
	}

	m, ev := newManager(t, statePath)
	ips := banIPs(t, 20)
	var bans []firewall.DesiredBan
	for _, ip := range ips {
		bans = append(bans, firewall.DesiredBan{IP: ip, Reason: "r", TTL: time.Hour})
	}

	foreign := banIPs(t, 3)
	seedForeign(t, foreign[:2], time.Hour, "manual")
	seedForeign(t, foreign[2:], time.Hour, "lfd-like (sshd)")

	m.ApplySync(firewall.SyncInput{Executor: "csf", Bans: bans})
	poll(t, 60*time.Second, time.Second, func() bool {
		tagged := taggedSet(readTempban(t))
		for _, ip := range ips {
			if !tagged[ip] {
				return false
			}
		}
		return true
	}, "20 tagged")

	_, readArgv := argvLog(t)

	m.ApplySync(firewall.SyncInput{Executor: "defensia", UndoToken: "lab-T1", Bans: bans})
	poll(t, 90*time.Second, time.Second, func() bool {
		return len(taggedSet(readTempban(t))) == 0
	}, "tagged 0 after undo")

	finalForeign := foreignSet(readTempban(t))
	for _, ip := range foreign {
		if !finalForeign[ip] {
			t.Errorf("foreign %s missing after undo", ip)
		}
	}
	members := backendMembers(t)
	for _, ip := range ips {
		if !members[ip] {
			t.Errorf("%s missing from backendMembers after undo", ip)
		}
	}

	poll(t, 30*time.Second, time.Second, func() bool {
		st := m.Status()
		return st != nil && st.LastUndoToken == "lab-T1" && st.LastUndoRemoved == 20
	}, "LastUndoToken=lab-T1 LastUndoRemoved=20")

	if !ev.hasType("csf_undo_completed") {
		t.Error("csf_undo_completed event never captured")
	}

	before := len(readArgv())
	m.ApplySync(firewall.SyncInput{Executor: "defensia", UndoToken: "lab-T1", Bans: bans})
	time.Sleep(3 * time.Second)
	for _, argv := range readArgv()[before:] {
		if strings.HasPrefix(argv, "-tr") {
			t.Errorf("unexpected new -tr for the already-acked token: %q", argv)
		}
	}

	for _, argv := range readArgv() {
		if strings.HasPrefix(argv, "-tf") {
			t.Error("csf -tf must never be issued")
		}
	}
}

// TestLabBanSyncFakeBinary (SYNC-07): a misbehaving csf binary degrades the
// executor to read-only with zero further writes, and recovers once the
// binary starts answering normally again.
func TestLabBanSyncFakeBinary(t *testing.T) {
	testingMode, ok := csfFunctionalPreamble(t)
	if !ok {
		return
	}
	statePath := filepath.Join(t.TempDir(), "ban_executor.json")
	if testingMode {
		assertUnavailableTestingMode(t, statePath)
		return
	}

	runFakeBinaryCase := func(t *testing.T, mode string, expectRecovery bool) {
		modeFile := filepath.Join(t.TempDir(), "mode")
		if err := os.WriteFile(modeFile, []byte(mode), 0o644); err != nil {
			t.Fatalf("write mode file: %v", err)
		}
		logPath := filepath.Join(t.TempDir(), "argv.log")
		t.Setenv("DEFENSIA_CSF_BIN", "/root/fakecsf/csf")
		t.Setenv("FAKECSF_MODE_FILE", modeFile)
		t.Setenv("FAKECSF_REAL", "/usr/sbin/csf")
		t.Setenv("FAKECSF_LOG", logPath)
		// DEFENSIA_CSF_PROBE_SECONDS is read exactly once, at package init,
		// long before this test function ever runs — t.Setenv here would be
		// a complete no-op (lab-measured, alma9-csf-orig, phase 18-10: the
		// probe interval silently stayed at its real 5-minute default the
		// whole time). SetCSFProbeInterval is the actual runtime seam.
		t.Cleanup(firewall.SetCSFProbeInterval(5 * time.Second))

		readArgv := func() []string {
			data, _ := os.ReadFile(logPath)
			var out []string
			for _, l := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
				if l != "" {
					out = append(out, l)
				}
			}
			return out
		}
		writeCount := func() int {
			n := 0
			for _, a := range readArgv() {
				if strings.HasPrefix(a, "-td") || strings.HasPrefix(a, "-tr") {
					n++
				}
			}
			return n
		}

		sp := filepath.Join(t.TempDir(), "ban_executor.json")
		m, _ := newManager(t, sp)
		ips := banIPs(t, 5)
		var bans []firewall.DesiredBan
		for _, ip := range ips {
			bans = append(bans, firewall.DesiredBan{IP: ip, Reason: "r", TTL: time.Hour})
		}
		m.ApplySync(firewall.SyncInput{Executor: "csf", Bans: bans})

		poll(t, 60*time.Second, 2*time.Second, func() bool {
			st := m.Status()
			return st != nil && st.State == "degraded"
		}, mode+": State degraded")

		countAfterDegrade := writeCount()
		more := banIPs(t, 5)
		for _, ip := range more {
			bans = append(bans, firewall.DesiredBan{IP: ip, Reason: "r", TTL: time.Hour})
		}
		m.ApplySync(firewall.SyncInput{Executor: "csf", Bans: bans})
		time.Sleep(30 * time.Second)
		if n := writeCount(); n != countAfterDegrade {
			t.Errorf("%s: write count changed while degraded: %d -> %d", mode, countAfterDegrade, n)
		}
		members := backendMembers(t)
		for _, ip := range append(append([]string{}, ips...), more...) {
			if members[ip] {
				t.Errorf("%s: %s fell back to the Defensia backend while degraded", mode, ip)
			}
		}

		if !expectRecovery {
			return
		}

		if err := os.WriteFile(modeFile, []byte("passthrough"), 0o644); err != nil {
			t.Fatalf("write mode file: %v", err)
		}
		poll(t, 30*time.Second, time.Second, func() bool {
			st := m.Status()
			return st != nil && st.State == "ok"
		}, mode+": State ok after recovery")
		poll(t, 30*time.Second, time.Second, func() bool {
			tagged := taggedSet(readTempban(t))
			for _, ip := range append(append([]string{}, ips...), more...) {
				if !tagged[ip] {
					return false
				}
			}
			return true
		}, mode+": all 10 bans tagged after recovery")
	}

	t.Run("garbage", func(t *testing.T) { runFakeBinaryCase(t, "garbage", true) })
	t.Run("exit1", func(t *testing.T) { runFakeBinaryCase(t, "exit1", false) })
	t.Run("binary", func(t *testing.T) { runFakeBinaryCase(t, "binary", false) })
	t.Run("hang", func(t *testing.T) { runFakeBinaryCase(t, "hang", false) })
}

// TestLabBanSyncNoCSF: on a VM without CSF, executor "csf" must still
// enforce bans — on the Defensia backend, with zero csf commands issued.
func TestLabBanSyncNoCSF(t *testing.T) {
	requireRoot(t)
	if env("LAB_EXPECT_CSF") != "0" {
		t.Log("CSF VM, not applicable")
		return
	}
	stopAgent(t)

	statePath := filepath.Join(t.TempDir(), "ban_executor.json")
	m, _ := newManager(t, statePath)
	if st := m.Status(); st != nil {
		t.Errorf("Status() = %+v, want nil (CSF not installed)", st)
	}

	ips := banIPs(t, 5)
	var bans []firewall.DesiredBan
	for _, ip := range ips {
		bans = append(bans, firewall.DesiredBan{IP: ip, Reason: "r", TTL: time.Hour})
	}
	m.ApplySync(firewall.SyncInput{Executor: "csf", Bans: bans})

	poll(t, 30*time.Second, time.Second, func() bool {
		members := backendMembers(t)
		for _, ip := range ips {
			if !members[ip] {
				return false
			}
		}
		return true
	}, "bans land on the Defensia backend despite executor=csf (no CSF installed)")

	if env("LAB_VM") == "alma10-noipset" {
		if firewall.Mode() != "nftables" {
			t.Errorf("Mode() = %q, want nftables on alma10-noipset", firewall.Mode())
		}
	}

	if _, err := os.Stat("/root/fakecsf"); err == nil {
		entries, _ := os.ReadDir("/root/fakecsf")
		for _, e := range entries {
			if e.Name() != "csf" {
				t.Errorf("unexpected file in /root/fakecsf: %s (a csf command ran)", e.Name())
			}
		}
	}
	if _, err := exec.LookPath("csf"); err == nil {
		t.Error("csf binary found in PATH on a no-CSF VM — LAB_EXPECT_CSF/VM mismatch")
	}
}
