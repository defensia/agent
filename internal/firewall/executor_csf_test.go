package firewall

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- test fixtures -----------------------------------------------------

func writeExecCSFConf(t *testing.T, dir string, kv map[string]string) {
	t.Helper()
	var sb strings.Builder
	for k, v := range kv {
		sb.WriteString(k + ` = "` + v + "\"\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "csf.conf"), []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeExecTempBan(t *testing.T, dir string, lines []string) {
	t.Helper()
	content := ""
	for _, l := range lines {
		content += l + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "csf.tempban"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// testPublicIP cycles through public TEST-NET blocks (RFC 5737), unlike
// sprintfIP (planner tests) which deliberately emits private 10.x IPs. The
// worker tests exercise the real guardCheck (not a stub), and a private IP
// is always refused as "safe" before ever reaching the add/defer logic.
func testPublicIP(n int) string {
	blocks := [][3]int{{203, 0, 113}, {198, 51, 100}, {192, 0, 2}}
	block := blocks[(n/254)%len(blocks)]
	host := n%254 + 1
	return fmt.Sprintf("%d.%d.%d.%d", block[0], block[1], block[2], host)
}

func tempBanLine(now time.Time, ip string, ttl time.Duration, comment string) string {
	return fmt.Sprintf("%d|%s|*|inout|%d|%s", now.Unix(), ip, int(ttl/time.Second), comment)
}

// execFakeEnv sets csfDir/csfVarDir to fresh temp dirs for the duration of
// the test (the same seam architecture guard_test.go already uses), and
// writes a permissive default csf.conf (not TESTING, LF_DAEMON on).
func execFakeEnv(t *testing.T) (confDir, varDir string) {
	t.Helper()
	confDir = t.TempDir()
	varDir = t.TempDir()
	oldDir, oldVar := csfDir, csfVarDir
	csfDir, csfVarDir = confDir, varDir
	t.Cleanup(func() { csfDir, csfVarDir = oldDir, oldVar })
	writeExecCSFConf(t, confDir, map[string]string{"LF_DAEMON": "1"})
	writeExecTempBan(t, varDir, nil)
	return confDir, varDir
}

// newTestExecutor builds a csfExecutor with every seam under test control:
// no real exec, a fake clock, and a no-op sleep (tests that care about
// rate-limit spacing override sleep themselves to record calls instead).
func newTestExecutor(t *testing.T, clock *time.Time) *csfExecutor {
	t.Helper()
	// lfdRunningFn is a package-level seam (its own doc comment: "nil
	// (unknown) is treated as 'don't block on this', only an explicit
	// false degrades") — the real lfdRunning(ctx) genuinely returns an
	// explicit false on any real Linux machine with no lfd process
	// running at all (never installed, as in CI), short-circuiting
	// environmentReady() to "lfd_not_running" before these tests ever
	// reach the breaker/worker logic they actually exercise. On a Mac
	// (no systemd/ps-based detection even attempted) the same call
	// returns nil, masking this locally. Lab-measured, phase 18-12:
	// every Breaker*/Worker*/Unavailable*/RestartPatience test failed
	// the first time this package ever ran in real Linux CI.
	prevLFD := lfdRunningFn
	running := true
	lfdRunningFn = func(context.Context) *bool { return &running }
	t.Cleanup(func() { lfdRunningFn = prevLFD })

	e := &csfExecutor{
		wake:          make(chan struct{}, 1),
		cli:           &csfCLI{bin: "test"},
		local:         map[string]localBan{},
		backoff:       map[string]time.Time{},
		prevOurs:      map[string]TempBanEntry{},
		vanish:        map[string]int{},
		keep:          map[string]bool{},
		denyinChainOK: func(context.Context) bool { return true },
		breaker:       newBreaker(),
		now:           func() time.Time { return *clock },
		sleep:         func(time.Duration) {},
		emit:          func(ExecutorEvent) {},
	}
	return e
}

// withExecRun stubs csfRun (the single CSF exec seam) and records every
// call's argv.
func withExecRun(t *testing.T, fn func(args []string) (string, int)) *[][]string {
	t.Helper()
	var calls [][]string
	prev := csfRun
	csfRun = func(ctx context.Context, bin string, args ...string) ([]byte, int, error) {
		calls = append(calls, append([]string{}, args...))
		out, code := fn(args)
		return []byte(out), code, nil
	}
	t.Cleanup(func() { csfRun = prev })
	return &calls
}

// statefulCSF is a fake CSF that actually persists -td/-tr into a real
// csf.tempban file on disk (like real CSF does), so the worker's own
// confirm-read step sees its own writes — needed by any test that checks
// DefensiaInCSF / make-before-break behaviour, not just argv shape.
type statefulCSF struct {
	varDir  string
	now     func() time.Time
	entries map[string]struct {
		ttl     time.Duration
		comment string
		added   int64
	}
}

func newStatefulCSF(varDir string, now func() time.Time) *statefulCSF {
	return &statefulCSF{varDir: varDir, now: now, entries: map[string]struct {
		ttl     time.Duration
		comment string
		added   int64
	}{}}
}

func (s *statefulCSF) handle(args []string) (string, int) {
	switch args[0] {
	case "-td":
		ip, ttlStr, comment := args[1], args[2], args[3]
		var ttlSec int
		fmt.Sscanf(ttlStr, "%d", &ttlSec)
		s.entries[ip] = struct {
			ttl     time.Duration
			comment string
			added   int64
		}{time.Duration(ttlSec) * time.Second, comment, s.now().Unix()}
		s.flush()
		return "csf: " + ip + " blocked on port * for " + ttlStr + " seconds inbound\n", 0
	case "-tr":
		ip := args[1]
		delete(s.entries, ip)
		s.flush()
		return "csf: temporary block removed\n", 0
	}
	return "", 0
}

func (s *statefulCSF) flush() {
	var lines []string
	for ip, e := range s.entries {
		lines = append(lines, fmt.Sprintf("%d|%s|*|inout|%d|%s", e.added, ip, int(e.ttl/time.Second), e.comment))
	}
	content := strings.Join(lines, "\n")
	if len(lines) > 0 {
		content += "\n"
	}
	os.WriteFile(filepath.Join(s.varDir, "csf.tempban"), []byte(content), 0o644)
}

func okTempDenyOutput(ip string) string {
	return "csf: " + ip + " blocked on port * for 86400 seconds inbound\n"
}

func okTempRemoveOutput() string {
	return "csf: temporary block removed\n"
}

// --- behavior tests ------------------------------------------------------

func TestWorkerAddsWithTagAndTTL(t *testing.T) {
	now := time.Now()
	_, varDir := execFakeEnv(t)
	e := newTestExecutor(t, &now)

	fake := newStatefulCSF(varDir, func() time.Time { return now })
	calls := withExecRun(t, fake.handle)

	e.desired = SyncInput{Bans: []DesiredBan{
		{IP: "203.0.113.1", Reason: "r1", ExpiresAt: mustTime(now, time.Hour)},
		{IP: "203.0.113.2", Reason: "r2", ExpiresAt: mustTime(now, time.Hour)},
		{IP: "203.0.113.3", Reason: "r3", ExpiresAt: mustTime(now, time.Hour)},
	}}
	e.runOnce(context.Background())

	if len(*calls) != 3 {
		t.Fatalf("got %d csf calls, want 3: %v", len(*calls), *calls)
	}
	for i, c := range *calls {
		if c[0] != "-td" || !strings.HasPrefix(c[3], "defensia:") {
			t.Errorf("call[%d] = %v, want -td ... defensia:...", i, c)
		}
	}

	st := e.status()
	if st.DefensiaInCSF != 3 || st.State != "ok" {
		t.Errorf("status = %+v, want DefensiaInCSF 3 State ok", st)
	}
}

func TestWorkerRemovesOnPanelUnban(t *testing.T) {
	now := time.Now()
	_, varDir := execFakeEnv(t)
	writeExecTempBan(t, varDir, []string{tempBanLine(now, "203.0.113.5", 24*time.Hour, "defensia:r")})

	e := newTestExecutor(t, &now)
	calls := withExecRun(t, func(args []string) (string, int) {
		if args[0] == "-tr" {
			return okTempRemoveOutput(), 0
		}
		return "", 0
	})

	e.desired = SyncInput{Bans: nil} // panel no longer wants it banned
	e.runOnce(context.Background())

	var removes int
	for _, c := range *calls {
		if c[0] == "-tr" {
			removes++
			if c[1] != "203.0.113.5" {
				t.Errorf("-tr argv = %v, want IP 203.0.113.5", c)
			}
		}
	}
	if removes != 1 {
		t.Fatalf("got %d -tr calls, want 1", removes)
	}
}

func TestWorkerRateLimit(t *testing.T) {
	now := time.Now()
	execFakeEnv(t)
	e := newTestExecutor(t, &now)
	withExecRun(t, func(args []string) (string, int) {
		if args[0] == "-td" {
			return okTempDenyOutput(args[1]), 0
		}
		return "", 0
	})

	var sleeps []time.Duration
	e.sleep = func(d time.Duration) { sleeps = append(sleeps, d) }

	var bans []DesiredBan
	for i := 0; i < 10; i++ {
		bans = append(bans, DesiredBan{IP: testPublicIP(i), Reason: "r", ExpiresAt: mustTime(now, time.Hour)})
	}
	e.desired = SyncInput{Bans: bans}
	e.runOnce(context.Background())

	if len(sleeps) != 9 { // spacing between 10 ops = 9 gaps
		t.Fatalf("got %d sleeps, want 9", len(sleeps))
	}
	for _, d := range sleeps {
		if d != csfMinInterval {
			t.Errorf("sleep = %v, want %v", d, csfMinInterval)
		}
	}
}

func TestWorkerOpsCapPerPass(t *testing.T) {
	now := time.Now()
	execFakeEnv(t)
	e := newTestExecutor(t, &now)
	calls := withExecRun(t, func(args []string) (string, int) {
		if args[0] == "-td" {
			return okTempDenyOutput(args[1]), 0
		}
		return "", 0
	})

	var bans []DesiredBan
	for i := 0; i < 3*csfMaxOpsPerPass; i++ {
		bans = append(bans, DesiredBan{IP: testPublicIP(i), Reason: "r", ExpiresAt: mustTime(now, time.Hour)})
	}
	e.desired = SyncInput{Bans: bans}
	e.runOnce(context.Background())

	if len(*calls) != csfMaxOpsPerPass {
		t.Fatalf("pass 1: got %d ops, want %d", len(*calls), csfMaxOpsPerPass)
	}
}

// TestWorkerOpsCapSelfWakes is the regression test for the lab-measured
// convergence stall (phase 18-10, alma9-csf-orig): a burst truncated purely
// by csfMaxOpsPerPass (real budget still has room) must self-wake so the
// NEXT pass runs without any external setDesired call or waiting for the
// 60s ticker — proven here by calling run()'s own wake-triggered path twice
// in a row with nothing re-arming e.wake except the executor itself.
func TestWorkerOpsCapSelfWakes(t *testing.T) {
	now := time.Now()
	execFakeEnv(t)
	e := newTestExecutor(t, &now)
	withExecRun(t, func(args []string) (string, int) {
		if args[0] == "-td" {
			return okTempDenyOutput(args[1]), 0
		}
		return "", 0
	})

	var bans []DesiredBan
	for i := 0; i < 3*csfMaxOpsPerPass; i++ {
		bans = append(bans, DesiredBan{IP: testPublicIP(i), Reason: "r", ExpiresAt: mustTime(now, time.Hour)})
	}
	e.desired = SyncInput{Bans: bans}
	e.runOnce(context.Background())

	select {
	case <-e.wake:
	default:
		t.Fatal("pass 1 left candidates deferred purely by the ops cap but did not self-wake")
	}

	calls2 := withExecRun(t, func(args []string) (string, int) {
		if args[0] == "-td" {
			return okTempDenyOutput(args[1]), 0
		}
		return "", 0
	})
	e.runOnce(context.Background())
	if len(*calls2) != csfMaxOpsPerPass {
		t.Fatalf("pass 2 (self-woken): got %d ops, want %d", len(*calls2), csfMaxOpsPerPass)
	}
}

func TestWorkerNonBlocking(t *testing.T) {
	now := time.Now()
	execFakeEnv(t)
	e := newTestExecutor(t, &now)
	block := make(chan struct{})
	withExecRun(t, func(args []string) (string, int) {
		<-block // hang until the test releases it
		return okTempDenyOutput("x"), 0
	})

	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	e.desired = SyncInput{Bans: []DesiredBan{{IP: "203.0.113.9", Reason: "r", ExpiresAt: mustTime(now, time.Hour)}}}
	go func() { e.run(ctx); close(stopped) }()
	e.wakeUp()

	// Release the hung run() goroutine and wait for it to fully exit before
	// returning — otherwise it keeps reading package-level test seams
	// (csfDir/csfVarDir) after this test's own t.Cleanup has already reset
	// them for the next test, which is a real data race, not just a test
	// hygiene nit.
	t.Cleanup(func() {
		cancel()
		close(block)
		select {
		case <-stopped:
		case <-time.After(2 * time.Second):
			t.Error("worker goroutine did not exit after ctx cancellation + unblocking the hung exec")
		}
	})

	done := make(chan struct{})
	go func() {
		e.setDesired(SyncInput{}, false)
		e.localBanIP("203.0.113.10", "ssh")
		e.localUnbanIP("203.0.113.10")
		_ = e.status()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("manager-facing calls blocked on a hung csf exec")
	}
}

func TestWorkerConfirmThenUnban(t *testing.T) {
	now := time.Now()
	_, varDir := execFakeEnv(t)
	e := newTestExecutor(t, &now)
	fake := newStatefulCSF(varDir, func() time.Time { return now })
	withExecRun(t, fake.handle)

	var unbanned []string
	origMembers := banMembersFn
	origUnban := unbanIPFn
	banMembersFn = func() map[string]bool { return map[string]bool{"203.0.113.20": true} }
	unbanIPFn = func(ip string) error { unbanned = append(unbanned, ip); return nil }
	t.Cleanup(func() { banMembersFn = origMembers; unbanIPFn = origUnban })

	e.desired = SyncInput{Bans: []DesiredBan{{IP: "203.0.113.20", Reason: "r", ExpiresAt: mustTime(now, time.Hour)}}}
	e.runOnce(context.Background())

	if len(unbanned) != 1 || unbanned[0] != "203.0.113.20" {
		t.Errorf("unbanIPFn calls = %v, want [203.0.113.20] (confirmed in csf.tempban + present on Defensia backend)", unbanned)
	}

	// Now simulate: -td reports OK but the IP never actually lands in
	// csf.tempban on the confirm read (write failed silently) — must NOT unban.
	// Use a fresh IP (the previous one is already "ours" and would just hit
	// the renew path, not the fresh-add-then-confirm path).
	withExecRun(t, func(args []string) (string, int) {
		if args[0] == "-td" {
			return okTempDenyOutput(args[1]), 0 // reports OK, but never written to disk
		}
		return "", 0
	})
	writeExecTempBan(t, varDir, nil)
	unbanned = nil
	e.desired = SyncInput{Bans: []DesiredBan{{IP: "203.0.113.25", Reason: "r", ExpiresAt: mustTime(now, time.Hour)}}}
	e.runOnce(context.Background())
	if len(unbanned) != 0 {
		t.Errorf("unbanIPFn should not be called when the confirm read shows the IP absent, got %v", unbanned)
	}
}

func TestWorkerMembersErrorKeepsAll(t *testing.T) {
	now := time.Now()
	_, varDir := execFakeEnv(t)
	writeExecTempBan(t, varDir, []string{tempBanLine(now, "203.0.113.21", 24*time.Hour, "defensia:r")})
	e := newTestExecutor(t, &now)
	withExecRun(t, func(args []string) (string, int) { return "", 0 })

	origMembers := banMembersFn
	origUnban := unbanIPFn
	var unbanned []string
	banMembersFn = func() map[string]bool { return map[string]bool{} } // "Members() failed" sentinel
	unbanIPFn = func(ip string) error { unbanned = append(unbanned, ip); return nil }
	t.Cleanup(func() { banMembersFn = origMembers; unbanIPFn = origUnban })

	e.desired = SyncInput{Bans: []DesiredBan{{IP: "203.0.113.21", Reason: "r", ExpiresAt: mustTime(now, time.Hour)}}}
	e.runOnce(context.Background())

	if len(unbanned) != 0 {
		t.Errorf("unbanIPFn should never be called when Members() came back empty/errored, got %v", unbanned)
	}
}

func TestWorkerKeepsThreatFeed(t *testing.T) {
	now := time.Now()
	_, varDir := execFakeEnv(t)
	writeExecTempBan(t, varDir, []string{tempBanLine(now, "203.0.113.22", 24*time.Hour, "defensia:r")})
	e := newTestExecutor(t, &now)
	withExecRun(t, func(args []string) (string, int) { return "", 0 })

	origMembers := banMembersFn
	origUnban := unbanIPFn
	var unbanned []string
	banMembersFn = func() map[string]bool { return map[string]bool{"203.0.113.22": true} }
	unbanIPFn = func(ip string) error { unbanned = append(unbanned, ip); return nil }
	t.Cleanup(func() { banMembersFn = origMembers; unbanIPFn = origUnban })

	e.desired = SyncInput{
		Bans:          []DesiredBan{{IP: "203.0.113.22", Reason: "r", ExpiresAt: mustTime(now, time.Hour)}},
		ThreatFeedIPs: map[string]bool{"203.0.113.22": true},
	}
	e.runOnce(context.Background())

	if len(unbanned) != 0 {
		t.Errorf("threat-feed IPs must never be removed by the CSF executor, got unban calls %v", unbanned)
	}
	if !e.ipsetKeep()["203.0.113.22"] {
		t.Error("threat-feed IP should be kept on the Defensia backend")
	}
}

// TestSetDesiredFreshSwitchSeedsKeep is the regression test for the
// lab-measured make-before-break violation (phase 18-10, alma9-csf-orig):
// setDesired(in, true) — the freshSwitch path BanManager.ApplySync takes
// right after a detected defensia -> csf switch — must seed ipsetKeep()
// with every IP in in.Bans BEFORE returning, since ApplySync calls
// cleanupStaleBansFn synchronously (same goroutine) immediately afterward,
// well before the worker's own goroutine has had any chance to run a pass
// and populate a real "not yet confirmed" keep set via confirmAndHandOver.
// Without this, that very first cleanup call used an empty keep set and
// stripped Defensia-backend protection from every IP before CSF had ever
// picked any of them up.
func TestSetDesiredFreshSwitchSeedsKeep(t *testing.T) {
	now := time.Now()
	e := newTestExecutor(t, &now)

	bans := []DesiredBan{
		{IP: "203.0.113.30", Reason: "r", ExpiresAt: mustTime(now, time.Hour)},
		{IP: "203.0.113.31", Reason: "r", ExpiresAt: mustTime(now, time.Hour)},
	}

	e.setDesired(SyncInput{Bans: bans}, true)
	keep := e.ipsetKeep()
	if !keep["203.0.113.30"] || !keep["203.0.113.31"] {
		t.Errorf("ipsetKeep() = %v after a fresh-switch setDesired, want both bans kept", keep)
	}
}

// TestSetDesiredOrdinaryResyncLeavesKeepAlone proves the fix is scoped to
// freshSwitch only: an ordinary steady-state resync (freshSwitch false)
// must not force everything back into ipsetKeep(), or every routine
// re-sync would redundantly re-protect already-CSF-confirmed IPs on the
// Defensia backend too, defeating confirmAndHandOver's own narrower,
// worker-computed keep set.
func TestSetDesiredOrdinaryResyncLeavesKeepAlone(t *testing.T) {
	now := time.Now()
	e := newTestExecutor(t, &now)
	e.keep = map[string]bool{"203.0.113.32": true} // simulates confirmAndHandOver's prior, narrower result

	e.setDesired(SyncInput{Bans: []DesiredBan{
		{IP: "203.0.113.32", Reason: "r", ExpiresAt: mustTime(now, time.Hour)},
		{IP: "203.0.113.33", Reason: "r", ExpiresAt: mustTime(now, time.Hour)},
	}}, false)

	keep := e.ipsetKeep()
	if keep["203.0.113.33"] {
		t.Errorf("ipsetKeep() = %v, want 203.0.113.33 NOT force-kept on an ordinary (non-switch) resync", keep)
	}
	if !keep["203.0.113.32"] {
		t.Error("ipsetKeep() should still have the pre-existing entry untouched")
	}
}

func TestWorkerUnbanNoBackend(t *testing.T) {
	now := time.Now()
	_, varDir := execFakeEnv(t)
	writeExecTempBan(t, varDir, []string{tempBanLine(now, "203.0.113.23", 24*time.Hour, "defensia:r")})
	e := newTestExecutor(t, &now)
	withExecRun(t, func(args []string) (string, int) { return "", 0 })

	origMembers := banMembersFn
	origUnban := unbanIPFn
	calls := 0
	banMembersFn = func() map[string]bool { return map[string]bool{"203.0.113.23": true} }
	unbanIPFn = func(ip string) error { calls++; return ErrNoBackend }
	t.Cleanup(func() { banMembersFn = origMembers; unbanIPFn = origUnban })

	e.desired = SyncInput{Bans: []DesiredBan{{IP: "203.0.113.23", Reason: "r", ExpiresAt: mustTime(now, time.Hour)}}}
	e.runOnce(context.Background())
	e.runOnce(context.Background())

	if calls != 2 {
		t.Errorf("unbanIPFn called %d times across 2 passes, want 2 (one attempt per pass, not retried in a tight loop within a pass)", calls)
	}
}

func TestWorkerRefusedOutcome(t *testing.T) {
	now := time.Now()
	execFakeEnv(t)
	e := newTestExecutor(t, &now)
	var events []ExecutorEvent
	done := make(chan struct{}, 10)
	e.emit = func(ev ExecutorEvent) { events = append(events, ev); done <- struct{}{} }
	withExecRun(t, func(args []string) (string, int) {
		return "csf: 203.0.113.24 is not a valid PUBLIC IP\n", 0
	})

	e.desired = SyncInput{Bans: []DesiredBan{{IP: "203.0.113.24", Reason: "r", ExpiresAt: mustTime(now, time.Hour)}}}
	e.runOnce(context.Background())
	<-done

	if len(events) != 1 || events[0].Details["reason"] != "refused" {
		t.Fatalf("events = %+v, want one csf_ban_deferred{reason:refused}", events)
	}
	if _, has := e.backoff["203.0.113.24"]; !has {
		t.Error("refused IP should be backed off")
	}
}

func TestWorkerDeferredCounts(t *testing.T) {
	now := time.Now()
	confDir, _ := execFakeEnv(t)
	writeExecCSFConf(t, confDir, map[string]string{"LF_DAEMON": "1", "DENY_TEMP_IP_LIMIT": "12"})
	e := newTestExecutor(t, &now)
	var events []ExecutorEvent
	done := make(chan struct{}, 10)
	e.emit = func(ev ExecutorEvent) { events = append(events, ev); done <- struct{}{} }
	withExecRun(t, func(args []string) (string, int) {
		if args[0] == "-td" {
			return okTempDenyOutput(args[1]), 0
		}
		return "", 0
	})

	var bans []DesiredBan
	for i := 0; i < 5; i++ {
		bans = append(bans, DesiredBan{IP: testPublicIP(i), Reason: "r", ExpiresAt: mustTime(now, time.Hour)})
	}
	e.desired = SyncInput{Bans: bans}
	e.runOnce(context.Background())
	<-done

	if e.status().Deferred != 3 {
		t.Errorf("Deferred = %d, want 3 (budget 2 of 5 desired)", e.status().Deferred)
	}
	var capacityEvent *ExecutorEvent
	for i := range events {
		if events[i].Details["reason"] == "capacity" {
			capacityEvent = &events[i]
		}
	}
	if capacityEvent == nil || capacityEvent.Details["count"] != "3" {
		t.Errorf("events = %+v, want a csf_ban_deferred{reason:capacity,count:3}", events)
	}
}

func TestWorkerLocalBan(t *testing.T) {
	now := time.Now()
	execFakeEnv(t)
	e := newTestExecutor(t, &now)
	calls := withExecRun(t, func(args []string) (string, int) {
		if args[0] == "-td" {
			return okTempDenyOutput(args[1]), 0
		}
		return "", 0
	})

	e.localBanIP("203.0.113.30", "ssh")
	e.runOnce(context.Background())

	if len(*calls) != 1 || (*calls)[0][0] != "-td" || (*calls)[0][1] != "203.0.113.30" || (*calls)[0][2] != "86400" {
		t.Fatalf("local ban call = %v, want -td 203.0.113.30 86400 defensia:ssh", *calls)
	}
}

func TestWorkerStatusLimitUnknown(t *testing.T) {
	now := time.Now()
	execFakeEnv(t) // LF_DAEMON only, no DENY_TEMP_IP_LIMIT key
	e := newTestExecutor(t, &now)
	withExecRun(t, func(args []string) (string, int) { return "", 0 })

	e.desired = SyncInput{}
	e.runOnce(context.Background())

	if e.status().CSFLimit != -1 {
		t.Errorf("CSFLimit = %d, want -1 (DENY_TEMP_IP_LIMIT absent)", e.status().CSFLimit)
	}
}

func TestWorkerTornReadNoStorm(t *testing.T) {
	now := time.Now()
	_, varDir := execFakeEnv(t)
	e := newTestExecutor(t, &now)
	calls := withExecRun(t, func(args []string) (string, int) {
		if args[0] == "-td" {
			return okTempDenyOutput(args[1]), 0
		}
		return "", 0
	})

	// Malformed line only -> parses to zero entries, Exists true, no error;
	// this is a legitimately empty tempban file, not a busy/torn read, so a
	// pass IS allowed to proceed (ErrTempBanBusy is the only "skip" signal).
	writeExecTempBan(t, varDir, []string{"garbage-not-six-fields"})
	e.desired = SyncInput{Bans: []DesiredBan{{IP: "203.0.113.31", Reason: "r", ExpiresAt: mustTime(now, time.Hour)}}}
	e.runOnce(context.Background())
	if len(*calls) != 1 {
		t.Fatalf("expected the pass to proceed on a malformed-but-readable file, got %d calls", len(*calls))
	}
}

// eventRecorder collects emitEvent's goroutine-fired events safely and lets
// a test wait for a specific one without depending on emission order.
type eventRecorder struct {
	mu     sync.Mutex
	events []ExecutorEvent
	signal chan struct{}
}

func newEventRecorder() *eventRecorder {
	return &eventRecorder{signal: make(chan struct{}, 64)}
}

func (r *eventRecorder) emit(ev ExecutorEvent) {
	r.mu.Lock()
	r.events = append(r.events, ev)
	r.mu.Unlock()
	select {
	case r.signal <- struct{}{}:
	default:
	}
}

func (r *eventRecorder) waitFor(t *testing.T, pred func(ExecutorEvent) bool, timeout time.Duration) *ExecutorEvent {
	t.Helper()
	deadline := time.After(timeout)
	for {
		r.mu.Lock()
		for i := range r.events {
			if pred(r.events[i]) {
				ev := r.events[i]
				r.mu.Unlock()
				return &ev
			}
		}
		r.mu.Unlock()
		select {
		case <-r.signal:
		case <-deadline:
			return nil
		}
	}
}

func TestWorkerEvictionBackoff(t *testing.T) {
	now := time.Now()
	confDir, varDir := execFakeEnv(t)
	// limit 12, reserve 10 -> budget 2 at 0 existing entries: enough for our
	// single pass-1 add. Later filled to 11 foreign entries (>= limit-1),
	// so the eventual removal is classified "evicted", not "removed_externally".
	writeExecCSFConf(t, confDir, map[string]string{"LF_DAEMON": "1", "DENY_TEMP_IP_LIMIT": "12"})
	e := newTestExecutor(t, &now)
	fake := newStatefulCSF(varDir, func() time.Time { return now })
	withExecRun(t, fake.handle)

	rec := newEventRecorder()
	e.emit = rec.emit

	ip := "203.0.113.40"
	e.desired = SyncInput{Bans: []DesiredBan{{IP: ip, Reason: "r", ExpiresAt: mustTime(now, 24*time.Hour)}}}
	e.runOnce(context.Background()) // pass 1: adds it, confirmed present
	if !fakeHasEntry(fake, ip) {
		t.Fatalf("precondition failed: ip was not actually added in pass 1 (entries=%v)", fake.entries)
	}

	// Simulate LFD evicting our entry externally, then fill the tempban file
	// up near DENY_TEMP_IP_LIMIT (12) with foreign entries.
	delete(fake.entries, ip)
	for i := 0; i < 11; i++ {
		fake.entries[testPublicIP(100+i)] = struct {
			ttl     time.Duration
			comment string
			added   int64
		}{time.Hour, "lfd", now.Unix()}
	}
	fake.flush()

	// Refuse re-adding ip this pass so the worker's own self-heal never
	// masks the externally-observed removal before detection runs.
	e.guard = func(candidate string) (bool, string) {
		if candidate == ip {
			return false, "test_hold"
		}
		return true, ""
	}

	e.runOnce(context.Background()) // pass 2: first miss observed
	e.runOnce(context.Background()) // pass 3: second consecutive miss -> classified

	found := rec.waitFor(t, func(ev ExecutorEvent) bool { return ev.Details["ip"] == ip }, time.Second)
	if found == nil || found.Details["reason"] != "evicted" {
		t.Fatalf("events = %+v, want a csf_ban_deferred{ip:%s,reason:evicted}", rec.events, ip)
	}
	if e.status().State != "capacity_exhausted" {
		t.Errorf("State = %q, want capacity_exhausted", e.status().State)
	}
	if until, has := e.backoff[ip]; !has || !until.After(now) {
		t.Errorf("evicted IP should be backed off, got %v", e.backoff[ip])
	}
}

func TestWorkerExternalRemoval(t *testing.T) {
	now := time.Now()
	confDir, varDir := execFakeEnv(t)
	writeExecCSFConf(t, confDir, map[string]string{"LF_DAEMON": "1", "DENY_TEMP_IP_LIMIT": "10000"})
	e := newTestExecutor(t, &now)
	fake := newStatefulCSF(varDir, func() time.Time { return now })
	withExecRun(t, fake.handle)

	rec := newEventRecorder()
	e.emit = rec.emit

	ip := "203.0.113.41"
	e.desired = SyncInput{Bans: []DesiredBan{{IP: ip, Reason: "r", ExpiresAt: mustTime(now, 24*time.Hour)}}}
	e.runOnce(context.Background()) // pass 1: adds it, confirmed present
	if !fakeHasEntry(fake, ip) {
		t.Fatalf("precondition failed: ip was not actually added in pass 1 (entries=%v)", fake.entries)
	}

	// Total is nowhere near the (very high) limit — a removal here is not
	// capacity pressure, so it must be classified "removed_externally".
	delete(fake.entries, ip)
	fake.flush()

	e.guard = func(candidate string) (bool, string) {
		if candidate == ip {
			return false, "test_hold"
		}
		return true, ""
	}

	e.runOnce(context.Background())
	e.runOnce(context.Background())

	found := rec.waitFor(t, func(ev ExecutorEvent) bool { return ev.Details["ip"] == ip }, time.Second)
	if found == nil || found.Details["reason"] != "removed_externally" {
		t.Fatalf("events = %+v, want a csf_ban_deferred{ip:%s,reason:removed_externally}", rec.events, ip)
	}
	if e.status().State == "capacity_exhausted" {
		t.Error("a low-pressure external removal must not report capacity_exhausted")
	}
}

func fakeHasEntry(fake *statefulCSF, ip string) bool {
	_, ok := fake.entries[ip]
	return ok
}
