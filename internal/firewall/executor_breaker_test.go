package firewall

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBreakerDegradesAfterThreeUnexpected(t *testing.T) {
	now := time.Now()
	execFakeEnv(t)
	e := newTestExecutor(t, &now)
	calls := withExecRun(t, func(args []string) (string, int) { return "garbage output", 0 })

	e.desired = SyncInput{Bans: []DesiredBan{{IP: "203.0.113.1", Reason: "r", ExpiresAt: mustTime(now, time.Hour)}}}

	for i := 0; i < 3; i++ {
		e.runOnce(context.Background())
	}
	if e.breaker.state != "degraded" || e.breaker.reason != "unknown_line: garbage output" {
		t.Fatalf("breaker = %+v, want degraded/unknown_line after 3 unexpected outcomes", e.breaker)
	}
	before := countWriteOps(*calls)

	for i := 0; i < 10; i++ {
		e.runOnce(context.Background())
	}
	if got := countWriteOps(*calls); got != before {
		t.Errorf("no further -td/-tr writes expected once degraded, went from %d to %d (calls=%v)", before, got, *calls)
	}
	st := e.status()
	if st.State != "degraded" {
		t.Errorf("Status.State = %q, want degraded", st.State)
	}
}

func TestBreakerResetOnSuccess(t *testing.T) {
	now := time.Now()
	_, varDir := execFakeEnv(t)
	e := newTestExecutor(t, &now)
	toggle := false
	withExecRun(t, func(args []string) (string, int) {
		toggle = !toggle
		if toggle {
			return "garbage", 0
		}
		return okTempDenyOutput(args[1]), 0
	})

	for i := 0; i < 20; i++ {
		ip := testPublicIP(i)
		e.desired = SyncInput{Bans: []DesiredBan{{IP: ip, Reason: "r", ExpiresAt: mustTime(now, time.Hour)}}}
		e.runOnce(context.Background())
		if e.breaker.state != "ok" {
			t.Fatalf("pass %d: breaker degraded unexpectedly: %+v", i, e.breaker)
		}
	}
	_ = varDir
}

func TestBreakerVersionMismatchDegradesImmediately(t *testing.T) {
	now := time.Now()
	execFakeEnv(t)
	e := newTestExecutor(t, &now)
	withExecRun(t, func(args []string) (string, int) { return "not a csf banner at all", 0 })

	e.checkVersionOnce(context.Background())

	if e.breaker.state != "degraded" || e.breaker.reason != "version_unrecognised" {
		t.Fatalf("breaker = %+v, want degraded/version_unrecognised", e.breaker)
	}
}

func TestBreakerMalformedTempban(t *testing.T) {
	now := time.Now()
	_, varDir := execFakeEnv(t)
	e := newTestExecutor(t, &now)
	withExecRun(t, func(args []string) (string, int) { return "", 0 })

	writeExecTempBan(t, varDir, []string{"this-is-not-a-valid-line"})
	e.desired = SyncInput{}
	e.runOnce(context.Background())

	if e.breaker.state != "degraded" || e.breaker.reason != "tempban_format" {
		t.Fatalf("breaker = %+v, want degraded/tempban_format on the FIRST malformed-line pass", e.breaker)
	}
}

func TestBreakerNoWritesWhileDegraded(t *testing.T) {
	now := time.Now()
	execFakeEnv(t)
	e := newTestExecutor(t, &now)
	e.breaker.degradeNow("unknown_line")
	calls := withExecRun(t, func(args []string) (string, int) { return okTempDenyOutput("x"), 0 })

	e.desired = SyncInput{Bans: []DesiredBan{{IP: "203.0.113.2", Reason: "r", ExpiresAt: mustTime(now, time.Hour)}}}
	e.runOnce(context.Background())

	if got := countWriteOps(*calls); got != 0 {
		t.Errorf("-td/-tr should never be reached while degraded, got calls %v", *calls)
	}
	if e.status().Deferred != 1 {
		t.Errorf("Deferred = %d, want 1 (the one desired IP, not yet in CSF)", e.status().Deferred)
	}
}

func TestBreakerReadsContinue(t *testing.T) {
	now := time.Now()
	_, varDir := execFakeEnv(t)
	e := newTestExecutor(t, &now)
	e.breaker.degradeNow("unknown_line")
	withExecRun(t, func(args []string) (string, int) { return "", 0 })

	writeExecTempBan(t, varDir, []string{
		tempBanLine(now, "203.0.113.3", time.Hour, "defensia:r"),
		tempBanLine(now, "203.0.113.4", time.Hour, "lfd"),
	})
	e.runOnce(context.Background())

	if got := e.status().CSFTempbanTotal; got != 2 {
		t.Errorf("CSFTempbanTotal = %d, want 2 (reads keep happening while degraded)", got)
	}
}

func TestBreakerRecovery(t *testing.T) {
	now := time.Now()
	execFakeEnv(t)
	e := newTestExecutor(t, &now)
	e.breaker.degradeNow("unknown_line")

	good := true
	withExecRun(t, func(args []string) (string, int) {
		if args[0] == "-v" {
			if good {
				return "csf: v15.00 (generic)", 0
			}
			return "garbage", 0
		}
		return "", 0
	})

	e.runOnce(context.Background()) // first good probe -> still degraded
	if e.breaker.state != "degraded" {
		t.Fatalf("after 1 good probe: state = %q, want degraded (needs 2 consecutive)", e.breaker.state)
	}

	now = now.Add(csfProbeEvery + time.Second)
	e.runOnce(context.Background()) // second consecutive good probe -> ok
	if e.breaker.state != "ok" {
		t.Fatalf("after 2 consecutive good probes: state = %q, want ok", e.breaker.state)
	}

	// A bad probe resets the counter.
	e.breaker.degradeNow("unknown_line")
	now = now.Add(csfProbeEvery + time.Second)
	e.runOnce(context.Background()) // good
	good = false
	now = now.Add(csfProbeEvery + time.Second)
	e.runOnce(context.Background()) // bad -> resets
	if e.breaker.goodProbes != 0 {
		t.Errorf("goodProbes = %d, want 0 after a bad probe interleaved", e.breaker.goodProbes)
	}
}

func TestUnavailableStates(t *testing.T) {
	cases := []struct {
		name string
		conf map[string]string
		want string
	}{
		{"testing", map[string]string{"TESTING": "1", "LF_DAEMON": "1"}, "testing_mode"},
		{"lf_daemon_off", map[string]string{"LF_DAEMON": "0"}, "lf_daemon_off"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			now := time.Now()
			confDir, _ := execFakeEnv(t)
			writeExecCSFConf(t, confDir, c.conf)
			e := newTestExecutor(t, &now)
			calls := withExecRun(t, func(args []string) (string, int) { return okTempDenyOutput("x"), 0 })

			e.desired = SyncInput{Bans: []DesiredBan{{IP: "203.0.113.5", Reason: "r", ExpiresAt: mustTime(now, time.Hour)}}}
			e.runOnce(context.Background())

			if len(*calls) != 0 {
				t.Errorf("%s: expected zero writes, got %v", c.name, *calls)
			}
			if got := e.status().Reason; got != c.want {
				t.Errorf("%s: Reason = %q, want %q", c.name, got, c.want)
			}

			// Fixing the condition recovers on the very next pass, no probes needed.
			writeExecCSFConf(t, confDir, map[string]string{"LF_DAEMON": "1"})
			e.runOnce(context.Background())
			if len(*calls) == 0 {
				t.Errorf("%s: expected writes once the condition is fixed", c.name)
			}
		})
	}
}

func TestUnavailableCSFMissing(t *testing.T) {
	now := time.Now()
	execFakeEnv(t)
	e := newTestExecutor(t, &now)
	e.cli = nil // binary missing
	withExecRun(t, func(args []string) (string, int) { return "", 0 })

	e.runOnce(context.Background())
	if got := e.status().Reason; got != "csf_missing" {
		t.Errorf("Reason = %q, want csf_missing", got)
	}
}

func TestRestartPatience(t *testing.T) {
	now := time.Now()
	execFakeEnv(t)
	e := newTestExecutor(t, &now)
	e.denyinChainOK = func(context.Context) bool { return false } // DENYIN missing
	calls := withExecRun(t, func(args []string) (string, int) { return okTempDenyOutput("x"), 0 })

	e.desired = SyncInput{Bans: []DesiredBan{{IP: "203.0.113.6", Reason: "r", ExpiresAt: mustTime(now, time.Hour)}}}
	e.runOnce(context.Background())
	if e.status().State == "unavailable" {
		t.Error("a restart window shorter than csfRestartPatience must not be 'unavailable'")
	}
	if len(*calls) != 0 {
		t.Errorf("zero writes expected during a restart window, got %v", *calls)
	}

	now = now.Add(60 * time.Second)
	e.runOnce(context.Background())
	if e.status().State == "unavailable" {
		t.Error("still within patience at 60s, must not be unavailable yet")
	}

	now = now.Add(31 * time.Second) // total 91s
	e.runOnce(context.Background())
	if got := e.status(); got.State != "unavailable" || got.Reason != "csf_restarting_too_long" {
		t.Errorf("after 91s: status = %+v, want unavailable/csf_restarting_too_long", got)
	}
}

func TestIptablesErrorDuringRestartNotCounted(t *testing.T) {
	now := time.Now()
	_, varDir := execFakeEnv(t)
	e := newTestExecutor(t, &now)
	if err := os.WriteFile(filepath.Join(varDir, "csf.lock"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	withExecRun(t, func(args []string) (string, int) { return "iptables: no such table", 0 })

	// denyinChainOK false would also mark "restarting"; keep it true here so
	// the only restart signal is csf.lock, matching the plan's "OR" clause.
	e.denyinChainOK = func(context.Context) bool { return true }
	e.desired = SyncInput{Bans: []DesiredBan{{IP: "203.0.113.7", Reason: "r", ExpiresAt: mustTime(now, time.Hour)}}}

	// Writes are paused during the restart window (csf.lock present), so no
	// outcome is observed at all yet — exercise observe() directly to prove
	// the suppression rule for when writes DO occur mid-restart (e.g. a
	// trailing in-flight op from just before the lock appeared).
	outcome := CSFOutcome{Result: ResultUnexpected, Reason: "iptables_error"}
	for i := 0; i < 5; i++ {
		e.breaker.observe(outcome, true)
	}
	if e.breaker.state != "ok" {
		t.Errorf("iptables_error during a restart must never count toward degrade, state = %q", e.breaker.state)
	}
}

func TestDegradedPersistsAcrossRestart(t *testing.T) {
	w := newFakeWorld(t)
	clock := time.Now()
	path := t.TempDir() + "/ban_executor.json"

	if err := saveBanState(path, banState{Mode: "csf", Degraded: true, DegradedReason: "unknown_line"}); err != nil {
		t.Fatal(err)
	}

	prevHasCSF := guardHasCSF
	guardHasCSF = func() bool { return true }
	t.Cleanup(func() { guardHasCSF = prevHasCSF })

	m := NewBanManager(ManagerOptions{StatePath: path, Now: func() time.Time { return clock }})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)

	if m.csf.breaker.state != "degraded" {
		t.Fatalf("new BanManager should start degraded from persisted state, got %+v", m.csf.breaker)
	}

	calls := len(w.ops())
	m.csf.runOnce(ctx)
	if len(w.ops()) != calls {
		t.Errorf("no writes expected until 2 good probes recover it")
	}
}

func TestDegradedDuringSwitchBack(t *testing.T) {
	w := newFakeWorld(t)
	clock := time.Now()
	path := t.TempDir() + "/ban_executor.json"
	m, _ := newMigrateManager(t, &clock, path)
	m.csf.breaker.degradeNow("unknown_line")

	ip := "203.0.113.8"
	w.seedTemp(map[string]tempEntry{ip: {ttl: time.Hour, comment: "defensia:r", ours: true}})

	desired := []DesiredBan{{IP: ip, Reason: "r", TTL: time.Hour, ExpiresAt: mustTime(clock, time.Hour)}}
	m.ApplySync(SyncInput{Executor: "csf"})
	m.ApplySync(SyncInput{Executor: "defensia", Bans: desired})
	m.csf.runOnce(context.Background())

	if indexOfOpPrefix(w.ops(), "banipfor:"+ip+":") == -1 {
		t.Errorf("BanIPFor should still run even while degraded, ops=%v", w.ops())
	}
	if indexOfOp(w.ops(), "tr:"+ip) != -1 {
		t.Errorf("no -tr while degraded, ops=%v", w.ops())
	}
	st := m.csf.status()
	if st.State != "migrating" || st.Reason != "csf_cleanup_pending" {
		t.Errorf("status = %+v, want State migrating Reason csf_cleanup_pending", st)
	}
}

func countWriteOps(calls [][]string) int {
	n := 0
	for _, c := range calls {
		if len(c) > 0 && (c[0] == "-td" || c[0] == "-tr") {
			n++
		}
	}
	return n
}
