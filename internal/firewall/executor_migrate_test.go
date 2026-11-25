package firewall

import (
	"context"
	"strings"
	"testing"
	"time"
)

// newMigrateManager builds a BanManager with a manually-wired csfExecutor
// (no real CSF binary resolution, no background goroutine — tests call
// runOnce/runMigratePass directly for determinism), on top of a fakeWorld.
func newMigrateManager(t *testing.T, clock *time.Time, path string) (*BanManager, *eventRecorder) {
	t.Helper()
	prevHasCSF := guardHasCSF
	guardHasCSF = func() bool { return true } // Status()/this package always treats CSF as installed here
	t.Cleanup(func() { guardHasCSF = prevHasCSF })

	rec := newEventRecorder()
	m := NewBanManager(ManagerOptions{StatePath: path, Now: func() time.Time { return *clock }, Emit: rec.emit})
	e := &csfExecutor{
		wake: make(chan struct{}, 1), cli: &csfCLI{bin: "test"},
		local: map[string]localBan{}, backoff: map[string]time.Time{},
		prevOurs: map[string]TempBanEntry{}, vanish: map[string]int{}, keep: map[string]bool{},
		denyinChainOK: func(context.Context) bool { return true },
		breaker:       newBreaker(),
		now:           func() time.Time { return *clock }, sleep: func(time.Duration) {}, emit: rec.emit,
	}
	e.onMigrationDone = m.migrationDone
	e.onDegradedChange = m.degradedChanged
	e.onUndoComplete = m.undoCompleted
	m.csf = e
	return m, rec
}

func indexOfOp(ops []string, exact string) int {
	for i, o := range ops {
		if o == exact {
			return i
		}
	}
	return -1
}

func indexOfOpPrefix(ops []string, prefix string) int {
	for i, o := range ops {
		if strings.HasPrefix(o, prefix) {
			return i
		}
	}
	return -1
}

func TestSwitchDefensiaToCSFPersistsFirst(t *testing.T) {
	w := newFakeWorld(t)
	clock := time.Now()
	path := t.TempDir() + "/ban_executor.json"
	m, rec := newMigrateManager(t, &clock, path)

	desired := []DesiredBan{{IP: "203.0.113.1", Reason: "r", ExpiresAt: mustTime(clock, time.Hour)}}
	m.ApplySync(SyncInput{Executor: "csf", Bans: desired})

	got := loadBanState(path)
	if got.Mode != "csf" || !got.Migrating || got.MigrationTarget != "csf" {
		t.Fatalf("state after ApplySync (before any runner call) = %+v, want Mode csf Migrating true MigrationTarget csf", got)
	}
	if len(w.ops()) != 0 {
		t.Fatalf("runner should not have been called yet, got ops %v", w.ops())
	}

	m.csf.runOnce(context.Background())

	if got := loadBanState(path); got.Migrating {
		t.Errorf("after convergence, Migrating should be false, got %+v", got)
	}

	var switches []ExecutorEvent
	rec.mu.Lock()
	for _, ev := range rec.events {
		if ev.Type == "csf_executor_switched" {
			switches = append(switches, ev)
		}
	}
	rec.mu.Unlock()
	if len(switches) != 1 {
		t.Fatalf("csf_executor_switched emitted %d times, want 1", len(switches))
	}
	if switches[0].Details["from"] != "defensia" || switches[0].Details["to"] != "csf" {
		t.Errorf("event details = %+v, want from:defensia to:csf", switches[0].Details)
	}
}

func TestSwitchCSFToDefensiaBackendFirst(t *testing.T) {
	w := newFakeWorld(t)
	clock := time.Now()
	path := t.TempDir() + "/ban_executor.json"
	m, _ := newMigrateManager(t, &clock, path)

	var desired []DesiredBan
	entries := map[string]tempEntry{}
	for i := 0; i < 5; i++ {
		ip := testPublicIP(i)
		ttl := time.Duration(i+1) * time.Hour
		desired = append(desired, DesiredBan{IP: ip, Reason: "r", TTL: ttl, ExpiresAt: mustTime(clock, ttl)})
		entries[ip] = tempEntry{ttl: time.Hour, comment: "defensia:r", ours: true}
	}
	for i := 0; i < 2; i++ {
		entries[testPublicIP(50+i)] = tempEntry{ttl: time.Hour, comment: "defensia:old", ours: true}
	}
	for i := 0; i < 3; i++ {
		entries[testPublicIP(100+i)] = tempEntry{ttl: time.Hour, comment: "lfd", ours: false}
	}
	w.seedTemp(entries)

	m.ApplySync(SyncInput{Executor: "csf"}) // establish prevMode=csf
	m.ApplySync(SyncInput{Executor: "defensia", Bans: desired})
	m.csf.runOnce(context.Background())

	ops := w.ops()
	for _, d := range desired {
		idxBan := indexOfOpPrefix(ops, "banipfor:"+d.IP+":")
		idxTr := indexOfOp(ops, "tr:"+d.IP)
		if idxBan == -1 || idxTr == -1 {
			t.Errorf("%s: missing banipfor/tr in ops %v", d.IP, ops)
			continue
		}
		if idxBan > idxTr {
			t.Errorf("%s: banipfor must precede tr, ops=%v", d.IP, ops)
		}
		if !strings.Contains(ops[idxBan], d.TTL.String()) {
			t.Errorf("%s: banipfor op %q does not mention TTL %v", d.IP, ops[idxBan], d.TTL)
		}
	}
	for i := 0; i < 2; i++ {
		ip := testPublicIP(50 + i)
		if indexOfOp(ops, "tr:"+ip) == -1 {
			t.Errorf("non-desired ours %s should have been removed, ops=%v", ip, ops)
		}
	}
	for i := 0; i < 3; i++ {
		ip := testPublicIP(100 + i)
		for _, op := range ops {
			if strings.Contains(op, ip) {
				t.Errorf("foreign %s should never be touched, found op %s", ip, op)
			}
		}
	}
	if tagged := w.tagged(); len(tagged) != 0 {
		t.Errorf("tagged should be empty after convergence, got %v", tagged)
	}
	for _, d := range desired {
		if !w.isMember(d.IP) {
			t.Errorf("%s should be a Defensia backend member", d.IP)
		}
	}
}

func TestSwitchBackRefusesWhenBanFails(t *testing.T) {
	w := newFakeWorld(t)
	clock := time.Now()
	path := t.TempDir() + "/ban_executor.json"
	m, _ := newMigrateManager(t, &clock, path)

	ip := "203.0.113.10"
	w.seedTemp(map[string]tempEntry{ip: {ttl: time.Hour, comment: "defensia:r", ours: true}})
	w.banIPForErr[ip] = ErrNoBackend // generic failure path too; see TestSwitchBackNoBackend for the dedicated one

	desired := []DesiredBan{{IP: ip, Reason: "r", TTL: time.Hour, ExpiresAt: mustTime(clock, time.Hour)}}
	m.ApplySync(SyncInput{Executor: "csf"})
	m.ApplySync(SyncInput{Executor: "defensia", Bans: desired})
	m.csf.runOnce(context.Background())

	if indexOfOp(w.ops(), "tr:"+ip) != -1 {
		t.Errorf("tr should NOT have been issued when BanIPFor failed, ops=%v", w.ops())
	}
	if !w.isTagged(ip) {
		t.Error("CSF entry should still be present (kept blocking)")
	}
	st := m.csf.status()
	if st.PendingMigration != 1 {
		t.Errorf("PendingMigration = %d, want 1", st.PendingMigration)
	}
}

func TestSwitchBackNoBackend(t *testing.T) {
	w := newFakeWorld(t)
	clock := time.Now()
	path := t.TempDir() + "/ban_executor.json"
	m, _ := newMigrateManager(t, &clock, path)

	var desired []DesiredBan
	entries := map[string]tempEntry{}
	for i := 0; i < 3; i++ {
		ip := testPublicIP(i)
		desired = append(desired, DesiredBan{IP: ip, Reason: "r", TTL: time.Hour, ExpiresAt: mustTime(clock, time.Hour)})
		entries[ip] = tempEntry{ttl: time.Hour, comment: "defensia:r", ours: true}
	}
	w.seedTemp(entries)
	w.banIPForErr["*"] = ErrNoBackend

	m.ApplySync(SyncInput{Executor: "csf"})
	m.ApplySync(SyncInput{Executor: "defensia", Bans: desired})
	m.csf.runOnce(context.Background())

	for _, op := range w.ops() {
		if strings.HasPrefix(op, "tr:") {
			t.Errorf("zero -tr expected, found %s", op)
		}
	}
	st := m.csf.status()
	if st.State != "migrating" || st.Reason != "defensia_backend_unavailable" {
		t.Errorf("status = %+v, want State migrating Reason defensia_backend_unavailable", st)
	}
	if st.PendingMigration != 3 {
		t.Errorf("PendingMigration = %d, want 3 (tagged count)", st.PendingMigration)
	}
}

func TestSwitchBackProtectedIP(t *testing.T) {
	w := newFakeWorld(t)
	clock := time.Now()
	path := t.TempDir() + "/ban_executor.json"
	m, _ := newMigrateManager(t, &clock, path)

	ip := "203.0.113.20"
	w.seedTemp(map[string]tempEntry{ip: {ttl: time.Hour, comment: "defensia:r", ours: true}})
	w.banIPForErr[ip] = ErrProtectedIP

	desired := []DesiredBan{{IP: ip, Reason: "r", TTL: time.Hour, ExpiresAt: mustTime(clock, time.Hour)}}
	m.ApplySync(SyncInput{Executor: "csf"})
	m.ApplySync(SyncInput{Executor: "defensia", Bans: desired})
	m.csf.runOnce(context.Background())

	if indexOfOp(w.ops(), "tr:"+ip) == -1 {
		t.Errorf("tr SHOULD have been issued for a protected IP, ops=%v", w.ops())
	}
	st := m.csf.status()
	if st.PendingMigration != 0 {
		t.Errorf("PendingMigration = %d, want 0 (protected IP is not pending)", st.PendingMigration)
	}
}

func TestSwitchBackGenerationChanged(t *testing.T) {
	w := newFakeWorld(t)
	clock := time.Now()
	path := t.TempDir() + "/ban_executor.json"
	m, _ := newMigrateManager(t, &clock, path)

	ip := "203.0.113.30"
	w.seedTemp(map[string]tempEntry{ip: {ttl: time.Hour, comment: "defensia:r", ours: true}})

	origGen := generationFn
	called := false
	generationFn = func() uint64 {
		if !called {
			called = true
			return 1
		}
		return 2 // bumped between the read-before and the read-after BanIPFor
	}
	t.Cleanup(func() { generationFn = origGen })

	desired := []DesiredBan{{IP: ip, Reason: "r", TTL: time.Hour, ExpiresAt: mustTime(clock, time.Hour)}}
	m.ApplySync(SyncInput{Executor: "csf"})
	m.ApplySync(SyncInput{Executor: "defensia", Bans: desired})
	m.csf.runOnce(context.Background())

	if indexOfOp(w.ops(), "tr:"+ip) != -1 {
		t.Errorf("tr should be skipped this pass when Generation() changed, ops=%v", w.ops())
	}
	st := m.csf.status()
	if st.PendingMigration != 1 {
		t.Errorf("PendingMigration = %d, want 1", st.PendingMigration)
	}
}

func TestEmergencyNoCSFCommands(t *testing.T) {
	w := newFakeWorld(t)
	clock := time.Now()
	path := t.TempDir() + "/ban_executor.json"
	m, _ := newMigrateManager(t, &clock, path)

	origApply := applyBanEntriesFn
	var applied []BanEntry
	applyBanEntriesFn = func(entries []BanEntry) int { applied = append(applied, entries...); return len(entries) }
	t.Cleanup(func() { applyBanEntriesFn = origApply })

	desired := []DesiredBan{{IP: "203.0.113.40", Reason: "r", TTL: time.Hour, ExpiresAt: mustTime(clock, time.Hour)}}
	m.ApplySync(SyncInput{Executor: "csf", Emergency: true, Bans: desired})

	if len(applied) != 1 || applied[0].IP != "203.0.113.40" {
		t.Errorf("applyBanEntriesFn calls = %+v, want the one desired entry", applied)
	}
	if len(w.ops()) != 0 {
		t.Errorf("emergency must issue zero csf commands, got %v", w.ops())
	}
	st := m.Status()
	if st == nil {
		t.Fatal("Status() = nil")
	}
	if st.State != "emergency_off" {
		t.Errorf("State = %q, want emergency_off", st.State)
	}
	if got := loadBanState(path); got.Mode != "defensia" {
		t.Errorf("persisted Mode = %q, want defensia", got.Mode)
	}
}

func TestEmergencyFromCSFPaused(t *testing.T) {
	newFakeWorld(t)
	clock := time.Now()
	path := t.TempDir() + "/ban_executor.json"
	m, _ := newMigrateManager(t, &clock, path)

	origPaused := csfPausedFn
	csfPausedFn = func() bool { return true }
	t.Cleanup(func() { csfPausedFn = origPaused })

	origApply := applyBanEntriesFn
	var applied []BanEntry
	applyBanEntriesFn = func(entries []BanEntry) int { applied = append(applied, entries...); return len(entries) }
	t.Cleanup(func() { applyBanEntriesFn = origApply })

	desired := []DesiredBan{{IP: "203.0.113.41", Reason: "r", TTL: time.Hour, ExpiresAt: mustTime(clock, time.Hour)}}
	m.ApplySync(SyncInput{Executor: "csf", Bans: desired}) // Emergency field false, but csfPausedFn() true

	if len(applied) != 1 {
		t.Errorf("applyBanEntriesFn calls = %+v, want 1", applied)
	}

	origBan := banIPFn
	var banned []string
	banIPFn = func(ip string) error { banned = append(banned, ip); return nil }
	t.Cleanup(func() { banIPFn = origBan })

	if err := m.Ban("203.0.113.42", "x"); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if len(banned) != 1 || banned[0] != "203.0.113.42" {
		t.Errorf("banIPFn calls = %v, want [203.0.113.42] (emergency forces the defensia path)", banned)
	}
}

func TestMigrationWhileCSFUnavailable(t *testing.T) {
	w := newFakeWorld(t)
	clock := time.Now()
	path := t.TempDir() + "/ban_executor.json"
	m, _ := newMigrateManager(t, &clock, path)

	ip := "203.0.113.50"
	w.seedTemp(map[string]tempEntry{ip: {ttl: time.Hour, comment: "defensia:r", ours: true}})
	w.writeConf(map[string]string{"LF_DAEMON": "1", "TESTING": "1"}) // readiness fails: testing_mode

	desired := []DesiredBan{{IP: ip, Reason: "r", TTL: time.Hour, ExpiresAt: mustTime(clock, time.Hour)}}
	m.ApplySync(SyncInput{Executor: "csf"})
	m.ApplySync(SyncInput{Executor: "defensia", Bans: desired})
	m.csf.runOnce(context.Background())

	if indexOfOpPrefix(w.ops(), "banipfor:"+ip+":") == -1 {
		t.Errorf("BanIPFor should still have been called even though CSF is not ready, ops=%v", w.ops())
	}
	if indexOfOp(w.ops(), "tr:"+ip) != -1 {
		t.Errorf("no -tr should be issued while CSF is unavailable, ops=%v", w.ops())
	}
	st := m.csf.status()
	if st.State != "migrating" || st.Reason != "csf_cleanup_pending" {
		t.Errorf("status = %+v, want State migrating Reason csf_cleanup_pending", st)
	}
	if st.PendingMigration != 1 {
		t.Errorf("PendingMigration = %d, want 1", st.PendingMigration)
	}

	// CSF becomes ready again -> the removal happens on the next pass.
	w.writeConf(map[string]string{"LF_DAEMON": "1"})
	m.csf.runOnce(context.Background())
	if indexOfOp(w.ops(), "tr:"+ip) == -1 {
		t.Errorf("tr should be issued once CSF is ready again, ops=%v", w.ops())
	}
}
