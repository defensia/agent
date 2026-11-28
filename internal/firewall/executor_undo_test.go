package firewall

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestUndoRemovesOnlyTagged(t *testing.T) {
	w := newFakeWorld(t)
	clock := time.Now()
	path := t.TempDir() + "/ban_executor.json"
	m, _ := newMigrateManager(t, &clock, path)

	var desired []DesiredBan
	entries := map[string]tempEntry{}
	for i := 0; i < 20; i++ {
		ip := testPublicIP(i)
		ttl := time.Hour
		desired = append(desired, DesiredBan{IP: ip, Reason: "r", TTL: ttl, ExpiresAt: mustTime(clock, ttl)})
		entries[ip] = tempEntry{ttl: time.Hour, comment: "defensia:r", ours: true}
	}
	entries["203.0.113.250"] = tempEntry{ttl: time.Hour, comment: "manual", ours: false}
	entries["203.0.113.251"] = tempEntry{ttl: time.Hour, comment: "lfd: (sshd) Failed SSH login", ours: false}
	entries["203.0.113.252"] = tempEntry{ttl: time.Hour, comment: "", ours: false}
	w.seedTemp(entries)

	m.csf.requestUndo("T1", desired)
	m.csf.runOnce(context.Background())

	if tagged := w.tagged(); len(tagged) != 0 {
		t.Errorf("tagged should be 0 after undo, got %v", tagged)
	}
	for _, ip := range []string{"203.0.113.250", "203.0.113.251", "203.0.113.252"} {
		if !containsStr(w.foreign(), ip) {
			t.Errorf("foreign entry %s should be intact", ip)
		}
	}
	for _, op := range w.ops() {
		if strings.HasPrefix(op, "-tf") || op == "tf" {
			t.Errorf("csf -tf must never be issued, found op %s", op)
		}
	}
	for _, d := range desired {
		idxBan := indexOfOpPrefix(w.ops(), "banipfor:"+d.IP+":")
		idxTr := indexOfOp(w.ops(), "tr:"+d.IP)
		if idxBan == -1 || idxTr == -1 || idxBan > idxTr {
			t.Errorf("%s: want banipfor before tr, ops=%v", d.IP, w.ops())
		}
	}
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func TestUndoIdempotentByToken(t *testing.T) {
	w := newFakeWorld(t)
	clock := time.Now()
	path := t.TempDir() + "/ban_executor.json"
	m, rec := newMigrateManager(t, &clock, path)

	entries := map[string]tempEntry{}
	var desired []DesiredBan
	for i := 0; i < 5; i++ {
		ip := testPublicIP(i)
		entries[ip] = tempEntry{ttl: time.Hour, comment: "defensia:r", ours: true}
		desired = append(desired, DesiredBan{IP: ip, Reason: "r", TTL: time.Hour, ExpiresAt: mustTime(clock, time.Hour)})
	}
	w.seedTemp(entries)

	m.ApplySync(SyncInput{Executor: "defensia", UndoToken: "T1", Bans: desired})
	m.csf.runOnce(context.Background())

	st := m.csf.status()
	if st.State != "ok" {
		t.Fatalf("after convergence: status = %+v, want State ok", st)
	}

	before := len(w.ops())
	m.ApplySync(SyncInput{Executor: "defensia", UndoToken: "T1", Bans: desired})
	m.csf.runOnce(context.Background())
	if len(w.ops()) != before {
		t.Errorf("same token again: expected zero new ops, ops went from %d to %d", before, len(w.ops()))
	}

	got := loadBanState(path)
	if got.LastUndoToken != "T1" || got.LastUndoRemoved != 5 {
		t.Errorf("persisted state = %+v, want LastUndoToken T1 LastUndoRemoved 5", got)
	}

	var completed []ExecutorEvent
	rec.mu.Lock()
	for _, ev := range rec.events {
		if ev.Type == "csf_undo_completed" {
			completed = append(completed, ev)
		}
	}
	rec.mu.Unlock()
	if len(completed) != 1 {
		t.Fatalf("csf_undo_completed emitted %d times, want 1", len(completed))
	}

	// New token re-runs (0 removed if nothing tagged).
	m.ApplySync(SyncInput{Executor: "defensia", UndoToken: "T2", Bans: desired})
	m.csf.runOnce(context.Background())
	if got := loadBanState(path); got.LastUndoToken != "T2" || got.LastUndoRemoved != 0 {
		t.Errorf("after T2: persisted state = %+v, want LastUndoToken T2 LastUndoRemoved 0", got)
	}
}

// TestManagerStatusSurfacesLastUndo is the regression test for the
// lab-measured gap (phase 18-10, alma9-csf-orig): BanManager.Status() must
// reflect LastUndoToken/LastUndoRemoved once undoCompleted has persisted
// them, even though the CSF executor's own ExecutorStatus (what
// csf.status() returns) never sets those two fields itself — only
// BanManager.undoCompleted writes them, into m.state. Every pre-existing
// undo test only ever checked loadBanState(path) (the persisted file)
// directly, never BanManager.Status() (what the panel-facing heartbeat
// actually reads) — which is exactly how this went unnoticed until
// TestLabBanSyncUndoAll's own Status()-based poll never converged despite
// the undo (and its persisted state, and its emitted event) all being
// correct underneath.
func TestManagerStatusSurfacesLastUndo(t *testing.T) {
	w := newFakeWorld(t)
	clock := time.Now()
	path := t.TempDir() + "/ban_executor.json"
	m, _ := newMigrateManager(t, &clock, path)

	entries := map[string]tempEntry{}
	var desired []DesiredBan
	for i := 0; i < 5; i++ {
		ip := testPublicIP(i)
		entries[ip] = tempEntry{ttl: time.Hour, comment: "defensia:r", ours: true}
		desired = append(desired, DesiredBan{IP: ip, Reason: "r", TTL: time.Hour, ExpiresAt: mustTime(clock, time.Hour)})
	}
	w.seedTemp(entries)

	m.ApplySync(SyncInput{Executor: "defensia", UndoToken: "T1", Bans: desired})
	m.csf.runOnce(context.Background())

	if st := m.Status(); st.LastUndoToken != "T1" || st.LastUndoRemoved != 5 {
		t.Errorf("Status() = %+v, want LastUndoToken T1 LastUndoRemoved 5", st)
	}
}

func TestUndoPersistsOnlyWhenClean(t *testing.T) {
	w := newFakeWorld(t)
	clock := time.Now()
	path := t.TempDir() + "/ban_executor.json"
	m, rec := newMigrateManager(t, &clock, path)

	entries := map[string]tempEntry{}
	var desired []DesiredBan
	failing := map[string]bool{}
	for i := 0; i < 20; i++ {
		ip := testPublicIP(i)
		entries[ip] = tempEntry{ttl: time.Hour, comment: "defensia:r", ours: true}
		desired = append(desired, DesiredBan{IP: ip, Reason: "r", TTL: time.Hour, ExpiresAt: mustTime(clock, time.Hour)})
		if i < 2 {
			failing[ip] = true
		}
	}
	w.seedTemp(entries)

	// Force -tr to fail (unexpected) for the first 2 IPs, once.
	origRun := csfRun
	csfRun = func(ctx context.Context, bin string, args ...string) ([]byte, int, error) {
		if len(args) > 1 && args[0] == "-tr" && failing[args[1]] {
			delete(failing, args[1]) // only fails once, succeeds on retry
			return []byte("completely unrecognised garbage"), 0, nil
		}
		return w.csfRunFake(ctx, bin, args...)
	}
	t.Cleanup(func() { csfRun = origRun })

	m.csf.requestUndo("T1", desired)
	m.csf.runOnce(context.Background())

	if got := loadBanState(path); got.LastUndoToken == "T1" {
		t.Fatalf("token must NOT be persisted while 2 IPs are still stuck, got %+v", got)
	}

	m.csf.runOnce(context.Background()) // retry: now clean
	got := loadBanState(path)
	if got.LastUndoToken != "T1" || got.LastUndoRemoved != 20 {
		t.Errorf("persisted state = %+v, want LastUndoToken T1 LastUndoRemoved 20", got)
	}

	var completed []ExecutorEvent
	rec.mu.Lock()
	for _, ev := range rec.events {
		if ev.Type == "csf_undo_completed" {
			completed = append(completed, ev)
		}
	}
	rec.mu.Unlock()
	if len(completed) != 1 {
		t.Fatalf("csf_undo_completed emitted %d times, want exactly 1", len(completed))
	}
	if completed[0].Details["token"] != "T1" || completed[0].Details["removed"] != "20" || completed[0].Details["remaining"] != "0" {
		t.Errorf("event details = %+v, want token:T1 removed:20 remaining:0", completed[0].Details)
	}
}

func TestUndoConflictsReported(t *testing.T) {
	w := newFakeWorld(t)
	clock := time.Now()
	path := t.TempDir() + "/ban_executor.json"
	m, rec := newMigrateManager(t, &clock, path)

	ip := "203.0.113.60"
	w.seedTemp(map[string]tempEntry{ip: {ttl: time.Hour, comment: "defensia:r", ours: true}})
	w.setExtraForeign(ip, true) // "an IP with both an Ours and a foreign entry" — never resolves

	desired := []DesiredBan{{IP: ip, Reason: "r", TTL: time.Hour, ExpiresAt: mustTime(clock, time.Hour)}}
	m.csf.requestUndo("T1", desired)

	for i := 0; i < 3; i++ {
		m.csf.runOnce(context.Background())
	}

	got := loadBanState(path)
	if got.LastUndoToken != "T1" {
		t.Fatalf("after 3 attempts the token must be persisted even with a conflict, got %+v", got)
	}

	var completed []ExecutorEvent
	rec.mu.Lock()
	for _, ev := range rec.events {
		if ev.Type == "csf_undo_completed" {
			completed = append(completed, ev)
		}
	}
	rec.mu.Unlock()
	if len(completed) == 0 {
		t.Fatal("csf_undo_completed never emitted")
	}
	last := completed[len(completed)-1]
	if last.Details["remaining"] != "1" {
		t.Errorf("event remaining = %q, want 1 (unresolved conflict)", last.Details["remaining"])
	}
}

// TestUndoPassSelfWakesWhenNotDone is the regression test for the
// lab-measured convergence stall (phase 18-10, alma9-csf-orig): a pass that
// leaves work pending (oursLeft > 0, attempts still under undoAttemptsMax)
// must self-wake so the next attempt runs promptly instead of waiting for
// the next external ApplySync or the 60s ticker — TestLabBanSyncUndoAll's
// own LastUndoToken/LastUndoRemoved poll missed its 30s window without
// this, since nothing else woke the worker again.
func TestUndoPassSelfWakesWhenNotDone(t *testing.T) {
	w := newFakeWorld(t)
	clock := time.Now()
	path := t.TempDir() + "/ban_executor.json"
	m, _ := newMigrateManager(t, &clock, path)

	ip := "203.0.113.61"
	w.seedTemp(map[string]tempEntry{ip: {ttl: time.Hour, comment: "defensia:r", ours: true}})
	w.setExtraForeign(ip, true) // never resolves within this test — forces "not done" on every pass

	desired := []DesiredBan{{IP: ip, Reason: "r", TTL: time.Hour, ExpiresAt: mustTime(clock, time.Hour)}}
	m.csf.requestUndo("T1", desired)

	// requestUndo's own wakeUp() already queued one signal; drain it so the
	// assertion below only reflects runOnce's OWN self-wake, not that one.
	select {
	case <-m.csf.wake:
	default:
	}

	m.csf.runOnce(context.Background())

	select {
	case <-m.csf.wake:
	default:
		t.Fatal("runOnce left the undo pass not done (unresolved conflict, attempts < max) but did not self-wake")
	}
}

func TestUndoNoBackend(t *testing.T) {
	w := newFakeWorld(t)
	clock := time.Now()
	path := t.TempDir() + "/ban_executor.json"
	m, _ := newMigrateManager(t, &clock, path)

	entries := map[string]tempEntry{
		"203.0.113.70": {ttl: time.Hour, comment: "defensia:r", ours: true},
		"203.0.113.71": {ttl: time.Hour, comment: "defensia:old", ours: true}, // non-desired, cleaned regardless
	}
	w.seedTemp(entries)
	w.banIPForErr["*"] = ErrNoBackend

	desired := []DesiredBan{{IP: "203.0.113.70", Reason: "r", TTL: time.Hour, ExpiresAt: mustTime(clock, time.Hour)}}
	m.csf.requestUndo("T1", desired)
	m.csf.runOnce(context.Background())

	if !w.isTagged("203.0.113.70") {
		t.Error("desired IP's CSF entry should be kept (still blocked) when BanIPFor fails")
	}
	if w.isTagged("203.0.113.71") {
		t.Error("non-desired tagged entry should still be removed")
	}
	if got := loadBanState(path); got.LastUndoToken == "T1" {
		t.Error("token must not be persisted while a desired IP is still stuck")
	}
	if got := m.csf.status().Reason; got != "undo_waiting_for_defensia_backend" {
		t.Errorf("Reason = %q, want undo_waiting_for_defensia_backend", got)
	}
}

func TestUndoWhenDegraded(t *testing.T) {
	w := newFakeWorld(t)
	clock := time.Now()
	path := t.TempDir() + "/ban_executor.json"
	m, _ := newMigrateManager(t, &clock, path)
	m.csf.breaker.degradeNow("unknown_line")

	ip := "203.0.113.80"
	w.seedTemp(map[string]tempEntry{ip: {ttl: time.Hour, comment: "defensia:r", ours: true}})

	desired := []DesiredBan{{IP: ip, Reason: "r", TTL: time.Hour, ExpiresAt: mustTime(clock, time.Hour)}}
	m.csf.requestUndo("T1", desired)
	m.csf.runOnce(context.Background())

	if got := m.csf.status().Reason; got != "undo_waiting_for_csf" {
		t.Errorf("Reason = %q, want undo_waiting_for_csf", got)
	}
	if indexOfOp(w.ops(), "tr:"+ip) != -1 {
		t.Errorf("no -tr should be issued while degraded, ops=%v", w.ops())
	}
}

func TestUndoAppliesInDefensiaMode(t *testing.T) {
	w := newFakeWorld(t)
	clock := time.Now()
	path := t.TempDir() + "/ban_executor.json"
	m, _ := newMigrateManager(t, &clock, path)

	ip := "203.0.113.90"
	w.seedTemp(map[string]tempEntry{ip: {ttl: time.Hour, comment: "defensia:r", ours: true}})

	// Executor already "defensia" (e.g. leftover from an earlier emergency) —
	// never switched to csf in this test at all.
	desired := []DesiredBan{{IP: ip, Reason: "r", TTL: time.Hour, ExpiresAt: mustTime(clock, time.Hour)}}
	m.csf.requestUndo("T1", desired)
	m.csf.runOnce(context.Background())

	if tagged := w.tagged(); len(tagged) != 0 {
		t.Errorf("tagged should be 0 after undo even in defensia mode, got %v", tagged)
	}
	if !w.isMember(ip) {
		t.Error("desired IP should have been re-added to the Defensia backend")
	}
}

func TestUndoInEmergency(t *testing.T) {
	w := newFakeWorld(t)
	clock := time.Now()
	path := t.TempDir() + "/ban_executor.json"
	m, _ := newMigrateManager(t, &clock, path)

	ip := "203.0.113.91"
	w.seedTemp(map[string]tempEntry{ip: {ttl: time.Hour, comment: "defensia:r", ours: true}})

	desired := []DesiredBan{{IP: ip, Reason: "r", TTL: time.Hour, ExpiresAt: mustTime(clock, time.Hour)}}
	m.ApplySync(SyncInput{Executor: "defensia", Emergency: true, UndoToken: "T1", Bans: desired})

	if len(w.ops()) != 0 {
		t.Errorf("emergency must issue zero csf commands even with an undo token, got %v", w.ops())
	}
	if got := m.Status().Reason; got != "undo_blocked_emergency" {
		t.Errorf("Status.Reason = %q, want undo_blocked_emergency", got)
	}
}
