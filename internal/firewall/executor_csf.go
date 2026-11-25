package firewall

import (
	"context"
	"log"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// csfExecutor is the rate-limited worker that reconciles the panel's desired
// ban list against CSF's own temp-ban file (csf.tempban), applying the pure
// plan from planCSFPass without ever blocking its callers (ApplySync, Ban,
// Unban, Status all just swap state and signal; the worker goroutine does
// every exec).
type csfExecutor struct {
	mu       sync.Mutex
	desired  SyncInput
	local    map[string]localBan
	backoff  map[string]time.Time
	prevOurs map[string]TempBanEntry
	vanish   map[string]int

	wake chan struct{} // cap 1

	cli           *csfCLI
	cliErr        error
	denyinChainOK func(ctx context.Context) bool
	// guard is a test seam; production (nil) uses the real package guardCheck.
	guard func(ip string) (bool, string)

	emit func(ExecutorEvent)
	now  func() time.Time
	// sleep is the rate-limit delay; tests replace it with a no-op or a
	// fake-clock advancer so TestWorkerRateLimit can observe spacing without
	// a real-time test taking seconds to run.
	sleep func(time.Duration)

	statusPtr atomic.Pointer[ExecutorStatus]
	applied   atomic.Int64

	keepMu sync.Mutex
	keep   map[string]bool

	// migrateTarget == "defensia" puts the worker in cleanup-migration mode
	// (executor_migrate.go) instead of the normal CSF reconcile pass; "" (or
	// "csf") means normal operation. onMigrationDone is called (by
	// BanManager, via Start) whenever a migration in either direction
	// finishes converging, so the persisted ban_executor.json state can be
	// updated without the worker needing to know about persistence itself.
	migrateTarget   string
	migrateAll      bool
	onMigrationDone func()
}

// newCSFExecutor constructs a worker. Resolving the CSF binary happens once,
// here; a missing binary is not fatal — it is reported as a permanent
// "unavailable/csf_missing" status instead of crashing the agent.
func newCSFExecutor(opts ManagerOptions) *csfExecutor {
	e := &csfExecutor{
		wake:          make(chan struct{}, 1),
		now:           opts.Now,
		sleep:         time.Sleep,
		emit:          opts.Emit,
		local:         map[string]localBan{},
		backoff:       map[string]time.Time{},
		prevOurs:      map[string]TempBanEntry{},
		vanish:        map[string]int{},
		keep:          map[string]bool{},
		denyinChainOK: defaultDenyinChainOK,
	}
	if e.now == nil {
		e.now = time.Now
	}
	if e.emit == nil {
		e.emit = func(ExecutorEvent) {}
	}
	e.cli, e.cliErr = newCSFCLI()
	if e.cliErr != nil {
		e.statusPtr.Store(&ExecutorStatus{
			Mode: "csf", EffectiveMode: "defensia", State: "unavailable", Reason: "csf_missing",
			CSFLimit: -1, UpdatedAt: e.now().UTC().Format(time.RFC3339),
		})
	}
	return e
}

func defaultDenyinChainOK(ctx context.Context) bool {
	_, err := run(ctx, 5*time.Second, "iptables", "-S", "DENYIN")
	return err == nil
}

// setDesired swaps the panel's desired state and wakes the worker. Never
// blocks: the channel send is a non-blocking best-effort signal (cap 1 — a
// second wake while one is already pending is a no-op, the pending wake will
// pick up the latest desired state anyway since setDesired already stored it).
func (e *csfExecutor) setDesired(in SyncInput) {
	e.mu.Lock()
	e.desired = in
	e.mu.Unlock()
	e.wakeUp()
}

// setMigrateTarget switches the worker between normal CSF-reconcile mode
// ("" / "csf") and defensia-migration-cleanup mode ("defensia"). When
// switching to "defensia", bans is the panel's current desired list (the
// worker's own e.desired.Bans is not otherwise updated while migrating,
// since setDesired is only called from the "csf" ApplySync branch).
func (e *csfExecutor) setMigrateTarget(target string, all bool, bans []DesiredBan) {
	e.mu.Lock()
	e.migrateTarget = target
	e.migrateAll = all
	if target == "defensia" {
		e.desired.Bans = bans
	}
	e.mu.Unlock()
	e.wakeUp()
}

func (e *csfExecutor) localBanIP(ip, reason string) {
	e.mu.Lock()
	if e.local == nil {
		e.local = map[string]localBan{}
	}
	e.local[ip] = localBan{Reason: reason, AddedAt: e.now()}
	e.mu.Unlock()
	e.wakeUp()
}

func (e *csfExecutor) localUnbanIP(ip string) {
	e.mu.Lock()
	delete(e.local, ip)
	e.mu.Unlock()
	e.wakeUp()
}

func (e *csfExecutor) wakeUp() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

func (e *csfExecutor) ipsetKeep() map[string]bool {
	e.keepMu.Lock()
	defer e.keepMu.Unlock()
	out := make(map[string]bool, len(e.keep))
	for k, v := range e.keep {
		out[k] = v
	}
	return out
}

func (e *csfExecutor) appliedCount() int { return int(e.applied.Load()) }

func (e *csfExecutor) status() *ExecutorStatus {
	if s := e.statusPtr.Load(); s != nil {
		return s
	}
	return &ExecutorStatus{Mode: "csf", EffectiveMode: "defensia", State: "unavailable", Reason: "starting", CSFLimit: -1, UpdatedAt: e.now().UTC().Format(time.RFC3339)}
}

// run loops forever (until ctx is cancelled), performing one reconcile pass
// whenever woken (by setDesired/localBanIP/localUnbanIP) or at least once a
// minute, so a stuck confirm/eviction state is always re-evaluated.
func (e *csfExecutor) run(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.wake:
		case <-ticker.C:
		}
		e.runOnce(ctx)
	}
}

// runOnce performs exactly one reconcile pass: read state, plan, execute
// ops (rate-limited), confirm + make-before-break, update status. Every
// return path before "execute ops" performs zero CSF writes.
func (e *csfExecutor) runOnce(ctx context.Context) {
	e.mu.Lock()
	desired := e.desired
	local := cloneLocal(e.local)
	backoff := cloneBackoff(e.backoff)
	migrateTarget := e.migrateTarget
	migrateAll := e.migrateAll
	e.mu.Unlock()

	if e.cli == nil {
		e.statusPtr.Store(&ExecutorStatus{
			Mode: "csf", EffectiveMode: "defensia", State: "unavailable", Reason: "csf_missing",
			CSFLimit: -1, UpdatedAt: e.now().UTC().Format(time.RFC3339),
		})
		return
	}

	if migrateTarget == "defensia" {
		e.runMigratePass(ctx, desired, migrateAll)
		return
	}

	conf, err := readCSFBanConf()
	if err != nil {
		e.statusPtr.Store(&ExecutorStatus{
			Mode: "csf", EffectiveMode: "defensia", State: "unavailable", Reason: "conf_unreadable",
			CSFLimit: -1, UpdatedAt: e.now().UTC().Format(time.RFC3339),
		})
		return
	}

	temp, err := readTempBans()
	if err != nil {
		// ErrTempBanBusy (or any other read failure): skip this pass with
		// zero writes rather than risk acting on a torn/empty read.
		return
	}

	if ready, reason := e.readiness(ctx, conf); !ready {
		e.statusPtr.Store(&ExecutorStatus{
			Mode: "csf", EffectiveMode: "defensia", State: "unavailable", Reason: reason,
			CSFLimit: conf.TempLimit, CSFTempbanTotal: len(temp.Entries),
			UpdatedAt: e.now().UTC().Format(time.RFC3339),
		})
		return
	}

	guardFn := e.guard
	if guardFn == nil {
		guardFn = guardCheck
	}
	plan := planCSFPass(passInput{
		Now: e.now(), Desired: desired.Bans, Local: local, Temp: temp, Conf: conf,
		Backoff: backoff, MonitorMode: desired.MonitorMode, Guard: guardFn,
	})

	applied := e.executeOps(ctx, plan.Ops)
	e.applied.Store(int64(applied))

	temp2, err2 := readTempBans()
	if err2 != nil {
		temp2 = temp
	}

	oursNow := map[string]TempBanEntry{}
	for _, en := range temp2.Entries {
		if en.Ours {
			oursNow[en.IP] = en
		}
	}

	e.confirmAndHandOver(desired, oursNow)

	anyEvicted := e.detectVanished(desired, oursNow, conf.TempLimit, len(temp2.Entries))

	state := "ok"
	if anyEvicted {
		state = "capacity_exhausted"
	}
	st := &ExecutorStatus{
		Mode: "csf", EffectiveMode: "csf", State: state,
		CSFReady: true, CSFLimit: conf.TempLimit, CSFTempbanTotal: len(temp2.Entries),
		DefensiaInCSF: len(oursNow), Deferred: plan.Deferred, DeferredIPv6: plan.DeferredIPv6,
		SkippedProtected: len(plan.Skipped),
		UpdatedAt:        e.now().UTC().Format(time.RFC3339),
	}
	e.statusPtr.Store(st)

	if plan.Deferred > 0 {
		e.emitEvent("csf_ban_deferred", map[string]string{
			"reason": "capacity", "count": strconv.Itoa(plan.Deferred), "limit": strconv.Itoa(conf.TempLimit),
		})
	}
}

// executeOps runs plan ops in order, spaced by csfMinInterval, stopping the
// pass early on a ResultUnexpected outcome (plan 08 wires the breaker; this
// plan just refuses to keep hammering CSF after one unexplained result).
func (e *csfExecutor) executeOps(ctx context.Context, ops []op) int {
	applied := 0
	for i, o := range ops {
		opCtx, cancel := context.WithTimeout(ctx, csfCmdTimeout)
		var outcome CSFOutcome
		switch o.Kind {
		case "add":
			outcome, _ = e.cli.TempDeny(opCtx, o.IP, o.TTL, o.Reason)
		case "remove":
			outcome, _ = e.cli.TempRemove(opCtx, o.IP)
		}
		cancel()

		switch outcome.Result {
		case ResultOK, ResultBenign:
			applied++
			if o.Kind == "add" {
				e.clearBackoff(o.IP)
			}
		case ResultRefused:
			e.setBackoff(o.IP, time.Hour)
			e.emitEvent("csf_ban_deferred", map[string]string{"ip": o.IP, "reason": "refused"})
		case ResultUnexpected:
			if i < len(ops)-1 {
				log.Printf("[firewall] csf executor: stopping pass early after unexpected result for %s: %s", o.IP, outcome.Reason)
			}
			return applied
		}

		if i < len(ops)-1 {
			e.sleep(csfMinInterval)
		}
	}
	return applied
}

// confirmAndHandOver is the make-before-break step: a panel ban is removed
// from the Defensia backend only once it is confirmed present in
// csf.tempban — never before, and never for threat-feed IPs (those stay on
// the Defensia backend regardless of what CSF additionally does with them).
func (e *csfExecutor) confirmAndHandOver(desired SyncInput, oursNow map[string]TempBanEntry) {
	members := banMembersFn()
	threatFeed := desired.ThreatFeedIPs

	keep := map[string]bool{}
	for _, b := range desired.Bans {
		if _, confirmed := oursNow[b.IP]; confirmed {
			if threatFeed[b.IP] {
				keep[b.IP] = true
				continue
			}
			if len(members) > 0 && members[b.IP] {
				if err := unbanIPFn(b.IP); err != nil {
					log.Printf("[firewall] csf executor: could not remove %s from the Defensia backend after CSF confirmation: %v", b.IP, err)
				}
			}
			continue
		}
		// Not yet confirmed in CSF: if it is still on the Defensia backend,
		// it must stay there (keep protecting it) until CSF catches up.
		if len(members) > 0 && members[b.IP] {
			keep[b.IP] = true
		}
	}

	e.keepMu.Lock()
	e.keep = keep
	e.keepMu.Unlock()

	// A defensia->csf switch has fully converged once nothing is left to
	// protect on the Defensia backend (every desired IP is either confirmed
	// in CSF or was never there to begin with) — tell BanManager so it can
	// persist Migrating:false. Harmless to call repeatedly in steady state.
	if len(keep) == 0 && e.onMigrationDone != nil {
		e.onMigrationDone()
	}
}

// detectVanished implements the two-consecutive-reads eviction/external-
// removal rule: an IP that was "ours" last pass, is desired, has not
// reached its own ExpiresAt yet, but is absent from this pass's read, is
// only classified (not just a torn read) once that absence is observed on a
// second consecutive pass.
func (e *csfExecutor) detectVanished(desired SyncInput, oursNow map[string]TempBanEntry, limit, total int) bool {
	e.mu.Lock()
	prev := e.prevOurs
	e.mu.Unlock()

	desiredByIP := map[string]bool{}
	for _, b := range desired.Bans {
		desiredByIP[b.IP] = true
	}

	// newPrev starts as this pass's confirmed state; an IP on its first
	// (not-yet-confirmed) missing observation is re-inserted below so the
	// NEXT pass's "prev" still remembers it — otherwise a single miss would
	// erase all memory of it and the two-consecutive-reads rule could never
	// reach its second observation.
	newPrev := cloneOurs(oursNow)
	anyEvicted := false

	for ip, entry := range prev {
		if !desiredByIP[ip] {
			continue
		}
		if _, stillThere := oursNow[ip]; stillThere {
			e.mu.Lock()
			delete(e.vanish, ip)
			e.mu.Unlock()
			continue
		}
		if !e.now().Before(entry.ExpiresAt) {
			continue // natural expiry, not a removal
		}

		e.mu.Lock()
		e.vanish[ip]++
		count := e.vanish[ip]
		e.mu.Unlock()
		if count < 2 {
			newPrev[ip] = entry
			continue
		}

		e.mu.Lock()
		delete(e.vanish, ip)
		e.mu.Unlock()
		e.setBackoff(ip, 10*time.Minute)

		reason := "removed_externally"
		if limit > 0 && total >= limit-1 {
			reason = "evicted"
			anyEvicted = true
		}
		e.emitEvent("csf_ban_deferred", map[string]string{"ip": ip, "reason": reason})
	}

	e.mu.Lock()
	e.prevOurs = newPrev
	e.mu.Unlock()
	return anyEvicted
}

func (e *csfExecutor) readiness(ctx context.Context, conf csfBanConf) (bool, string) {
	if conf.Testing {
		return false, "testing_mode"
	}
	if conf.Found["LF_DAEMON"] && !conf.LFDaemon {
		return false, "lf_daemon_off"
	}
	if e.denyinChainOK != nil {
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		ok := e.denyinChainOK(rctx)
		cancel()
		if !ok {
			return false, "denyin_missing"
		}
	}
	return true, ""
}

func (e *csfExecutor) setBackoff(ip string, d time.Duration) {
	e.mu.Lock()
	if e.backoff == nil {
		e.backoff = map[string]time.Time{}
	}
	e.backoff[ip] = e.now().Add(d)
	e.mu.Unlock()
}

func (e *csfExecutor) clearBackoff(ip string) {
	e.mu.Lock()
	delete(e.backoff, ip)
	e.mu.Unlock()
}

func (e *csfExecutor) emitEvent(t string, details map[string]string) {
	emit := e.emit
	if emit == nil {
		return
	}
	go emit(ExecutorEvent{Type: t, Severity: "info", Details: details})
}

func cloneLocal(m map[string]localBan) map[string]localBan {
	out := make(map[string]localBan, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func cloneBackoff(m map[string]time.Time) map[string]time.Time {
	out := make(map[string]time.Time, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func cloneOurs(m map[string]TempBanEntry) map[string]TempBanEntry {
	out := make(map[string]TempBanEntry, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
