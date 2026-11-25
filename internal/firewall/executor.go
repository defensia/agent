package firewall

import (
	"context"
	"log"
	"strconv"
	"sync"
	"time"
)

// DesiredBan is one panel-driven ban the executor must enforce.
type DesiredBan struct {
	IP       string
	Reason   string
	BanCount int
	PanelID  int64
	// ExpiresAt nil means permanent; otherwise it drives the CSF TTL.
	ExpiresAt *time.Time
	// TTL is the Phase 17 kernel TTL (banTTL(expires_at) computed by the
	// caller). Used only on the defensia path — never for CSF (csfTTLFor
	// derives the CSF TTL from ExpiresAt directly).
	TTL time.Duration
}

// SyncInput is one ApplySync call's worth of panel state.
type SyncInput struct {
	Executor      string // "defensia" | "csf"; "" = "defensia"
	Emergency     bool
	UndoToken     string
	Bans          []DesiredBan
	ThreatFeedIPs map[string]bool
	ActiveRuleIPs map[string]bool
	MonitorMode   bool
}

// SyncResult is what ApplySync reports back to the caller (main.go logging).
type SyncResult struct{ Applied, Cleaned int }

// ExecutorStatus is the ban-executor half of the heartbeat payload (plan 03's
// contract; sanitised to the wire shape by plan 09).
type ExecutorStatus struct {
	Mode             string `json:"mode"`
	EffectiveMode    string `json:"effective_mode"`
	State            string `json:"state"`
	Reason           string `json:"reason"`
	CSFReady         bool   `json:"csf_ready"`
	CSFLimit         int    `json:"csf_limit"` // -1 = unknown
	CSFTempbanTotal  int    `json:"csf_tempban_total"`
	DefensiaInCSF    int    `json:"defensia_in_csf"`
	Deferred         int    `json:"deferred"`
	DeferredIPv6     int    `json:"deferred_ipv6"`
	PendingMigration int    `json:"pending_migration"`
	SkippedProtected int    `json:"skipped_protected"`
	LastUndoToken    string `json:"last_undo_token"`
	LastUndoRemoved  int    `json:"last_undo_removed"`
	UpdatedAt        string `json:"updated_at"`
}

// ExecutorEvent is one event the manager/worker wants plan 09 to emit to the
// panel (ban_skipped_protected, csf_ban_deferred, csf_executor_switched, ...).
type ExecutorEvent struct {
	Type, Severity string
	Details        map[string]string
}

// ManagerOptions configures a BanManager.
type ManagerOptions struct {
	StatePath string
	Emit      func(ExecutorEvent)
	Now       func() time.Time
}

// BanManager is the single entry point main.go (plan 09) uses for every ban
// decision: it dispatches to Phase 17's existing defensia code path
// (unchanged behaviour) or to the CSF reconcile worker, depending on the
// panel's configured executor. It never calls Ensure/Reselect and never
// inspects Mode() — that stays Phase 17's job in main.go.
type BanManager struct {
	mu                sync.Mutex
	opts              ManagerOptions
	statePath         string
	state             banState
	csf               *csfExecutor
	unknownExecLogged bool
	lastMode          string // effective executor currently in force ("defensia" | "csf")
	emergency         bool
	// undoBlockedByEmergency is true for the duration of an emergency during
	// which the panel has requested an undo (a new UndoToken) that cannot
	// run yet — surfaced via Status() as a distinct reason from the generic
	// emergency_off, so the customer knows the undo is queued, not ignored.
	undoBlockedByEmergency bool
}

// NewBanManager constructs a BanManager, loading any persisted executor
// state from opts.StatePath (or the default banStatePath) so Ban/Unban use
// the right path even before the first ApplySync call after a restart.
func NewBanManager(opts ManagerOptions) *BanManager {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Emit == nil {
		opts.Emit = func(ExecutorEvent) {}
	}
	path := opts.StatePath
	if path == "" {
		path = banStatePath
	}
	state := loadBanState(path)
	mode := state.Mode
	if mode == "" {
		mode = "defensia"
	}
	return &BanManager{opts: opts, statePath: path, state: state, lastMode: mode}
}

// Start lazily brings up the CSF reconcile worker, only when HasCSF() is
// true on this host. Safe to call more than once (idempotent).
func (m *BanManager) Start(ctx context.Context) {
	m.mu.Lock()
	if m.csf != nil {
		m.mu.Unlock()
		return
	}
	if !guardHasCSF() {
		m.mu.Unlock()
		return
	}
	csf := newCSFExecutor(m.opts)
	csf.onMigrationDone = m.migrationDone
	csf.onDegradedChange = m.degradedChanged
	csf.onUndoComplete = m.undoCompleted
	degraded, degradedReason := m.state.Degraded, m.state.DegradedReason
	m.csf = csf
	m.mu.Unlock()

	// checkVersionOnce (via persistDegraded) and run's own passes call back
	// into m.degradedChanged/migrationDone/undoCompleted, each of which
	// re-locks m.mu — so m.mu MUST be released before calling either, or a
	// single goroutine deadlocks on its own non-reentrant mutex (caught live
	// in the lab: TestLabBanSyncFakeBinary/garbage, an unrecognised `csf -v`
	// answer, phase 18-10).
	if degraded {
		// Resume degraded across a restart — recovery still requires fresh
		// evidence (csfRecoverAfter consecutive good probes), never time
		// alone, so simply being the first pass of a new process is not by
		// itself grounds to come back "ok".
		csf.breaker.degradeNow(degradedReason)
	} else {
		csf.checkVersionOnce(ctx)
	}
	go csf.run(ctx)
}

// degradedChanged persists the breaker's degraded/not-degraded state.
// Idempotent, like migrationDone — safe to call on every pass.
func (m *BanManager) degradedChanged(degraded bool, reason string) {
	m.mu.Lock()
	m.state.Degraded = degraded
	m.state.DegradedReason = reason
	m.state.UpdatedAt = m.opts.Now().UTC().Format(time.RFC3339)
	s := m.state
	path := m.statePath
	m.mu.Unlock()

	if err := saveBanState(path, s); err != nil {
		log.Printf("[firewall] could not persist ban executor state: %v", err)
	}
}

// undoCompleted persists LastUndoToken/LastUndoRemoved and emits
// csf_undo_completed — called by the csfExecutor once an undo-all pass
// either fully converges (remaining == 0) or exhausts its retry budget on
// an unresolved conflict (remaining > 0, reported as-is).
func (m *BanManager) undoCompleted(token string, removed, remaining int) {
	m.mu.Lock()
	m.state.LastUndoToken = token
	m.state.LastUndoRemoved = removed
	m.state.UpdatedAt = m.opts.Now().UTC().Format(time.RFC3339)
	s := m.state
	path := m.statePath
	m.mu.Unlock()

	if err := saveBanState(path, s); err != nil {
		log.Printf("[firewall] could not persist ban executor state: %v", err)
	}

	m.opts.Emit(ExecutorEvent{
		Type: "csf_undo_completed", Severity: "info",
		Details: map[string]string{
			"token": token, "removed": strconv.Itoa(removed), "remaining": strconv.Itoa(remaining),
		},
	})
}

// migrationDone persists Migrating:false — called by the csfExecutor (in
// either direction) once it observes convergence. Deliberately idempotent:
// called every steady-state pass too, which is harmless (a small JSON write
// at most once per wake/tick, never on a hot ban path).
func (m *BanManager) migrationDone() {
	m.mu.Lock()
	m.state.Migrating = false
	m.state.UpdatedAt = m.opts.Now().UTC().Format(time.RFC3339)
	s := m.state
	path := m.statePath
	m.mu.Unlock()

	if err := saveBanState(path, s); err != nil {
		log.Printf("[firewall] could not persist ban executor state: %v", err)
	}
}

// persistSwitch records the start of a switch BEFORE the first op of it is
// ever issued, so a crash mid-switch resumes correctly on restart (the
// persisted Mode already reflects the new target, Migrating stays true
// until migrationDone fires).
func (m *BanManager) persistSwitch(target string) {
	m.state = banState{
		Mode: target, Migrating: true, MigrationTarget: target,
		LastUndoToken: m.state.LastUndoToken, LastUndoRemoved: m.state.LastUndoRemoved,
		UpdatedAt: m.opts.Now().UTC().Format(time.RFC3339),
	}
	if err := saveBanState(m.statePath, m.state); err != nil {
		log.Printf("[firewall] could not persist ban executor state: %v", err)
	}
}

// normalizeExecutor maps an unknown/empty executor string to "defensia",
// logging the unknown value exactly once per manager instance.
func (m *BanManager) normalizeExecutor(executor string) string {
	if executor == "defensia" || executor == "csf" {
		return executor
	}
	m.mu.Lock()
	warn := !m.unknownExecLogged
	m.unknownExecLogged = true
	m.mu.Unlock()
	if warn && executor != "" {
		log.Printf("[firewall] unknown ban executor %q, treating as defensia", executor)
	}
	return "defensia"
}

// ApplySync reconciles the firewall against in.Bans.
//
// defensia mode performs exactly Phase 17's main.go sequence:
// ApplyBanEntries(entries) (skipped entirely under MonitorMode) then
// CleanupStaleBans(activeBanIPs, activeRuleIPs) — unchanged on every
// backend (ipset, nftables, iptables, none).
//
// csf mode hands the desired state to the CSF worker (non-blocking) and
// cleans up the Defensia backend down to only the IPs the worker has not
// yet confirmed moved into CSF, plus threat-feed IPs (which the CSF
// executor never removes).
func (m *BanManager) ApplySync(in SyncInput) SyncResult {
	executor := m.normalizeExecutor(in.Executor)
	emergency := in.Emergency || csfPausedFn()
	target := executor
	if emergency {
		target = "defensia"
	}

	m.mu.Lock()
	csf := m.csf
	prevMode := m.lastMode
	lastUndoToken := m.state.LastUndoToken
	switching := target != prevMode
	if switching {
		m.persistSwitch(target)
	} else if emergency {
		// Not a detected "switch" (e.g. already-defensia at rest, or the
		// very first sync of this process) but still an emergency: the
		// persisted file must always say defensia while one is active, so a
		// restart mid-emergency also issues zero CSF commands.
		m.state.Mode = "defensia"
		m.state.Migrating = false
		m.state.UpdatedAt = m.opts.Now().UTC().Format(time.RFC3339)
		if err := saveBanState(m.statePath, m.state); err != nil {
			log.Printf("[firewall] could not persist ban executor state: %v", err)
		}
	}
	m.lastMode = target
	m.emergency = emergency
	wantsUndo := in.UndoToken != "" && in.UndoToken != lastUndoToken
	m.undoBlockedByEmergency = wantsUndo && emergency
	m.mu.Unlock()

	if switching {
		m.opts.Emit(ExecutorEvent{
			Type: "csf_executor_switched", Severity: "info",
			Details: map[string]string{"from": prevMode, "to": target},
		})
	}

	if emergency {
		// Emergency means zero CSF commands, period — not even the cleanup
		// migration runs, and not even a requested undo (it is deferred
		// until the emergency ends, reported via Status' undo_blocked_
		// emergency reason); whatever is in CSF stays there untouched.
		if csf != nil {
			csf.setMigrateTarget("", false, nil)
		}
		return m.applyDefensia(in)
	}

	if wantsUndo && csf != nil {
		csf.requestUndo(in.UndoToken, in.Bans)
	}

	if target == "defensia" {
		res := m.applyDefensia(in)
		if csf != nil {
			csf.setMigrateTarget("defensia", false, in.Bans)
		}
		return res
	}

	// target == "csf"
	if csf == nil {
		// Worker never started (HasCSF false on this host) — bans must
		// still be enforced somewhere, so fall back to the defensia path
		// rather than silently dropping them.
		return m.applyDefensia(in)
	}
	csf.setMigrateTarget("", false, nil)
	csf.setDesired(in)
	keep := csf.ipsetKeep()
	for ip := range in.ThreatFeedIPs {
		keep[ip] = true
	}
	cleaned := cleanupStaleBansFn(keep, in.ActiveRuleIPs)
	return SyncResult{Applied: csf.appliedCount(), Cleaned: cleaned}
}

// applyDefensia is exactly Phase 17's main.go sequence: ApplyBanEntries
// (skipped under MonitorMode) then CleanupStaleBans — unchanged on every
// backend (ipset, nftables, iptables, none).
func (m *BanManager) applyDefensia(in SyncInput) SyncResult {
	entries := make([]BanEntry, 0, len(in.Bans))
	activeBanIPs := make(map[string]bool, len(in.Bans))
	for _, b := range in.Bans {
		entries = append(entries, BanEntry{IP: b.IP, TTL: b.TTL})
		activeBanIPs[b.IP] = true
	}

	applied := 0
	if !in.MonitorMode {
		applied = applyBanEntriesFn(entries)
	}
	cleaned := cleanupStaleBansFn(activeBanIPs, in.ActiveRuleIPs)

	return SyncResult{Applied: applied, Cleaned: cleaned}
}

// Ban bans a single IP immediately (e.g. a live watcher detection), outside
// the periodic sync. It returns the firewall error unchanged so main.go's
// shouldReportBan wrappers keep working (ErrNoBackend / ErrProtectedIP).
func (m *BanManager) Ban(ip, reason string) error {
	m.mu.Lock()
	csf := m.csf
	csfMode := m.lastMode == "csf"
	m.mu.Unlock()

	if csfMode && csf != nil {
		if err := admitBan(ip, "csf_local"); err != nil {
			return err
		}
		csf.localBanIP(ip, reason)
		return nil
	}

	return banIPFn(ip)
}

// Unban removes a single IP's ban immediately.
func (m *BanManager) Unban(ip string) error {
	m.mu.Lock()
	csf := m.csf
	csfMode := m.lastMode == "csf"
	m.mu.Unlock()

	if csfMode && csf != nil {
		csf.localUnbanIP(ip)
		return nil
	}

	return unbanIPFn(ip)
}

// Status reports the current executor state for the heartbeat payload.
// Returns nil when CSF is not installed on this host at all.
func (m *BanManager) Status() *ExecutorStatus {
	if !guardHasCSF() {
		return nil
	}

	m.mu.Lock()
	csf := m.csf
	emergency := m.emergency
	mode := m.lastMode
	undoBlocked := m.undoBlockedByEmergency
	m.mu.Unlock()

	if emergency {
		reason := ""
		if undoBlocked {
			reason = "undo_blocked_emergency"
		}
		return &ExecutorStatus{
			Mode: "defensia", EffectiveMode: "defensia", State: "emergency_off", Reason: reason,
			CSFLimit: -1, UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}

	if csf == nil {
		return &ExecutorStatus{Mode: mode, EffectiveMode: mode, State: "ok", CSFLimit: -1, UpdatedAt: time.Now().UTC().Format(time.RFC3339)}
	}

	return csf.status()
}
