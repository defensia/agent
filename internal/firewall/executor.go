package firewall

import (
	"context"
	"log"
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
	csf               *csfExecutor
	unknownExecLogged bool
	lastMode          string // last normalized SyncInput.Executor ("defensia" | "csf")
}

// NewBanManager constructs a BanManager. opts.Now defaults to time.Now,
// opts.Emit to a no-op.
func NewBanManager(opts ManagerOptions) *BanManager {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Emit == nil {
		opts.Emit = func(ExecutorEvent) {}
	}
	return &BanManager{opts: opts}
}

// Start lazily brings up the CSF reconcile worker, only when HasCSF() is
// true on this host. Safe to call more than once (idempotent).
func (m *BanManager) Start(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.csf != nil {
		return
	}
	if !guardHasCSF() {
		return
	}
	m.csf = newCSFExecutor(m.opts)
	go m.csf.run(ctx)
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

	m.mu.Lock()
	csf := m.csf
	m.lastMode = executor
	m.mu.Unlock()

	if executor == "csf" && csf != nil {
		csf.setDesired(in)
		keep := csf.ipsetKeep()
		for ip := range in.ThreatFeedIPs {
			keep[ip] = true
		}
		cleaned := cleanupStaleBansFn(keep, in.ActiveRuleIPs)
		return SyncResult{Applied: csf.appliedCount(), Cleaned: cleaned}
	}

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
	m.mu.Unlock()

	if csf == nil {
		return &ExecutorStatus{Mode: "defensia", EffectiveMode: "defensia", State: "ok", CSFLimit: -1, UpdatedAt: time.Now().UTC().Format(time.RFC3339)}
	}

	return csf.status()
}
