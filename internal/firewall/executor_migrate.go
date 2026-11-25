package firewall

import (
	"context"
	"errors"
	"log"
	"time"
)

// runMigratePass is the worker's entry point while switching csf -> defensia
// (BanManager puts the worker in this mode via setMigrateTarget("defensia",
// ...)): it never runs the normal CSF-add reconcile pass, only
// migrateToDefensia, and reports the result as Status "migrating" until no
// "ours" entries remain in csf.tempban.
func (e *csfExecutor) runMigratePass(ctx context.Context, desired SyncInput, all bool) {
	removed, pending, reason := e.migrateToDefensia(ctx, desired.Bans, all)
	_ = removed

	temp2, err := readTempBans()
	oursLeft := 0
	total := 0
	if err == nil {
		total = len(temp2.Entries)
		for _, en := range temp2.Entries {
			if en.Ours {
				oursLeft++
			}
		}
	} else {
		// Could not confirm convergence this pass; report migrating and try
		// again next wake/tick rather than guessing.
		oursLeft = pending + 1
	}

	state := "migrating"
	effective := "csf"
	if oursLeft == 0 && pending == 0 {
		state = "ok"
		effective = "defensia"
		if e.onMigrationDone != nil {
			e.onMigrationDone()
		}
	}

	e.statusPtr.Store(&ExecutorStatus{
		Mode: "defensia", EffectiveMode: effective, State: state, Reason: reason,
		CSFTempbanTotal: total, DefensiaInCSF: oursLeft, PendingMigration: pending,
		UpdatedAt: e.now().UTC().Format(time.RFC3339),
	})
}

// migrateToDefensia is the ONLY function in this package that calls
// banIPForFn: it moves every still-"ours" CSF temp ban back onto the
// Defensia backend, make-before-break — BanIPFor must succeed (and the
// backend generation must not have changed mid-flight) before the matching
// csf.tempban entry is ever removed. An IP refused by the guard
// (ErrProtectedIP) is the one exception: it must never stay blocked nowhere
// at all, so its CSF entry is removed regardless of backend/generation
// state. `all` (used by plan 08's undo) widens the desired set to "every
// ours entry", not just the panel's current desired list.
func (e *csfExecutor) migrateToDefensia(ctx context.Context, desired []DesiredBan, all bool) (removed, pending int, reason string) {
	desiredByIP := make(map[string]DesiredBan, len(desired))
	for _, d := range desired {
		desiredByIP[d.IP] = d
	}

	temp, err := readTempBans()
	if err != nil {
		return 0, 0, ""
	}

	// "Ready" here means both the environment looks sane (testing_mode,
	// LF_DAEMON, DENYIN) AND the breaker allows writes — a degraded breaker
	// must hold back every removal exactly like an environment problem does
	// (reported the same way: BanIPFor still runs, csf_cleanup_pending).
	ready := false
	if conf, cerr := readCSFBanConf(); cerr == nil {
		envReady, _, _ := e.environmentReady(ctx, conf)
		ready = envReady && e.breaker.allowWrite()
	}

	ops := 0
	sawUnavailable := false
	sawNotReady := false

	for _, entry := range temp.Entries {
		if !entry.Ours {
			continue
		}
		if ops >= csfMaxOpsPerPass {
			pending++
			continue
		}

		d, isDesired := desiredByIP[entry.IP]
		if !isDesired {
			// No panel ban is driving this IP (either it was never ours to
			// re-add — `all`, plan 08's undo, widens what counts as "ours
			// enough to clean up" elsewhere — or the panel simply unbanned
			// it meanwhile): there is nothing to re-add to the Defensia
			// backend, just drop the stale CSF entry if we safely can.
			if !ready {
				pending++
				sawNotReady = true
				continue
			}
			if e.removeTempOwned(ctx, entry.IP) {
				removed++
			} else {
				pending++
			}
			ops++
			if ops < csfMaxOpsPerPass {
				e.sleep(csfMinInterval)
			}
			continue
		}

		gen := generationFn()
		banErr := banIPForFn(entry.IP, d.TTL)
		ops++

		switch {
		case banErr == nil:
			if !ready {
				pending++
				sawNotReady = true
			} else if generationFn() != gen {
				pending++
			} else if e.removeTempOwned(ctx, entry.IP) {
				removed++
			} else {
				pending++ // a foreign entry also exists for this IP; retry later
			}
		case errors.Is(banErr, ErrProtectedIP):
			// Must never stay blocked nowhere at all: remove from CSF
			// regardless of CSF readiness/generation state.
			e.removeTemp(ctx, entry.IP)
			removed++
		case errors.Is(banErr, ErrNoBackend):
			pending++
			sawUnavailable = true
		default:
			pending++
			log.Printf("[firewall] migrate-to-defensia: BanIPFor(%s) failed: %v", entry.IP, banErr)
		}

		if ops < csfMaxOpsPerPass {
			e.sleep(csfMinInterval)
		}
	}

	switch {
	case sawUnavailable:
		reason = "defensia_backend_unavailable"
	case sawNotReady:
		reason = "csf_cleanup_pending"
	}

	return removed, pending, reason
}

// removeTempOwned removes ip's CSF temp ban only if no foreign (non-"ours")
// entry also exists for the same IP at the moment of removal — a fresh
// re-check right before the write, since the plan-time read and this write
// are not atomic with CSF's own state.
func (e *csfExecutor) removeTempOwned(ctx context.Context, ip string) bool {
	if t, err := readTempBans(); err == nil {
		for _, en := range t.Entries {
			if en.IP == ip && !en.Ours {
				return false
			}
		}
	}
	outcome, _ := e.cli.TempRemove(ctx, ip)
	return outcome.Result == ResultOK || outcome.Result == ResultBenign
}

// removeTemp removes ip's CSF temp ban unconditionally (used only for the
// ErrProtectedIP safety case, where leaving any entry — foreign or not — in
// place would mean the IP stays blocked somewhere it must never be).
func (e *csfExecutor) removeTemp(ctx context.Context, ip string) {
	e.cli.TempRemove(ctx, ip)
}
