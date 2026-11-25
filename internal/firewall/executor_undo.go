package firewall

import (
	"context"
	"time"
)

// undoState tracks one in-progress "remove all Defensia entries from CSF"
// request, keyed by the panel's generation token (SYNC-06) — not the lossy
// csf_pending_actions queue. removed accumulates across passes/attempts so
// the final csf_undo_completed event reports the true total, not just the
// last pass's delta.
type undoState struct {
	token    string
	attempts int
	removed  int
}

// requestUndo schedules (or re-wakes, idempotently per token) an undo-all
// pass. Never runs inline — the worker goroutine does it, like every other
// CSF write.
func (e *csfExecutor) requestUndo(token string, bans []DesiredBan) {
	e.mu.Lock()
	if e.undo == nil || e.undo.token != token {
		e.undo = &undoState{token: token}
	}
	e.desired.Bans = bans
	e.mu.Unlock()
	e.wakeUp()
}

// undoAttemptsMax caps how many passes a single undo token gets before an
// unresolved conflict (an IP with both an "ours" and a foreign entry) is
// reported as-is rather than retried forever.
const undoAttemptsMax = 3

// runUndoPass is undoAll's worker-side entry point: it never runs the
// normal CSF-add reconcile pass, only migrateToDefensia with the widened
// "every ours entry" scope (all=true), applied regardless of the current
// executor mode (defensia or csf) — undo must work even if a prior
// emergency already forced defensia while leftover CSF entries remain.
func (e *csfExecutor) runUndoPass(ctx context.Context, desired SyncInput, u *undoState) {
	removed, pending, reason := e.migrateToDefensia(ctx, desired.Bans, true)
	u.removed += removed
	u.attempts++

	temp2, err := readTempBans()
	oursLeft := pending
	total := 0
	if err == nil {
		total = len(temp2.Entries)
		oursLeft = 0
		for _, en := range temp2.Entries {
			if en.Ours {
				oursLeft++
			}
		}
	}

	done := oursLeft == 0 || u.attempts >= undoAttemptsMax

	statusReason := ""
	switch reason {
	case "defensia_backend_unavailable":
		statusReason = "undo_waiting_for_defensia_backend"
	case "csf_cleanup_pending":
		statusReason = "undo_waiting_for_csf"
	}

	e.statusPtr.Store(&ExecutorStatus{
		Mode: "defensia", EffectiveMode: "defensia", State: boolState(done, "ok", "migrating"), Reason: statusReason,
		CSFTempbanTotal: total, DefensiaInCSF: oursLeft, PendingMigration: oursLeft,
		UpdatedAt: e.now().UTC().Format(time.RFC3339),
	})

	if done {
		e.mu.Lock()
		e.undo = nil
		e.mu.Unlock()
		if e.onUndoComplete != nil {
			e.onUndoComplete(u.token, u.removed, oursLeft)
		}
		return
	}

	// Not done yet (oursLeft > 0, attempts still under undoAttemptsMax):
	// self-wake so the next attempt runs promptly instead of waiting for
	// the next external ApplySync or the 60s ticker — same rationale as
	// the normal CSF-add pass's OpsCapped self-wake (executor_csf.go).
	// Lab-measured, alma9-csf-orig, phase 18-10: a pass that converged
	// everything but needed the "done" confirmation on a later read missed
	// the test's 30s window waiting on onUndoComplete, since nothing woke
	// the worker again until the 60s ticker.
	e.wakeUp()
}

func boolState(cond bool, ifTrue, ifFalse string) string {
	if cond {
		return ifTrue
	}
	return ifFalse
}
