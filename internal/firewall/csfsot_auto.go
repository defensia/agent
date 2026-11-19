package firewall

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/defensia/agent/internal/csfsotwire"
)

// autoResult is maybeAutoCorrect's answer: whether it applied anything
// this cycle, why not if it didn't, and any status/token overrides the
// caller (detectDrift) must fold into the heartbeat report.
type autoResult struct {
	Applied         bool
	HoldReason      string // settling | stale_sync | version_changed | adopted | backoff | ""
	StatusOverride  string // "" | paused_conflict | readonly
	Events          []SotEvent
	FixesInWindow   int
	NextAt          *time.Time
	ResumeTokenEcho *string
	Refused         []csfsotwire.Refusal
}

// maybeAutoCorrect is the automatic-correction policy: settle, a
// stale-sync gate, a structural-change hold, a rolling-hour limit with
// backoff, and a paused_conflict escalation that stops fighting an
// external rewriter -- resumable only by an explicit resume_token.
func (e *SotEngine) maybeAutoCorrect(ctx context.Context, cfg *csfsotwire.Config, obs sotObservation, drift []csfsotwire.DriftItem) autoResult {
	tm := sotTiming()
	res := autoResult{}

	// Resume is processed regardless of current correction mode, so
	// switching back to warn and later back to auto doesn't resurrect a
	// stale window; only an explicit resume_token clears it.
	if cfg.ResumeToken != nil && *cfg.ResumeToken != e.st.LastResumeToken {
		e.st.LastResumeToken = *cfg.ResumeToken
		e.st.Paused = false
		e.st.AutoFixes = nil
		res.ResumeTokenEcho = cfg.ResumeToken
	}

	if cfg.Correction != "auto" {
		return res
	}

	if e.st.Paused {
		res.StatusOverride = "paused_conflict"
		res.FixesInWindow = len(e.st.AutoFixes)

		return res
	}

	snap := CurrentCSFSnapshot()
	fork, version := "", ""
	if snap != nil {
		fork, version = snap.Fork, snap.Version
	}

	if fork == "unknown" {
		res.StatusOverride = "readonly"

		return res
	}

	now := e.deps.Now()

	structuralChange := e.st.LastFork != "" && (e.st.LastFork != fork || e.st.LastVersion != version)
	if structuralChange {
		e.st.HoldUntil = now.Add(tm.Hold)
		e.st.HoldReason = "version_changed"
	}
	e.st.LastFork, e.st.LastVersion = fork, version

	if now.Before(e.st.HoldUntil) {
		res.HoldReason = e.st.HoldReason
		if res.HoldReason == "" {
			res.HoldReason = "adopted"
		}

		return res
	}

	if e.deps.LastSyncOK != nil {
		if last := e.deps.LastSyncOK(); !last.IsZero() && now.Sub(last) > tm.StaleSync {
			res.HoldReason = "stale_sync"

			return res
		}
	}

	if len(drift) == 0 {
		res.FixesInWindow = len(e.st.AutoFixes)

		return res
	}

	// scope_changed drift (IPv6 toggled) is reported, never corrected,
	// to avoid fighting a deliberate config change.
	for _, d := range drift {
		if d.Hint == "scope_changed" {
			res.HoldReason = "scope_changed"

			return res
		}
	}

	settled := true
	for _, d := range drift {
		key := d.Kind + ":" + d.Key + ":" + d.Value
		if e.st.DriftSeenCycles[key] < driftSettleCycle {
			settled = false
		}
	}
	if obs.ConfMtime.IsZero() || now.Sub(obs.ConfMtime) < tm.Settle {
		settled = false
	}
	if !settled {
		res.HoldReason = "settling"

		return res
	}

	// Prune fixes outside the rolling window.
	kept := e.st.AutoFixes[:0:0]
	for _, ts := range e.st.AutoFixes {
		if now.Sub(ts) <= tm.Window {
			kept = append(kept, ts)
		}
	}
	e.st.AutoFixes = kept

	if len(e.st.AutoFixes) >= tm.MaxAuto {
		e.st.Paused = true
		changedKeys := driftKeys(drift)
		res.Events = append(res.Events, SotEvent{
			Type: "csf_sot_conflict", Severity: "warning",
			Details: map[string]string{
				"keys":   changedKeys,
				"count":  fmt.Sprintf("%d", len(e.st.AutoFixes)+1),
				"window": fmt.Sprintf("%d", int(tm.Window.Seconds())),
			},
		})
		res.StatusOverride = "paused_conflict"
		res.FixesInWindow = len(e.st.AutoFixes)

		return res
	}

	if len(e.st.AutoFixes) > 0 {
		idx := len(e.st.AutoFixes) - 1
		if idx >= len(tm.AutoBackoff) {
			idx = len(tm.AutoBackoff) - 1
		}
		nextOK := e.st.AutoFixes[len(e.st.AutoFixes)-1].Add(tm.AutoBackoff[idx])
		if now.Before(nextOK) {
			res.HoldReason = "backoff"
			res.NextAt = timePtr(nextOK)
			res.FixesInWindow = len(e.st.AutoFixes)

			return res
		}
	}

	// Apply toward desired, once, same mechanics as an intentional change.
	desired := csfsotwire.Managed{}
	if cfg.Desired != nil {
		desired = *cfg.Desired
	}

	portsResult := applyPortsFn(ctx, desired.Ports, obs)
	listsResult := applyListsFn(ctx, desired, obs, e.deps.PanelIP)

	e.st.AutoFixes = append(e.st.AutoFixes, now)
	res.FixesInWindow = len(e.st.AutoFixes)

	if portsResult.SelfWriteHash != "" {
		e.st.LastSelfWriteHash = portsResult.SelfWriteHash
	}

	allRefusals := append(append([]csfsotwire.Refusal{}, portsResult.Refusals...), listsResult.Refusals...)
	res.Refused = allRefusals
	for _, r := range allRefusals {
		res.Events = append(res.Events, SotEvent{
			Type: "csf_sot_refused", Severity: "warning",
			Details: map[string]string{"reason": r.Reason, "detail": r.Detail, "trigger": "auto"},
		})
	}

	if len(allRefusals) == 0 {
		res.Applied = true
		res.Events = append(res.Events, SotEvent{
			Type: "csf_sot_corrected", Severity: "info",
			Details: map[string]string{"trigger": "auto", "keys": driftKeys(drift)},
		})
	}

	return res
}

func driftKeys(drift []csfsotwire.DriftItem) string {
	seen := map[string]bool{}
	var keys []string
	for _, d := range drift {
		k := d.Key
		if k == "" {
			k = d.Value
		}
		if k != "" && !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}

	return strings.Join(keys, ",")
}
