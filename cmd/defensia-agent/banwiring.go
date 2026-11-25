package main

import (
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defensia/agent/internal/api"
	"github.com/defensia/agent/internal/firewall"
)

// newBanManager wires the executor's events back to the panel: every
// ExecutorEvent is sent in its OWN ReportEvents batch (never QueueEvent —
// an old panel rejecting an unknown type must never drop an unrelated
// security event queued alongside it).
func newBanManager(client *api.Client) *firewall.BanManager {
	return firewall.NewBanManager(firewall.ManagerOptions{
		StatePath: "/etc/defensia/ban_executor.json",
		Emit: func(ev firewall.ExecutorEvent) {
			go func() {
				if err := client.ReportEvents([]api.EventRequest{executorEventRequest(ev, time.Now())}); err != nil {
					log.Printf("[ban-executor] event %s not reported: %v", ev.Type, err)
				}
			}()
		},
	})
}

// buildSyncInput translates one /sync response into the executor's
// SyncInput. The defensia-path kernel TTL (DesiredBan.TTL) is still
// Phase 17's banTTL — unchanged regardless of which executor is actually
// configured, since the CSF path derives its own TTL from ExpiresAt
// directly (csfTTLFor, in the firewall package).
func buildSyncInput(s *api.SyncResponse, now time.Time) firewall.SyncInput {
	emergency := s.Config.BanExecutorEmergency || (s.CSFIntegrationDisabled != nil && *s.CSFIntegrationDisabled)

	bans := make([]firewall.DesiredBan, 0, len(s.Bans))
	for _, b := range s.Bans {
		reason := "ban"
		if b.Reason != nil && *b.Reason != "" {
			reason = *b.Reason
		}
		banCount := 0
		if b.BanCount != nil {
			banCount = *b.BanCount
		}

		expiresAt := parseBanExpiry(b.ExpiresAt)
		if b.ExpiresAt != nil && *b.ExpiresAt != "" && expiresAt == nil {
			log.Printf("[sync] ban %d (%s): unparseable expires_at %q, treating as permanent", b.ID, b.IPAddress, *b.ExpiresAt)
		}

		bans = append(bans, firewall.DesiredBan{
			IP: b.IPAddress, Reason: reason, BanCount: banCount, PanelID: b.ID,
			ExpiresAt: expiresAt,
			TTL:       banTTL(b.ExpiresAt, now),
		})
	}

	threatFeedIPs := make(map[string]bool, len(s.ThreatFeed))
	for _, e := range s.ThreatFeed {
		if e.IP != nil && *e.IP != "" {
			threatFeedIPs[*e.IP] = true
		}
	}

	activeRuleIPs := make(map[string]bool)
	for _, r := range s.Rules {
		if r.Type == "block" && r.IPAddress != nil && *r.IPAddress != "" {
			activeRuleIPs[*r.IPAddress] = true
		}
	}

	return firewall.SyncInput{
		Executor:      s.Config.BanExecutor,
		Emergency:     emergency,
		UndoToken:     s.Config.UndoToken(),
		Bans:          bans,
		ThreatFeedIPs: threatFeedIPs,
		ActiveRuleIPs: activeRuleIPs,
		MonitorMode:   s.Config.MonitorMode,
	}
}

const (
	syncIntervalDefault = 5 * time.Minute
	syncIntervalMin     = 10 * time.Second
	syncIntervalMax     = 3600 * time.Second
)

var syncIntervalLogOnce sync.Once

// syncInterval lets the lab override the fallback sync ticker's period via
// DEFENSIA_SYNC_INTERVAL_SECONDS, clamped to [10s, 3600s]; unset or
// unparseable falls back to Phase 17's 5-minute default.
func syncInterval() time.Duration {
	v := os.Getenv("DEFENSIA_SYNC_INTERVAL_SECONDS")
	if v == "" {
		return syncIntervalDefault
	}
	secs, err := strconv.Atoi(v)
	if err != nil {
		return syncIntervalDefault
	}

	d := time.Duration(secs) * time.Second
	if d < syncIntervalMin {
		d = syncIntervalMin
	}
	if d > syncIntervalMax {
		d = syncIntervalMax
	}
	syncIntervalLogOnce.Do(func() {
		log.Printf("[sync] interval overridden to %s via DEFENSIA_SYNC_INTERVAL_SECONDS", d)
	})
	return d
}

// executorEventRequest converts an executor event into the wire shape,
// defaulting severity to "info" and lifting a recognisable IP out of
// Details["ip"] into SourceIP (the panel's events table indexes on it).
func executorEventRequest(ev firewall.ExecutorEvent, now time.Time) api.EventRequest {
	severity := ev.Severity
	if severity == "" {
		severity = "info"
	}

	req := api.EventRequest{
		Type: ev.Type, Severity: severity, Details: ev.Details,
		OccurredAt: now.UTC().Format(time.RFC3339),
	}
	if ip, ok := ev.Details["ip"]; ok && net.ParseIP(ip) != nil {
		req.SourceIP = ip
	}
	return req
}

var reasonDisallowedChars = regexp.MustCompile(`[^a-z0-9_:.\-]+`)

// sanitizeHeartbeatReason keeps the heartbeat's ban_executor_state.reason
// panel-acceptable regardless of what the executor put in it: lowercased,
// restricted to [a-z0-9_:.-], truncated to 120 chars.
func sanitizeHeartbeatReason(s string) string {
	s = strings.ToLower(s)
	s = reasonDisallowedChars.ReplaceAllString(s, "")
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

var validExecutorStates = map[string]bool{
	"ok": true, "migrating": true, "degraded": true,
	"unavailable": true, "capacity_exhausted": true, "emergency_off": true,
}

func clampNonNegative(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

// statusToHeartbeat sanitises firewall.ExecutorStatus into the wire shape:
// nil in -> nil out (CSF not installed, key omitted entirely); an unknown
// CSFLimit (-1) becomes JSON null, never a guessed number; negative
// counters (should never happen, but never trust it) clamp to 0; an
// over-length undo token (> 64 chars, corrupt/attacker-controlled) is
// dropped rather than forwarded; a State outside the 6-value enum is
// reported as "unavailable"/"invalid_state" so the panel never has to
// guess what an unrecognised value means.
func statusToHeartbeat(s *firewall.ExecutorStatus) *api.BanExecutorState {
	if s == nil {
		return nil
	}

	state := s.State
	reason := s.Reason
	if !validExecutorStates[state] {
		state = "unavailable"
		reason = "invalid_state"
	}

	var limit *int
	if s.CSFLimit >= 0 {
		l := s.CSFLimit
		limit = &l
	}

	lastUndoToken := s.LastUndoToken
	if len(lastUndoToken) > 64 {
		lastUndoToken = ""
	}

	return &api.BanExecutorState{
		Mode: s.Mode, EffectiveMode: s.EffectiveMode, State: state,
		Reason: sanitizeHeartbeatReason(reason), CSFReady: s.CSFReady, CSFLimit: limit,
		CSFTempbanTotal: clampNonNegative(s.CSFTempbanTotal), DefensiaInCSF: clampNonNegative(s.DefensiaInCSF),
		Deferred: clampNonNegative(s.Deferred), DeferredIPv6: clampNonNegative(s.DeferredIPv6),
		PendingMigration: clampNonNegative(s.PendingMigration), SkippedProtected: clampNonNegative(s.SkippedProtected),
		LastUndoToken: lastUndoToken, LastUndoRemoved: clampNonNegative(s.LastUndoRemoved),
		UpdatedAt: s.UpdatedAt,
	}
}
