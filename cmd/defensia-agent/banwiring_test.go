package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/defensia/agent/internal/api"
	"github.com/defensia/agent/internal/firewall"
)

func TestBuildSyncInput(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	plus2h := "2026-11-25T14:00:00Z"
	ip1 := "203.0.113.1"
	ip2 := "198.51.100.1"
	cidr1 := "203.0.113.0/24"
	blockIP := "203.0.113.5"

	s := &api.SyncResponse{
		Config: api.SyncConfig{BanExecutor: "csf", BanExecutorEmergency: true, CSFUndoToken: strp("T")},
		Bans: []api.Ban{
			{ID: 1, IPAddress: "203.0.113.10", ExpiresAt: &plus2h, Reason: strp("brute_force"), BanCount: intp(3)},
			{ID: 2, IPAddress: "203.0.113.11", ExpiresAt: nil, Reason: strp("manual"), BanCount: intp(1)},
			{ID: 3, IPAddress: "203.0.113.12", ExpiresAt: nil, Reason: nil, BanCount: nil},
		},
		ThreatFeed: []api.ThreatEntry{
			{IP: &ip1, Source: "spamhaus"},
			{IP: &ip2, Source: "feodo"},
			{CIDR: &cidr1, Source: "spamhaus"},
		},
		Rules: []api.Rule{
			{Type: "block", IPAddress: &blockIP, Status: "synced"},
			{Type: "block", IPAddress: nil},
		},
	}

	in := buildSyncInput(s, now)

	if in.Executor != "csf" || !in.Emergency || in.UndoToken != "T" {
		t.Fatalf("SyncInput = %+v, want Executor csf Emergency true UndoToken T", in)
	}
	if len(in.Bans) != 3 {
		t.Fatalf("want 3 bans, got %d", len(in.Bans))
	}

	b0 := in.Bans[0]
	wantExpires := now.Add(2 * time.Hour)
	if b0.ExpiresAt == nil || !b0.ExpiresAt.Equal(wantExpires) {
		t.Errorf("bans[0].ExpiresAt = %v, want %v", b0.ExpiresAt, wantExpires)
	}
	if b0.TTL != banTTL(&plus2h, now) {
		t.Errorf("bans[0].TTL = %v, want %v (banTTL)", b0.TTL, banTTL(&plus2h, now))
	}
	if b0.Reason != "brute_force" || b0.BanCount != 3 || b0.PanelID != 1 {
		t.Errorf("bans[0] = %+v, want Reason brute_force BanCount 3 PanelID 1", b0)
	}

	b2 := in.Bans[2]
	if b2.Reason != "ban" || b2.BanCount != 0 {
		t.Errorf("bans[2] = %+v, want Reason ban (default) BanCount 0", b2)
	}

	if len(in.ThreatFeedIPs) != 2 || !in.ThreatFeedIPs[ip1] || !in.ThreatFeedIPs[ip2] {
		t.Errorf("ThreatFeedIPs = %v, want exactly {%s, %s} (CIDR entries excluded)", in.ThreatFeedIPs, ip1, ip2)
	}
	if len(in.ActiveRuleIPs) != 1 || !in.ActiveRuleIPs[blockIP] {
		t.Errorf("ActiveRuleIPs = %v, want {%s}", in.ActiveRuleIPs, blockIP)
	}

	// Bad expires_at -> nil ExpiresAt, TTL as banTTL returns (0), logged (not asserted here, just must not panic).
	bad := "not-a-date"
	s2 := &api.SyncResponse{Bans: []api.Ban{{ID: 9, IPAddress: "203.0.113.99", ExpiresAt: &bad}}}
	in2 := buildSyncInput(s2, now)
	if in2.Bans[0].ExpiresAt != nil {
		t.Errorf("bad expires_at: ExpiresAt = %v, want nil", in2.Bans[0].ExpiresAt)
	}
	if in2.Bans[0].TTL != 0 {
		t.Errorf("bad expires_at: TTL = %v, want 0", in2.Bans[0].TTL)
	}
}

func TestBuildSyncInputKillSwitch(t *testing.T) {
	now := time.Now()

	s := &api.SyncResponse{Config: api.SyncConfig{BanExecutorEmergency: false}, CSFIntegrationDisabled: boolp(true)}
	if in := buildSyncInput(s, now); !in.Emergency {
		t.Error("top-level csf_integration_disabled=true should force Emergency, got false")
	}

	s2 := &api.SyncResponse{Config: api.SyncConfig{BanExecutorEmergency: false}, CSFIntegrationDisabled: nil}
	if in := buildSyncInput(s2, now); in.Emergency {
		t.Error("both absent/false should leave Emergency false")
	}
}

func TestSyncInterval(t *testing.T) {
	cases := []struct {
		env  string
		want time.Duration
	}{
		{"", 5 * time.Minute},
		{"15", 15 * time.Second},
		{"5", 10 * time.Second},
		{"99999", 3600 * time.Second},
		{"abc", 5 * time.Minute},
	}
	for _, c := range cases {
		t.Run(c.env, func(t *testing.T) {
			if c.env == "" {
				os.Unsetenv("DEFENSIA_SYNC_INTERVAL_SECONDS")
			} else {
				os.Setenv("DEFENSIA_SYNC_INTERVAL_SECONDS", c.env)
			}
			defer os.Unsetenv("DEFENSIA_SYNC_INTERVAL_SECONDS")

			if got := syncInterval(); got != c.want {
				t.Errorf("syncInterval() with env=%q = %v, want %v", c.env, got, c.want)
			}
		})
	}
}

func TestExecutorEventRequest(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

	ev := firewall.ExecutorEvent{Type: "csf_executor_degraded", Severity: "high", Details: map[string]string{"reason": "unknown_line", "ip": "203.0.113.5"}}
	req := executorEventRequest(ev, now)
	if req.Type != "csf_executor_degraded" || req.Severity != "high" {
		t.Errorf("req = %+v, want Type csf_executor_degraded Severity high", req)
	}
	if req.OccurredAt != "2026-11-25T12:00:00Z" {
		t.Errorf("OccurredAt = %q, want RFC3339 UTC", req.OccurredAt)
	}
	if req.SourceIP != "203.0.113.5" {
		t.Errorf("SourceIP = %q, want 203.0.113.5", req.SourceIP)
	}

	ev2 := firewall.ExecutorEvent{Type: "csf_undo_completed", Details: map[string]string{"token": "T1"}}
	req2 := executorEventRequest(ev2, now)
	if req2.Severity != "info" {
		t.Errorf("default Severity = %q, want info", req2.Severity)
	}
	if req2.SourceIP != "" {
		t.Errorf("SourceIP = %q, want empty (no valid ip in Details)", req2.SourceIP)
	}
}

func TestStatusToHeartbeat(t *testing.T) {
	if got := statusToHeartbeat(nil); got != nil {
		t.Fatalf("statusToHeartbeat(nil) = %+v, want nil", got)
	}

	s := &firewall.ExecutorStatus{
		Mode: "csf", EffectiveMode: "csf", State: "ok", Reason: "",
		CSFReady: true, CSFLimit: 100, CSFTempbanTotal: 5, DefensiaInCSF: 2,
		Deferred: 0, DeferredIPv6: 0, PendingMigration: 0, SkippedProtected: 0,
		LastUndoToken: "T1", LastUndoRemoved: 3, UpdatedAt: "2026-11-25T00:00:00Z",
	}
	got := statusToHeartbeat(s)
	if got == nil {
		t.Fatal("statusToHeartbeat(populated) = nil")
	}
	if got.Mode != "csf" || got.State != "ok" || got.LastUndoToken != "T1" {
		t.Errorf("got = %+v, want Mode csf State ok LastUndoToken T1", got)
	}
	if got.CSFLimit == nil || *got.CSFLimit != 100 {
		t.Errorf("CSFLimit = %v, want 100", got.CSFLimit)
	}

	unknown := &firewall.ExecutorStatus{Mode: "csf", EffectiveMode: "csf", State: "ok", CSFLimit: -1}
	if got := statusToHeartbeat(unknown); got.CSFLimit != nil {
		t.Errorf("CSFLimit -1 -> %v, want nil", got.CSFLimit)
	}

	zero := &firewall.ExecutorStatus{Mode: "csf", EffectiveMode: "csf", State: "ok", CSFLimit: 0}
	if got := statusToHeartbeat(zero); got.CSFLimit == nil || *got.CSFLimit != 0 {
		t.Errorf("CSFLimit 0 -> %v, want pointer to 0", got.CSFLimit)
	}

	neg := &firewall.ExecutorStatus{Mode: "csf", EffectiveMode: "csf", State: "ok", Deferred: -3}
	if got := statusToHeartbeat(neg); got.Deferred != 0 {
		t.Errorf("Deferred -3 -> %d, want 0", got.Deferred)
	}

	longReason := &firewall.ExecutorStatus{
		Mode: "csf", EffectiveMode: "csf", State: "ok",
		Reason: strings.Repeat("A bad réason! ", 40), // mixed case, spaces, unicode, > 120 chars raw
	}
	got = statusToHeartbeat(longReason)
	if len(got.Reason) > 120 {
		t.Errorf("Reason length = %d, want <= 120", len(got.Reason))
	}
	if strings.ContainsAny(got.Reason, " !é") {
		t.Errorf("Reason = %q, want only [a-z0-9_:.-]", got.Reason)
	}

	longToken := &firewall.ExecutorStatus{
		Mode: "csf", EffectiveMode: "csf", State: "ok",
		LastUndoToken: strings.Repeat("x", 70),
	}
	if got := statusToHeartbeat(longToken); got.LastUndoToken != "" {
		t.Errorf("LastUndoToken (70 chars) -> %q, want \"\" (dropped)", got.LastUndoToken)
	}

	invalid := &firewall.ExecutorStatus{Mode: "csf", EffectiveMode: "csf", State: "totally_bogus"}
	got = statusToHeartbeat(invalid)
	if got.State != "unavailable" || got.Reason != "invalid_state" {
		t.Errorf("invalid state -> State=%q Reason=%q, want unavailable/invalid_state", got.State, got.Reason)
	}
}
