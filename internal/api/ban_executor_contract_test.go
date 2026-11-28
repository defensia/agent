package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return data
}

func TestDecodeSyncV18(t *testing.T) {
	var sync SyncResponse
	if err := json.Unmarshal(readTestdata(t, "sync_v18.json"), &sync); err != nil {
		t.Fatalf("unmarshal sync_v18.json: %v", err)
	}

	if sync.Config.BanExecutor != "csf" {
		t.Errorf("BanExecutor = %q, want csf", sync.Config.BanExecutor)
	}
	if sync.Config.BanExecutorEmergency {
		t.Error("BanExecutorEmergency = true, want false")
	}
	if got := sync.Config.UndoToken(); got != "Tok123" {
		t.Errorf("UndoToken() = %q, want Tok123", got)
	}
	if sync.CSFIntegrationDisabled == nil || *sync.CSFIntegrationDisabled {
		t.Errorf("CSFIntegrationDisabled = %v, want non-nil false", sync.CSFIntegrationDisabled)
	}

	if len(sync.Bans) != 2 {
		t.Fatalf("want 2 bans, got %d", len(sync.Bans))
	}
	b0 := sync.Bans[0]
	if b0.Reason == nil || *b0.Reason != "brute_force" {
		t.Errorf("bans[0].Reason = %v, want brute_force", b0.Reason)
	}
	if b0.BanCount == nil || *b0.BanCount != 3 {
		t.Errorf("bans[0].BanCount = %v, want 3", b0.BanCount)
	}
	if b0.ExpiresAt == nil || *b0.ExpiresAt != "2026-11-17T10:00:00.000000Z" {
		t.Errorf("bans[0].ExpiresAt = %v, want the timestamp", b0.ExpiresAt)
	}

	b1 := sync.Bans[1]
	if b1.Reason != nil {
		t.Errorf("bans[1].Reason = %v, want nil", b1.Reason)
	}
	if b1.BanCount != nil {
		t.Errorf("bans[1].BanCount = %v, want nil", b1.BanCount)
	}
}

func TestDecodeSyncLegacy(t *testing.T) {
	var sync SyncResponse
	if err := json.Unmarshal(readTestdata(t, "sync_legacy.json"), &sync); err != nil {
		t.Fatalf("unmarshal sync_legacy.json: %v", err)
	}

	if sync.Config.BanExecutor != "" {
		t.Errorf("BanExecutor = %q, want \"\" (key absent on an old panel)", sync.Config.BanExecutor)
	}
	if sync.Config.BanExecutorEmergency {
		t.Error("BanExecutorEmergency = true, want false")
	}
	if got := sync.Config.UndoToken(); got != "" {
		t.Errorf("UndoToken() = %q, want \"\" (key absent)", got)
	}
}

func TestHeartbeatOmitsStateWhenNil(t *testing.T) {
	req := HeartbeatRequest{Status: "online"}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["ban_executor_state"]; ok {
		t.Error("ban_executor_state key present, want omitted entirely")
	}
}

func TestHeartbeatStateKeys(t *testing.T) {
	limit := 100
	req := HeartbeatRequest{
		Status: "online",
		BanExecutorState: &BanExecutorState{
			Mode: "csf", EffectiveMode: "csf", State: "ok", Reason: "",
			CSFReady: true, CSFLimit: &limit, CSFTempbanTotal: 5, DefensiaInCSF: 2,
			Deferred: 0, DeferredIPv6: 0, PendingMigration: 0, SkippedProtected: 0,
			LastUndoToken: "T1", LastUndoRemoved: 3, UpdatedAt: "2026-11-25T00:00:00Z",
		},
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	raw, ok := m["ban_executor_state"]
	if !ok {
		t.Fatal("ban_executor_state key missing")
	}

	var inner map[string]json.RawMessage
	if err := json.Unmarshal(raw, &inner); err != nil {
		t.Fatalf("unmarshal inner: %v", err)
	}

	want := []string{
		"mode", "effective_mode", "state", "reason", "csf_ready", "csf_limit",
		"csf_tempban_total", "defensia_in_csf", "deferred", "deferred_ipv6",
		"pending_migration", "skipped_protected", "last_undo_token",
		"last_undo_removed", "updated_at",
	}
	if len(inner) != len(want) {
		var got []string
		for k := range inner {
			got = append(got, k)
		}
		sort.Strings(got)
		sort.Strings(want)
		t.Fatalf("got %d keys %v, want %d keys %v", len(inner), got, len(want), want)
	}
	for _, k := range want {
		if _, ok := inner[k]; !ok {
			t.Errorf("missing key %q", k)
		}
	}
}

func TestHeartbeatStateNullLimit(t *testing.T) {
	req := HeartbeatRequest{
		Status: "online",
		BanExecutorState: &BanExecutorState{
			Mode: "defensia", EffectiveMode: "defensia", State: "ok", CSFLimit: nil,
			UpdatedAt: "2026-11-25T00:00:00Z",
		},
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var inner map[string]json.RawMessage
	if err := json.Unmarshal(m["ban_executor_state"], &inner); err != nil {
		t.Fatalf("unmarshal inner: %v", err)
	}
	if string(inner["csf_limit"]) != "null" {
		t.Errorf("csf_limit = %s, want null", inner["csf_limit"])
	}
}
