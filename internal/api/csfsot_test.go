package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defensia/agent/internal/csfsotwire"
)

// --- Builders (also used by the golden tests and the behavior tests below,
// so a golden and a unit test can never silently drift apart). ---

func csfSotFullReport() *csfsotwire.Report {
	nextAt := time.Date(2026, 11, 5, 10, 5, 0, 0, time.UTC)
	firstSeen := time.Date(2026, 11, 5, 9, 58, 0, 0, time.UTC)
	refusedAt := time.Date(2026, 11, 5, 9, 59, 0, 0, time.UTC)
	mtime := time.Date(2026, 11, 5, 9, 50, 0, 0, time.UTC)
	revertAck := "11111111-1111-4111-8111-111111111111"

	return &csfsotwire.Report{
		Active:          true,
		GenerationSeen:  7,
		GenerationAcked: 7,
		Status:          "drift",
		ObservedHash:    strings.Repeat("c", 64),
		DesiredHash:     strings.Repeat("d", 64),
		TokensAcked:     csfsotwire.TokensAcked{Revert: &revertAck},
		Drift: []csfsotwire.DriftItem{
			{Kind: "port", Key: "TCP_IN", Added: []string{"8080"}, Removed: []string{"21"}, FirstSeen: firstSeen, Hint: "default"},
			{Kind: "allow", Value: "203.0.113.5", Change: "removed", FirstSeen: firstSeen, Hint: "default"},
		},
		Observed: &csfsotwire.Managed{
			Ports: map[string]string{"TCP_IN": "20,21,22,25,53,80,443,8080"},
			Allow: []csfsotwire.Entry{},
			Deny:  []csfsotwire.Entry{},
		},
		CSFConfMtime:       &mtime,
		IPv6:               true,
		ManagedKeys:        []string{"TCP_IN", "TCP_OUT", "UDP_IN", "UDP_OUT", "TCP6_IN", "TCP6_OUT", "UDP6_IN", "UDP6_OUT"},
		TaggedEntriesCount: 2,
		Retry:              &csfsotwire.RetryInfo{Count: 1, NextAt: &nextAt},
		Auto:               &csfsotwire.AutoInfo{FixesInWindow: 2, NextAt: &nextAt},
		Refused: []csfsotwire.Refusal{
			{Reason: "ssh_port_in_use", Detail: "22", At: refusedAt, Generation: 7},
		},
		SSHPorts: []int{22},
	}
}

func csfSotPrecheckReport() *csfsotwire.Report {
	return &csfsotwire.Report{
		Active: false,
		Problems: []csfsotwire.Problem{
			{Reason: "duplicate_key", Detail: "TCP_IN"},
		},
	}
}

func heartbeatCSFSot() HeartbeatRequest {
	hb := baseHeartbeat()
	hb.Capabilities = []string{"csf_sot"}
	hb.CSFSot = csfSotFullReport()
	return hb
}

func heartbeatCSFSotPrecheck() HeartbeatRequest {
	hb := baseHeartbeat()
	hb.Capabilities = []string{"csf_sot"}
	hb.CSFSot = csfSotPrecheckReport()
	return hb
}

func csfSotSnapshotRequest() csfsotwire.SnapshotRequest {
	return csfsotwire.SnapshotRequest{
		Observed: csfsotwire.Managed{
			Ports: map[string]string{"TCP_IN": "20,21,22,25,53,80,443"},
			Allow: []csfsotwire.Entry{},
			Deny:  []csfsotwire.Entry{},
		},
		ObservedHash: strings.Repeat("e", 64),
		IPv6:         true,
		ManagedKeys:  []string{"TCP_IN", "TCP_OUT", "UDP_IN", "UDP_OUT"},
		SSHPorts:     []int{22},
		Fork:         "aetherinox",
		Version:      "15.10",
		Problems:     []csfsotwire.Problem{},
	}
}

// --- Encode-direction goldens (agent -> panel) ---

func TestCSFSotContractGolden(t *testing.T) {
	compareOrUpdateGolden(t, "heartbeat_csf_sot_precheck.json", heartbeatCSFSotPrecheck())
	compareOrUpdateGolden(t, "snapshot_request.json", csfSotSnapshotRequest())
}

// --- Behavior tests ---

func TestHeartbeatCapabilitiesAlways(t *testing.T) {
	hb := baseHeartbeat()
	hb.Capabilities = []string{"csf_sot"}

	data, err := json.Marshal(hb)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	keys := rawKeys(t, data)

	raw, ok := keys["capabilities"]
	if !ok || string(raw) != `["csf_sot"]` {
		t.Errorf("capabilities = %v (present=%v), want [\"csf_sot\"]", raw, ok)
	}
	if _, ok := keys["csf_sot"]; ok {
		t.Errorf("csf_sot key must be absent when CSFSot is nil, got %s", data)
	}
}

func TestHeartbeatCSFSotGolden(t *testing.T) {
	compareOrUpdateGolden(t, "heartbeat_csf_sot.json", heartbeatCSFSot())
}

func TestSyncOldPanelNoCSFSot(t *testing.T) {
	var sync SyncResponse
	if err := json.Unmarshal(readGolden(t, "sync_old_panel.json"), &sync); err != nil {
		t.Fatalf("unmarshal sync_old_panel.json: %v", err)
	}
	if sync.Config.CSFSot != nil {
		t.Errorf("old-panel sync must decode Config.CSFSot as nil, got %+v", sync.Config.CSFSot)
	}
}

func TestSyncCSFSotActive(t *testing.T) {
	var sync SyncResponse
	if err := json.Unmarshal(readGolden(t, "sync_csf_sot_active.json"), &sync); err != nil {
		t.Fatalf("unmarshal sync_csf_sot_active.json: %v", err)
	}
	cfg := sync.Config.CSFSot
	if cfg == nil {
		t.Fatalf("Config.CSFSot must not be nil")
	}
	if cfg.Mode != "defensia" || cfg.Correction != "warn" || cfg.Generation != 7 || cfg.SnapshotRequested {
		t.Errorf("unexpected scalar fields: %+v", cfg)
	}
	if cfg.Desired == nil {
		t.Fatalf("Desired must not be nil")
	}
	if cfg.Desired.Ports["TCP_IN"] != "20,21,22,25,53,80,443" {
		t.Errorf("Desired.Ports[TCP_IN] = %q, want the golden's value", cfg.Desired.Ports["TCP_IN"])
	}
	if len(cfg.Desired.Allow) != 1 || cfg.Desired.Allow[0].Value != "203.0.113.5" {
		t.Errorf("unexpected Allow: %+v", cfg.Desired.Allow)
	}
	if len(cfg.Desired.Deny) != 1 || cfg.Desired.Deny[0].Value != "198.51.100.0/24" {
		t.Errorf("unexpected Deny: %+v", cfg.Desired.Deny)
	}
}

func TestSyncCSFSotInactive(t *testing.T) {
	var sync SyncResponse
	if err := json.Unmarshal(readGolden(t, "sync_csf_sot_csf.json"), &sync); err != nil {
		t.Fatalf("unmarshal sync_csf_sot_csf.json: %v", err)
	}
	cfg := sync.Config.CSFSot
	if cfg == nil {
		t.Fatalf("Config.CSFSot must not be nil")
	}
	if cfg.Mode != "csf" {
		t.Errorf("Mode = %q, want csf", cfg.Mode)
	}
	if cfg.Desired != nil {
		t.Errorf("Desired must be nil in mode csf, got %+v", cfg.Desired)
	}
}

func TestHeartbeatResponseHint(t *testing.T) {
	var resp HeartbeatResponse
	if err := json.Unmarshal(readGolden(t, "heartbeat_response_csf_sot.json"), &resp); err != nil {
		t.Fatalf("unmarshal heartbeat_response_csf_sot.json: %v", err)
	}
	if resp.CSFSot == nil {
		t.Fatalf("CSFSot hint must not be nil")
	}
	if resp.CSFSot.Mode != "defensia" || resp.CSFSot.Generation != 7 || resp.CSFSot.Correction != "warn" {
		t.Errorf("unexpected hint: %+v", resp.CSFSot)
	}

	var noHint HeartbeatResponse
	if err := json.Unmarshal([]byte(`{"status":"ok","last_seen_at":"2026-11-05T10:00:00Z"}`), &noHint); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if noHint.CSFSot != nil {
		t.Errorf("CSFSot must be nil when the key is absent, got %+v", noHint.CSFSot)
	}
}

func TestPostCSFSotSnapshot(t *testing.T) {
	var gotPath, gotAuth string
	var gotBody csfsotwire.SnapshotRequest
	status := http.StatusOK
	respBody := `{"accepted":true,"generation":1}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(respBody))
	}))
	defer srv.Close()

	c := New(srv.URL, "test-token")
	req := csfSotSnapshotRequest()

	resp, code, err := c.PostCSFSotSnapshot(req)
	if err != nil {
		t.Fatalf("PostCSFSotSnapshot: %v", err)
	}
	if gotPath != "/api/v1/agent/csf/sot/snapshot" {
		t.Errorf("path = %q, want /api/v1/agent/csf/sot/snapshot", gotPath)
	}
	if gotAuth != "Bearer test-token" {
		t.Errorf("Authorization = %q, want Bearer test-token", gotAuth)
	}
	if code != http.StatusOK {
		t.Errorf("status = %d, want 200", code)
	}
	if !resp.Accepted || resp.Generation != 1 {
		t.Errorf("unexpected response: %+v", resp)
	}
	compareOrUpdateGolden(t, "snapshot_request.json", gotBody)

	status = http.StatusConflict
	respBody = `{"accepted":false,"reason":"not_requested"}`

	resp2, code2, err2 := c.PostCSFSotSnapshot(req)
	if err2 != nil {
		t.Fatalf("PostCSFSotSnapshot (409 case) must not return an error, got %v", err2)
	}
	if code2 != http.StatusConflict {
		t.Errorf("status = %d, want 409", code2)
	}
	if resp2.Accepted || resp2.Reason != "not_requested" {
		t.Errorf("unexpected response: %+v", resp2)
	}
}
