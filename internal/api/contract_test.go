package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// update rewrites the golden files under testdata/contract to match whatever
// the builders below currently produce. Run once (`go test ./internal/api
// -run TestContractGolden -update`), inspect the diff by hand, then always
// run the suite without -update afterwards — these files are the actual
// panel-replayed contract (plan 15-08), not disposable test scaffolding.
var update = flag.Bool("update", false, "rewrite golden files in testdata/contract")

func strPtr(s string) *string { return &s }
func boolPtr(b bool) *bool    { return &b }
func intPtr(n int) *int       { return &n }

func goldenPath(name string) string {
	return filepath.Join("testdata", "contract", name)
}

// compareOrUpdateGolden marshals got to pretty-printed JSON and either
// rewrites the golden file (-update) or compares it byte-for-byte against
// what is already on disk.
func compareOrUpdateGolden(t *testing.T, name string, got any) {
	t.Helper()

	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal %s: %v", name, err)
	}

	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		t.Fatalf("indent %s: %v", name, err)
	}
	pretty := append(buf.Bytes(), '\n')

	path := goldenPath(name)
	if *update {
		if err := os.WriteFile(path, pretty, 0o644); err != nil {
			t.Fatalf("write golden %s: %v", name, err)
		}
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s (run with -update to create it): %v", name, err)
	}
	if !bytes.Equal(want, pretty) {
		t.Errorf("golden %s mismatch (run with -update after reviewing the diff):\n--- want ---\n%s\n--- got ---\n%s", name, want, pretty)
	}
}

// rawKeys decodes a marshalled JSON object into its top-level key set, for
// tests that only care which keys are present, not their values.
func rawKeys(t *testing.T, data []byte) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return m
}

const fixedTimestamp = "2026-11-05T10:00:00Z"

func baseHeartbeat() HeartbeatRequest {
	return HeartbeatRequest{
		Status:    "online",
		Version:   "1.4.95-test",
		Timestamp: fixedTimestamp,
	}
}

// --- Builders for the golden payloads (also reused directly by the
// behavior tests below, so the golden files and the unit tests can never
// silently drift apart). ---

func csfPresentFields() *CSFHeartbeatFields {
	return &CSFHeartbeatFields{
		CSFInstalled:       true,
		CSFVersion:         strPtr("15.11"),
		CSFPortsIn:         strPtr("20,21,22,25,80,443"),
		CSFPortsOut:        strPtr("20,21,25,80,443,2087"),
		CSFDenyCount:       intPtr(12),
		CSFAllowCount:      intPtr(2),
		CSFFork:            strPtr("sentinel"),
		CSFForkEvidence:    []string{"downloadservers:sentinel"},
		CSFTesting:         boolPtr(false),
		CSFAutoUpdates:     nil, // tri-state: never collected (e.g. key removed upstream in cpanel-csf 16.x)
		CSFAutoUpdatesCron: boolPtr(false),
		CSFLFDaemon:        boolPtr(true),
		CSFLFDRunning:      boolPtr(true),
		CSFIPv6:            boolPtr(false),
		CSFDownloadServers: []string{"raw.githubusercontent.com/example/sentinelfw/refs/heads/main/"},
		CSFDenyIPLimit:     intPtr(200),
		CSFDenyTempIPLimit: intPtr(100),
		CSFListsHash:       strPtr(strings.Repeat("a", 64)),
		CSFListsTruncated:  boolPtr(false),
	}
}

func heartbeatCSFPresent() HeartbeatRequest {
	hb := baseHeartbeat()
	hb.CSFHeartbeatFields = csfPresentFields()
	hb.CSFPaused = boolPtr(false)
	return hb
}

func heartbeatNoCSF() HeartbeatRequest {
	return baseHeartbeat()
}

// heartbeatCSFRemoved represents a host where CSF was installed, seen at
// least once, then uninstalled: csf_installed:false is explicit (distinct
// from heartbeatNoCSF's total absence of any csf_ key — COL-06's other half).
func heartbeatCSFRemoved() HeartbeatRequest {
	hb := baseHeartbeat()
	hb.CSFHeartbeatFields = &CSFHeartbeatFields{CSFInstalled: false}
	return hb
}

// heartbeatCSFPaused represents the kill switch being on: no collector facts
// are sent (CSF stays nil) but csf_paused:true is still reported so the panel
// can show "paused" rather than silence.
func heartbeatCSFPaused() HeartbeatRequest {
	hb := baseHeartbeat()
	hb.CSFPaused = boolPtr(true)
	return hb
}

func csfListsUploadPayload() CSFListsRequest {
	return CSFListsRequest{
		Hash:        strings.Repeat("b", 64),
		CollectedAt: fixedTimestamp,
		Deny: CSFListPayload{
			Total:     2,
			Truncated: false,
			Entries: []CSFListEntryPayload{
				{Value: "198.51.100.7", Kind: "ip", Comment: "Repeat SSH brute force"},
				{Value: "tcp|in|d=22|s=198.51.100.7", Kind: "advanced", Comment: ""},
			},
		},
		Allow: CSFListPayload{
			Total:     1,
			Truncated: false,
			Entries: []CSFListEntryPayload{
				{Value: "192.0.2.10", Kind: "ip", Comment: "lab-panel"},
			},
		},
	}
}

func csfPortEvents() []EventRequest {
	return []EventRequest{
		{
			Type:     "csf_port_changed",
			Severity: "info",
			Details: map[string]string{
				"port":      "8080",
				"direction": "in",
				"action":    "add",
				"action_id": "6f1c1e2a-0000-4000-8000-000000000001",
				"result":    "applied",
			},
			OccurredAt: fixedTimestamp,
		},
		{
			Type:     "csf_port_error",
			Severity: "critical",
			Details: map[string]string{
				"port":          "2222",
				"direction":     "in",
				"action":        "remove",
				"action_id":     "6f1c1e2a-0000-4000-8000-000000000002",
				"result":        "rollback_failed",
				"reason":        "health check failed and rollback could not restore the backup",
				"rolled_back":   "false",
				"backup":        "/etc/csf/csf.conf.bak.20261105100000",
				"ipv6_mirrored": "false",
				"testing_mode":  "false",
				"error":         "backup restore: permission denied",
			},
			OccurredAt: fixedTimestamp,
		},
		{
			// Old agent (pre-15-04/15-06) shape: no action_id at all, because
			// the sync item it reacted to never carried an id either.
			Type:     "csf_port_error",
			Severity: "warning",
			Details: map[string]string{
				"port":      "9090",
				"direction": "out",
				"action":    "add",
				"error":     "csf -a failed: exit status 1",
			},
			OccurredAt: fixedTimestamp,
		},
	}
}

func TestContractGolden(t *testing.T) {
	compareOrUpdateGolden(t, "heartbeat_csf_present.json", heartbeatCSFPresent())
	compareOrUpdateGolden(t, "heartbeat_nocsf.json", heartbeatNoCSF())
	compareOrUpdateGolden(t, "heartbeat_csf_removed.json", heartbeatCSFRemoved())
	compareOrUpdateGolden(t, "heartbeat_csf_paused.json", heartbeatCSFPaused())
	compareOrUpdateGolden(t, "csf_lists_upload.json", csfListsUploadPayload())
	compareOrUpdateGolden(t, "csf_port_events.json", csfPortEvents())
}

// --- Tri-state / omitempty-trap behavior tests ---

func TestHeartbeatNoCSFHasNoCSFKeys(t *testing.T) {
	data, err := json.Marshal(heartbeatNoCSF())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for k := range rawKeys(t, data) {
		if strings.HasPrefix(k, "csf_") {
			t.Errorf("heartbeat with no CSF data must have no csf_ key, found %q in %s", k, data)
		}
	}
}

func TestHeartbeatCSFPresentFalseZeroSent(t *testing.T) {
	data, err := json.Marshal(heartbeatCSFPresent())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	keys := rawKeys(t, data)

	wantRaw := map[string]string{
		"csf_installed":       "true",
		"csf_testing":         "false",
		"csf_deny_count":      "12",
		"csf_lists_truncated": "false",
		"csf_paused":          "false",
	}
	for key, want := range wantRaw {
		raw, ok := keys[key]
		if !ok {
			t.Errorf("expected key %q to be present, got none (keys: %s)", key, data)
			continue
		}
		if string(raw) != want {
			t.Errorf("key %q = %s, want %s", key, raw, want)
		}
	}
}

func TestHeartbeatTriStateNull(t *testing.T) {
	data, err := json.Marshal(heartbeatCSFPresent())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	keys := rawKeys(t, data)

	raw, ok := keys["csf_auto_updates"]
	if !ok {
		t.Fatalf("csf_auto_updates key must be present (even when never collected), got none in %s", data)
	}
	if string(raw) != "null" {
		t.Errorf("csf_auto_updates = %s, want explicit null", raw)
	}
}

func TestHeartbeatCSFRemovedSendsFalse(t *testing.T) {
	data, err := json.Marshal(heartbeatCSFRemoved())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	keys := rawKeys(t, data)

	if raw, ok := keys["csf_installed"]; !ok || string(raw) != "false" {
		t.Errorf("csf_installed = %v (present=%v), want explicit false", raw, ok)
	}

	otherCSFKeys := []string{
		"csf_version", "csf_ports_in", "csf_ports_out", "csf_deny_count",
		"csf_allow_count", "csf_fork", "csf_fork_evidence", "csf_testing",
		"csf_auto_updates", "csf_auto_updates_cron", "csf_lf_daemon",
		"csf_lfd_running", "csf_ipv6", "csf_download_servers",
		"csf_deny_ip_limit", "csf_deny_temp_ip_limit", "csf_lists_hash",
		"csf_lists_truncated",
	}
	for _, key := range otherCSFKeys {
		raw, ok := keys[key]
		if !ok {
			t.Errorf("removed-CSF payload must still carry key %q (as null), got none", key)
			continue
		}
		if string(raw) != "null" {
			t.Errorf("key %q = %s, want null on a removed-CSF payload", key, raw)
		}
	}

	if _, ok := keys["csf_paused"]; ok {
		t.Errorf("removed-CSF payload must not carry csf_paused, got %s", keys["csf_paused"])
	}
}

func TestHeartbeatPausedOnly(t *testing.T) {
	data, err := json.Marshal(heartbeatCSFPaused())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	keys := rawKeys(t, data)

	var csfKeys []string
	for k := range keys {
		if strings.HasPrefix(k, "csf_") {
			csfKeys = append(csfKeys, k)
		}
	}
	if len(csfKeys) != 1 || csfKeys[0] != "csf_paused" {
		t.Fatalf("paused-only heartbeat must carry exactly one csf_ key (csf_paused), got %v", csfKeys)
	}
	if string(keys["csf_paused"]) != "true" {
		t.Errorf("csf_paused = %s, want true", keys["csf_paused"])
	}
}

// --- Sync decoding: old panel vs new panel ---

func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(goldenPath(name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return data
}

func TestSyncOldPanelPayload(t *testing.T) {
	var sync SyncResponse
	if err := json.Unmarshal(readGolden(t, "sync_old_panel.json"), &sync); err != nil {
		t.Fatalf("unmarshal sync_old_panel.json: %v", err)
	}

	if len(sync.CSFPortActions) != 1 {
		t.Fatalf("want exactly 1 csf_port_action, got %d", len(sync.CSFPortActions))
	}
	action := sync.CSFPortActions[0]
	if action.ID != "" {
		t.Errorf("old-panel action.ID = %q, want empty (no id key sent)", action.ID)
	}
	if action.Port != 8080 || action.Direction != "in" || action.Action != "add" {
		t.Errorf("unexpected action: %+v", action)
	}

	if sync.CSFIntegrationDisabled != nil {
		t.Errorf("old-panel sync must decode csf_integration_disabled as nil (key absent), got %v", *sync.CSFIntegrationDisabled)
	}
}

func TestSyncNewPanelPayload(t *testing.T) {
	var sync SyncResponse
	if err := json.Unmarshal(readGolden(t, "sync_new_panel.json"), &sync); err != nil {
		t.Fatalf("unmarshal sync_new_panel.json: %v", err)
	}

	if len(sync.CSFPortActions) != 1 {
		t.Fatalf("want exactly 1 csf_port_action, got %d", len(sync.CSFPortActions))
	}
	action := sync.CSFPortActions[0]
	if action.ID == "" {
		t.Errorf("new-panel action.ID must be set, got empty")
	}

	if sync.CSFIntegrationDisabled == nil {
		t.Fatalf("new-panel sync must decode csf_integration_disabled as a non-nil bool")
	}
	if *sync.CSFIntegrationDisabled != false {
		t.Errorf("csf_integration_disabled = %v, want false", *sync.CSFIntegrationDisabled)
	}
}

// --- Lists upload client ---

func TestUploadCSFListsOldPanel404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "test-token")
	err := c.UploadCSFLists(csfListsUploadPayload())
	if err == nil {
		t.Fatalf("expected an error from a 404 response, got nil")
	}

	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("expected *HTTPError, got %T: %v", err, err)
	}
	if httpErr.Status != http.StatusNotFound {
		t.Errorf("Status = %d, want 404", httpErr.Status)
	}
}

func TestUploadCSFListsSendsBearerAndBody(t *testing.T) {
	var gotPath, gotMethod, gotAuth string
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(srv.URL, "secret-token")
	if err := c.UploadCSFLists(csfListsUploadPayload()); err != nil {
		t.Fatalf("UploadCSFLists: %v", err)
	}

	if gotPath != "/api/v1/agent/csf/lists" {
		t.Errorf("path = %q, want /api/v1/agent/csf/lists", gotPath)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotAuth != "Bearer secret-token" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer secret-token")
	}
	for _, key := range []string{"hash", "collected_at", "deny", "allow"} {
		if _, ok := gotBody[key]; !ok {
			t.Errorf("request body missing key %q: %v", key, gotBody)
		}
	}
}

func TestUploadCSFListsTooManyEntriesNeverSends(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	req := csfListsUploadPayload()
	entries := make([]CSFListEntryPayload, csfListsMaxEntries+1)
	for i := range entries {
		entries[i] = CSFListEntryPayload{Value: "203.0.113.1", Kind: "ip"}
	}
	req.Deny.Entries = entries

	c := New(srv.URL, "test-token")
	err := c.UploadCSFLists(req)
	if err == nil {
		t.Fatalf("expected ErrCSFListsTooLarge, got nil")
	}
	if err != ErrCSFListsTooLarge {
		t.Errorf("err = %v, want ErrCSFListsTooLarge", err)
	}
	if called {
		t.Errorf("UploadCSFLists must not make an HTTP request when over the entry cap")
	}
}
