package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// oldPanelFirewallModes documents origin/main's heartbeat validation rule
// (AgentController, pre-phase-17): firewall_mode was `in:ipset,iptables`.
// Any other value — nftables, none — was rejected with a 422 that aborted
// the WHOLE heartbeat, not just the firewall_mode field.
const oldPanelFirewallModes = "in:ipset,iptables"

// oldPanelHandler emulates the origin/main panel: 422 (Laravel validation
// shape) if firewall_mode is present and not in {ipset, iptables}; otherwise
// 200. Returns the handler and a pointer to the received-request counter.
func oldPanelHandler(t *testing.T, requests *[]map[string]any) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("reading request body: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(body, &m); err != nil {
			t.Fatalf("unmarshal request body: %v", err)
		}
		*requests = append(*requests, m)

		mode, _ := m["firewall_mode"].(string)
		if mode != "" && mode != "ipset" && mode != "iptables" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"message":"The selected firewall mode is invalid.","errors":{"firewall_mode":["The selected firewall mode is invalid."]}}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"online","last_seen_at":"2026-11-17T12:00:00Z"}`))
	}
}

// newPanelHandler emulates a phase-17 panel: accepts every firewall_mode.
func newPanelHandler(t *testing.T, requests *[]map[string]any) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("reading request body: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(body, &m); err != nil {
			t.Fatalf("unmarshal request body: %v", err)
		}
		*requests = append(*requests, m)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"online","last_seen_at":"2026-11-17T12:00:00Z"}`))
	}
}

func TestHeartbeatOldPanelRejectsNftablesThenRetriesWithoutMode(t *testing.T) {
	for _, mode := range []string{"nftables", "none"} {
		t.Run(mode, func(t *testing.T) {
			var requests []map[string]any
			srv := httptest.NewServer(oldPanelHandler(t, &requests))
			defer srv.Close()

			c := New(srv.URL, "test-token")
			resp, err := c.Heartbeat(HeartbeatRequest{Status: "online", FirewallMode: mode, BanCapacity: 65536, ActiveBans: 3})
			if err != nil {
				t.Fatalf("Heartbeat: %v", err)
			}
			if resp.Status != "online" {
				t.Fatalf("resp.Status = %q, want online", resp.Status)
			}
			if len(requests) != 2 {
				t.Fatalf("server saw %d requests, want 2", len(requests))
			}
			second := requests[1]
			for _, key := range []string{"firewall_mode", "ban_capacity", "active_bans"} {
				if _, present := second[key]; present {
					t.Fatalf("2nd request body still has %q: %+v", key, second)
				}
			}
		})
	}
}

func TestHeartbeatNewPanelAcceptsNftablesSingleRequest(t *testing.T) {
	var requests []map[string]any
	srv := httptest.NewServer(newPanelHandler(t, &requests))
	defer srv.Close()

	c := New(srv.URL, "test-token")
	_, err := c.Heartbeat(HeartbeatRequest{Status: "online", FirewallMode: "nftables", BanCapacity: 65536, ActiveBans: 1})
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if len(requests) != 1 {
		t.Fatalf("server saw %d requests, want 1", len(requests))
	}
	if got, _ := requests[0]["firewall_mode"].(string); got != "nftables" {
		t.Fatalf("request firewall_mode = %q, want nftables", got)
	}
}

func TestHeartbeatNoRetryForOtherFailures(t *testing.T) {
	t.Run("422 but firewall_mode is already a valid old value", func(t *testing.T) {
		var requests []map[string]any
		srv := httptest.NewServer(oldPanelHandler(t, &requests))
		defer srv.Close()

		c := New(srv.URL, "test-token")
		// ipset is accepted by the old panel's rule, so this should never 422
		// in the first place — if it somehow did, there must be no retry
		// (the fallback only triggers for nftables/none).
		_, err := c.Heartbeat(HeartbeatRequest{Status: "online", FirewallMode: "ipset"})
		if err != nil {
			t.Fatalf("Heartbeat: %v", err)
		}
		if len(requests) != 1 {
			t.Fatalf("server saw %d requests, want 1", len(requests))
		}
	})

	t.Run("422 without a firewall_mode field in the body", func(t *testing.T) {
		var requests []map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			var m map[string]any
			_ = json.Unmarshal(body, &m)
			requests = append(requests, m)
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"message":"The version field is required.","errors":{"version":["The version field is required."]}}`))
		}))
		defer srv.Close()

		c := New(srv.URL, "test-token")
		_, err := c.Heartbeat(HeartbeatRequest{Status: "online", FirewallMode: "nftables"})
		if err == nil {
			t.Fatalf("Heartbeat: want an error (unrelated 422 must not trigger the fallback)")
		}
		if len(requests) != 1 {
			t.Fatalf("server saw %d requests, want 1 (no retry for an unrelated 422)", len(requests))
		}
	})

	t.Run("500 is never retried", func(t *testing.T) {
		var requests []map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			var m map[string]any
			_ = json.Unmarshal(body, &m)
			requests = append(requests, m)
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"message":"internal error"}`))
		}))
		defer srv.Close()

		c := New(srv.URL, "test-token")
		_, err := c.Heartbeat(HeartbeatRequest{Status: "online", FirewallMode: "nftables"})
		if err == nil {
			t.Fatalf("Heartbeat: want an error")
		}
		if len(requests) != 1 {
			t.Fatalf("server saw %d requests, want 1", len(requests))
		}
	})
}

func TestHeartbeatLegacyWarningLoggedOnce(t *testing.T) {
	var requests []map[string]any
	srv := httptest.NewServer(oldPanelHandler(t, &requests))
	defer srv.Close()

	c := New(srv.URL, "test-token")

	var logBuf bytes.Buffer
	origOutput := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(origOutput)

	if _, err := c.Heartbeat(HeartbeatRequest{Status: "online", FirewallMode: "nftables"}); err != nil {
		t.Fatalf("Heartbeat 1: %v", err)
	}
	if _, err := c.Heartbeat(HeartbeatRequest{Status: "online", FirewallMode: "none"}); err != nil {
		t.Fatalf("Heartbeat 2: %v", err)
	}

	n := strings.Count(logBuf.String(), "[api] panel rejected firewall_mode")
	if n != 1 {
		t.Fatalf("log line printed %d times, want exactly 1:\n%s", n, logBuf.String())
	}
}

func TestHeartbeatJSONNoneMode(t *testing.T) {
	data, err := json.Marshal(HeartbeatRequest{FirewallMode: "none"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, `"firewall_mode":"none"`) {
		t.Fatalf("JSON = %s, want it to contain \"firewall_mode\":\"none\"", s)
	}
	if strings.Contains(s, "ban_capacity") || strings.Contains(s, "active_bans") {
		t.Fatalf("JSON = %s, want neither ban_capacity nor active_bans (both zero-value omitempty)", s)
	}
}
