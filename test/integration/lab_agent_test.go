//go:build integration

package integration

import (
	"testing"
	"time"
)

// TestLabAgentServiceActive asserts the defensia-agent systemd unit is
// active when LAB_EXPECT_AGENT=1.
func TestLabAgentServiceActive(t *testing.T) {
	requireRoot(t)
	if requireEnv(t, "LAB_EXPECT_AGENT") != "1" {
		return
	}
	out, _ := sh(t, "systemctl", "is-active", "defensia-agent")
	if out != "active" {
		t.Fatalf("systemctl is-active defensia-agent = %q, want active", out)
	}
}

// labServer mirrors the subset of the panel's Agent JSON this suite
// reads (GET /api/v1/servers/{id}).
type labServer struct {
	Name       string `json:"name"`
	LastSeenAt string `json:"last_seen_at"`
}

// parseServerTimestamp parses the panel's last_seen_at, trying both
// time.RFC3339Nano and Carbon's default microsecond JSON format.
func parseServerTimestamp(s string) (time.Time, error) {
	formats := []string{time.RFC3339Nano, "2006-01-02T15:04:05.000000Z"}
	var lastErr error
	for _, f := range formats {
		if parsed, err := time.Parse(f, s); err == nil {
			return parsed, nil
		} else {
			lastErr = err
		}
	}
	return time.Time{}, lastErr
}

// TestLabAgentHeartbeat asserts the panel has seen this VM's agent within
// the last 180s, via GET /api/v1/servers/{id}.
func TestLabAgentHeartbeat(t *testing.T) {
	requireEnv(t, "LAB_PANEL_URL")
	requireEnv(t, "LAB_PANEL_TOKEN")
	vm := requireEnv(t, "LAB_VM")

	id := readAgentConfig(t)

	var server labServer
	panelGet(t, "/api/v1/servers/"+id, &server)

	if server.Name != vm {
		t.Fatalf("GET /api/v1/servers/%s name = %q, want %q", id, server.Name, vm)
	}

	seen, err := parseServerTimestamp(server.LastSeenAt)
	if err != nil {
		t.Fatalf("parse last_seen_at %q: %v", server.LastSeenAt, err)
	}
	if age := time.Since(seen); age > 180*time.Second {
		t.Fatalf("last_seen_at age = %s, want <= 180s", age)
	}
}
