//go:build integration

package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// env returns the trimmed value of the environment variable k.
func env(k string) string {
	return strings.TrimSpace(os.Getenv(k))
}

// requireEnv returns the value of k. When k is unset/empty it either
// skips the test (LAB_ALLOW_SKIP=1 — CI, no lab/panel available) or fails
// it outright (the lab always sets every LAB_* var via lab/test.sh, so an
// empty value there means the harness itself is broken, not a legitimate
// "not applicable" case).
func requireEnv(t *testing.T, k string) string {
	t.Helper()
	v := env(k)
	if v == "" {
		if env("LAB_ALLOW_SKIP") == "1" {
			t.Skipf("LAB %s not set (CI)", k)
		}
		t.Fatalf("lab env %s is required (run via make lab-test)", k)
	}
	return v
}

// requireRoot fails the test if it is not running as root — CSF/systemd
// state is only readable as root.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatalf("test must run as root (euid=%d)", os.Geteuid())
	}
}

// sh runs name with args and returns its combined, trimmed output.
func sh(t *testing.T, name string, args ...string) (string, error) {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// agentConfig mirrors the subset of /etc/defensia/config.json this suite
// reads. agent_id is decoded as raw JSON (not int64) because it may be
// written as a bare number or a quoted string depending on installer
// version — readAgentConfig normalizes either shape.
type agentConfig struct {
	ServerURL string          `json:"server_url"`
	AgentID   json.RawMessage `json:"agent_id"`
}

// readAgentConfig reads /etc/defensia/config.json and returns the
// agent_id as a plain decimal string, stripped of surrounding quotes.
func readAgentConfig(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("/etc/defensia/config.json")
	if err != nil {
		t.Fatalf("read /etc/defensia/config.json: %v", err)
	}
	var cfg agentConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse /etc/defensia/config.json: %v", err)
	}
	id := strings.Trim(strings.TrimSpace(string(cfg.AgentID)), `"`)
	if id == "" {
		t.Fatalf("/etc/defensia/config.json has no agent_id")
	}
	return id
}

// panelGet performs an authenticated GET against LAB_PANEL_URL+path and
// decodes the JSON response body into out. Fails the test on any
// non-2xx status or JSON decode error.
func panelGet(t *testing.T, path string, out any) {
	t.Helper()
	url := env("LAB_PANEL_URL") + path
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("panelGet %s: build request: %v", path, err)
	}
	req.Header.Set("Authorization", "Bearer "+requireEnv(t, "LAB_PANEL_TOKEN"))
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("panelGet %s: %v", path, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := body
		if len(snippet) > 300 {
			snippet = snippet[:300]
		}
		t.Fatalf("panelGet %s: status %d: %s", path, resp.StatusCode, snippet)
	}
	if err := json.Unmarshal(body, out); err != nil {
		t.Fatalf("panelGet %s: decode: %v", path, err)
	}
}
