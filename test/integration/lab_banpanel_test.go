//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// panelDo performs an authenticated HTTP call against LAB_PANEL_URL+path
// (same bearer-token auth as panelGet) with an optional JSON body, and
// best-effort decodes the response body into out regardless of status —
// unlike panelGet, it never Fatals on a non-2xx status, since this suite
// deliberately exercises 422/403 paths and needs their response bodies.
//
// It retries internally on 429: the panel's `dashboard-api` rate limiter
// (60 req/min) is keyed by user ID, not per-token or per-endpoint, so it is
// shared across every GET/POST/DELETE this test's token makes across the
// whole run — individual call-site pacing (sleeps between POSTs, wider poll
// intervals) kept chasing 429s to a DIFFERENT call site every time it fixed
// the last one. Lab-measured, alma9-csf-orig, phase 18-11. A fixed per-call
// pace can't work when the budget is shared and the call volume varies by
// phase of the test; retrying the 429 itself is the only fix that holds
// regardless of which call site happens to be the one that trips it.
func panelDo(t *testing.T, method, path string, body any, out any) int {
	t.Helper()
	url := env("LAB_PANEL_URL") + path

	var bodyBytes []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("panelDo %s %s: marshal body: %v", method, path, err)
		}
		bodyBytes = b
	}

	const maxAttempts = 5
	var status int
	var respBody []byte
	for attempt := 0; attempt < maxAttempts; attempt++ {
		var reqBody io.Reader
		if bodyBytes != nil {
			reqBody = bytes.NewReader(bodyBytes)
		}
		req, err := http.NewRequest(method, url, reqBody)
		if err != nil {
			t.Fatalf("panelDo %s %s: build request: %v", method, path, err)
		}
		req.Header.Set("Authorization", "Bearer "+requireEnv(t, "LAB_PANEL_TOKEN"))
		req.Header.Set("Accept", "application/json")
		if bodyBytes != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("panelDo %s %s: %v", method, path, err)
		}
		status = resp.StatusCode
		respBody, _ = io.ReadAll(resp.Body)
		resp.Body.Close()

		if status != 429 {
			break
		}
		// Rate-limited: back off and retry rather than failing the whole
		// test — this limiter's 60/min window is shared and bursts are
		// expected (SIGKILL-recovery polling, 30-ban batches, etc).
		time.Sleep(2 * time.Second)
	}

	if out != nil && len(respBody) > 0 {
		_ = json.Unmarshal(respBody, out) // best-effort; caller decides what status means
	}
	return status
}

// installLabBanDropIn writes a systemd drop-in overriding the real
// defensia-agent service's env (fast sync interval for the lab, optionally
// pointed at the fake csf binary), reloads systemd and restarts the agent.
// Removed + reloaded + restarted again at t.Cleanup, per the plan's own
// interface spec.
func installLabBanDropIn(t *testing.T, extra map[string]string) {
	t.Helper()
	lines := []string{"[Service]", "Environment=DEFENSIA_SYNC_INTERVAL_SECONDS=15"}
	for k, v := range extra {
		lines = append(lines, fmt.Sprintf("Environment=%s=%s", k, v))
	}
	const dir = "/etc/systemd/system/defensia-agent.service.d"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	path := dir + "/lab-ban.conf"
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if out, err := sh(t, "systemctl", "daemon-reload"); err != nil {
		t.Fatalf("daemon-reload: %v (%s)", err, out)
	}
	restartAgent(t)

	t.Cleanup(func() {
		os.Remove(path)
		sh(t, "systemctl", "daemon-reload")
		restartAgent(t)
	})
}

// banExecutorShow is the JSON shape of GET /servers/{id}/ban-executor.
type banExecutorShow struct {
	BanExecutor      string         `json:"ban_executor"`
	BanExecutorState map[string]any `json:"ban_executor_state"`
	UndoStatus       string         `json:"undo_status"`
	Preflight        struct {
		Blockers []string `json:"blockers"`
	} `json:"preflight"`
}

// panelBanResponse is the JSON shape of a successful POST /bans response.
type panelBanResponse struct {
	ID int64 `json:"id"`
}

// switchExecutor retries PUT .../ban-executor until it succeeds or the
// deadline passes, surfacing the panel's own blocker list on failure.
// Needed every time this test asks for "csf": ban_executor_state going
// non-null on a freshly (re)started agent does NOT mean csf_ready is
// true yet — the panel's own preflight check ("csf_not_ready") can still
// 422 a switch attempted the instant the state first appears, and the
// SAME gap re-opens briefly after any later agent restart (e.g. the
// SIGKILL recovery below) — lab-measured, alma9-csf-orig, phase 18-11:
// both the very first switch and the post-SIGKILL one hit this.
//
// 150s, not 90s: a cold start of the FULL lab matrix (10 VMs registering
// and syncing against the same panel at once) measurably slows this
// specific VM's own first few sync cycles beyond what 90s of retrying
// absorbs — lab-measured, alma9-csf-orig, phase 18-11, full-matrix run.
// In isolation this resolves within the first one or two retries.
func switchExecutor(t *testing.T, execPath, executor string, timeout time.Duration) {
	t.Helper()
	var lastErr struct {
		Errors struct {
			Executor []string `json:"executor"`
		} `json:"errors"`
	}
	lastStatus := 0
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		lastErr.Errors.Executor = nil
		lastStatus = panelDo(t, "PUT", execPath, map[string]string{"executor": executor}, &lastErr)
		if lastStatus == 200 {
			return
		}
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("PUT ban-executor %s = %d after %s of retrying, want 200; last blockers: %v", executor, lastStatus, timeout, lastErr.Errors.Executor)
}

// TestLabBanPanelEndToEnd (SYNC-01/02/05/06/07, plan 11): closes the loop
// through the real panel API, the real running defensia-agent service and
// real CSF — nothing in-process, nothing stopped. The only other ban-sync
// suite that leaves the real agent service running throughout.
func TestLabBanPanelEndToEnd(t *testing.T) {
	requireRoot(t)
	requireEnv(t, "LAB_PANEL_URL")
	requireEnv(t, "LAB_PANEL_TOKEN")
	id := readAgentConfig(t)

	// Every VM: the last heartbeat was accepted (proves no lab agent's
	// executor state is rejected by this panel, incl. its heartbeat
	// sanitizer from 18-03/18-09).
	var srv map[string]any
	if status := panelDo(t, "GET", "/api/v1/servers/"+id, nil, &srv); status != 200 {
		t.Fatalf("GET /servers/%s = %d", id, status)
	}
	lastSeen, ok := parsePanelTime(fmt.Sprint(srv["last_seen_at"]))
	if !ok {
		t.Fatalf("last_seen_at = %v, could not parse", srv["last_seen_at"])
	}
	if age := time.Since(lastSeen); age > 2*time.Minute {
		t.Errorf("last_seen_at age = %s, want < 2m — this lab agent's heartbeat may have been rejected", age)
	}

	execPath := "/api/v1/servers/" + id + "/ban-executor"

	if !isCSFVM() {
		var errBody struct {
			Errors struct {
				Executor []string `json:"executor"`
			} `json:"errors"`
		}
		status := panelDo(t, "PUT", execPath, map[string]string{"executor": "csf"}, &errBody)
		if status != 422 {
			t.Fatalf("PUT ban-executor csf on non-CSF VM = %d, want 422", status)
		}
		if !containsStr(errBody.Errors.Executor, "csf_not_installed") {
			t.Errorf("errors.executor = %v, want to contain csf_not_installed", errBody.Errors.Executor)
		}
		return
	}

	if env("LAB_EXPECT_TESTING") == "1" {
		var errBody struct {
			Errors struct {
				Executor []string `json:"executor"`
			} `json:"errors"`
		}
		status := panelDo(t, "PUT", execPath, map[string]string{"executor": "csf"}, &errBody)
		if status != 422 {
			t.Fatalf("PUT ban-executor csf on TESTING=1 VM = %d, want 422", status)
		}
		if !containsStr(errBody.Errors.Executor, "csf_testing_mode") {
			t.Errorf("errors.executor = %v, want to contain csf_testing_mode", errBody.Errors.Executor)
		}
		return
	}

	// Writable CSF VM: real agent, real CSF, driven entirely through the
	// panel API from here on.
	installLabBanDropIn(t, nil)
	cleanupTagged(t)

	// 3s, not 1s: every poll below that calls panelDo shares the panel's
	// own dashboard-api rate limiter (60 req/min per token, keyed across
	// EVERY call this test's token makes, GET and POST and DELETE alike)
	// with the ban POSTs further down — a 1s interval alone would exhaust
	// it before ever reaching those. Lab-measured, alma9-csf-orig, phase
	// 18-11: "POST /bans ... = 429, want 201" partway through the SIGKILL
	// section's 30-ban batch, purely from cumulative GETs in these polls.
	poll(t, 150*time.Second, 3*time.Second, func() bool {
		var sh banExecutorShow
		if status := panelDo(t, "GET", execPath, nil, &sh); status != 200 {
			return false
		}
		return sh.BanExecutorState != nil
	}, "ban_executor_state non-null")

	t.Cleanup(func() {
		panelDo(t, "PUT", execPath, map[string]string{"executor": "defensia"}, nil)
	})

	switchExecutor(t, execPath, "csf", 150*time.Second)

	ips := banIPs(t, 3)
	var banIDs []int64
	for _, ip := range ips {
		var resp panelBanResponse
		status := panelDo(t, "POST", "/api/v1/bans", map[string]any{
			"ip_address": ip, "reason": "lab_e2e", "server_id": mustAtoi(t, id),
			"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		}, &resp)
		if status != 201 {
			t.Fatalf("POST /bans %s = %d, want 201", ip, status)
		}
		banIDs = append(banIDs, resp.ID)
	}
	t.Cleanup(func() {
		for _, bid := range banIDs {
			panelDo(t, "DELETE", "/api/v1/bans/"+strconv.FormatInt(bid, 10), nil, nil)
		}
	})

	poll(t, 150*time.Second, 3*time.Second, func() bool {
		tagged := taggedSet(readTempban(t))
		for _, ip := range ips {
			if !tagged[ip] {
				return false
			}
		}
		members := backendMembers(t)
		for _, ip := range ips {
			if members[ip] {
				return false
			}
		}
		var sh banExecutorShow
		panelDo(t, "GET", execPath, nil, &sh)
		effMode, _ := sh.BanExecutorState["effective_mode"].(string)
		return effMode == "csf"
	}, "3 bans tagged, none on the Defensia backend, effective_mode csf")

	for _, l := range readTempban(t) {
		if l.IP == ips[0] {
			if !strings.HasPrefix(l.Comment, "defensia:lab_e2e") {
				t.Errorf("%s comment = %q, want defensia:lab_e2e", ips[0], l.Comment)
			}
		}
	}

	if status := panelDo(t, "DELETE", "/api/v1/bans/"+strconv.FormatInt(banIDs[0], 10), nil, nil); status != 200 {
		t.Fatalf("DELETE /bans/%d = %d, want 200", banIDs[0], status)
	}
	deletedIP := ips[0]
	poll(t, 120*time.Second, time.Second, func() bool {
		return !taggedSet(readTempban(t))[deletedIP]
	}, "deleted ban gone from tempban")

	// --- SIGKILL mid-switch: the real systemd service, not an in-process
	// context cancel — proves state-file resume across a real crash.
	more := banIPs(t, 30)
	var moreIDs []int64
	for i, ip := range more {
		var resp panelBanResponse
		status := panelDo(t, "POST", "/api/v1/bans", map[string]any{
			"ip_address": ip, "reason": "lab_e2e", "server_id": mustAtoi(t, id),
			"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		}, &resp)
		if status != 201 {
			t.Fatalf("POST /bans %s = %d, want 201", ip, status)
		}
		moreIDs = append(moreIDs, resp.ID)
		// Pace well under the 60 req/min dashboard-api limiter shared with
		// every other panelDo call this test makes.
		if i < len(more)-1 {
			time.Sleep(1200 * time.Millisecond)
		}
	}
	t.Cleanup(func() {
		for _, bid := range moreIDs {
			panelDo(t, "DELETE", "/api/v1/bans/"+strconv.FormatInt(bid, 10), nil, nil)
		}
	})
	allDesired := append(append([]string{}, ips[1:]...), more...)

	poll(t, 120*time.Second, 200*time.Millisecond, func() bool {
		return len(taggedSet(readTempban(t))) >= 30
	}, "tagged >= 30 before SIGKILL")

	if status := panelDo(t, "PUT", execPath, map[string]string{"executor": "defensia"}, nil); status != 200 {
		t.Fatalf("PUT ban-executor defensia = %d, want 200", status)
	}

	// 180s, not 60s: migrating 30 entries back to the defensia backend is a
	// make-before-break sequence (confirm each on the defensia backend,
	// THEN -tr it off CSF) that drains at the same ticker cadence as every
	// other reconcile pass — under full-matrix load (10 VMs sharing one
	// OrbStack host, csf-tuning.md's own documented constraint) a single
	// VM's pass can legitimately take longer than a quiet single-VM run
	// does. Lab-measured, alma10-noipset, phase 18-11: timed out at 60s
	// under full-matrix load; passed in isolation.
	poll(t, 180*time.Second, 200*time.Millisecond, func() bool {
		return len(taggedSet(readTempban(t))) < 30
	}, "tagged dropped below 30 (switch-back started)")

	if out, err := sh(t, "systemctl", "kill", "-s", "KILL", "defensia-agent"); err != nil {
		t.Fatalf("systemctl kill -s KILL defensia-agent: %v (%s)", err, out)
	}

	active := false
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if out, _ := sh(t, "systemctl", "is-active", "defensia-agent"); out == "active" {
			active = true
			break
		}
		time.Sleep(time.Second)
	}
	if !active {
		t.Logf("FINDING: defensia-agent did not auto-restart within 30s of SIGKILL; starting it manually")
		if out, err := sh(t, "systemctl", "start", "defensia-agent"); err != nil {
			t.Fatalf("systemctl start defensia-agent (after SIGKILL, no auto-restart): %v (%s)", err, out)
		}
	}

	violations := 0
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(300 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				members := backendMembers(t)
				tagged := taggedSet(readTempban(t))
				for _, ip := range allDesired {
					if !members[ip] && !tagged[ip] {
						violations++
					}
				}
			}
		}
	}()

	poll(t, 180*time.Second, time.Second, func() bool {
		tagged := taggedSet(readTempban(t))
		if len(tagged) != 0 {
			return false
		}
		members := backendMembers(t)
		for _, ip := range allDesired {
			if !members[ip] {
				return false
			}
		}
		return true
	}, "post-SIGKILL convergence to defensia (tagged 0, all desired on the backend)")

	close(stop)
	<-done
	if violations > 0 {
		t.Errorf("SIGKILL mid-switch gap violations = %d, want 0", violations)
	}

	// --- Undo all
	// The agent just restarted (SIGKILL recovery above); switchExecutor's
	// own retry covers the same transient csf_not_ready window as the
	// very first switch above.
	switchExecutor(t, execPath, "csf", 150*time.Second)
	poll(t, 120*time.Second, time.Second, func() bool {
		tagged := taggedSet(readTempban(t))
		for _, ip := range allDesired {
			if !tagged[ip] {
				return false
			}
		}
		return true
	}, "all desired tagged before undo")

	foreign := banIPs(t, 1)
	seedForeign(t, foreign, time.Hour, "manual")

	if status := panelDo(t, "POST", execPath+"/undo", nil, nil); status != 200 {
		t.Fatalf("POST ban-executor/undo = %d, want 200", status)
	}

	poll(t, 180*time.Second, 3*time.Second, func() bool {
		var sh banExecutorShow
		if status := panelDo(t, "GET", execPath, nil, &sh); status != 200 {
			return false
		}
		if sh.UndoStatus != "completed" {
			return false
		}
		if len(taggedSet(readTempban(t))) != 0 {
			return false
		}
		members := backendMembers(t)
		for _, ip := range allDesired {
			if !members[ip] {
				return false
			}
		}
		return true
	}, "undo_status completed, tagged 0, backendMembers has all desired")

	finalForeign := foreignSet(readTempban(t))
	for _, ip := range foreign {
		if !finalForeign[ip] {
			t.Errorf("foreign %s missing after undo", ip)
		}
	}
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("mustAtoi(%q): %v", s, err)
	}
	return n
}

// parsePanelTime tries the handful of timestamp layouts Laravel's default
// Carbon JSON serialization can emit.
func parsePanelTime(s string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000000Z"} {
		if tm, err := time.Parse(layout, s); err == nil {
			return tm, true
		}
	}
	return time.Time{}, false
}
