//go:build integration

package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// attackEvent mirrors the subset of a GET /api/v1/events row this suite reads.
type attackEvent struct {
	Type       string `json:"type"`
	SourceIP   string `json:"source_ip"`
	OccurredAt string `json:"occurred_at"`
}

// attackEventsResponse mirrors EventController::index's paginator response.
type attackEventsResponse struct {
	Data []attackEvent `json:"data"`
}

// pollForAttackEvent polls GET /api/v1/events?ip=<ip> every 5s, up to
// timeout, for any event whose type is in allowed and whose source_ip
// equals ip. Returns the matched type on success.
//
// Does NOT reuse helpers_test.go's panelGet: that helper Fatals on any
// non-2xx status, but this suite's traffic shares the lab panel's
// pre-existing agent-events/dashboard-api rate-limit buckets with the
// other 6 agent VMs' background heartbeats/syncs (see
// 14-05-SUMMARY.md/deferred-items.md — the per-agent key falls back to a
// shared IP bucket). A 429 here is a real, known, out-of-scope-to-fix
// throttle hit, not a broken assertion — it must be absorbed by a retry
// within the same poll budget, never surfaced as a failed Fatal.
func pollForAttackEvent(t *testing.T, ip string, allowed map[string]bool, timeout time.Duration) (matchedType string, seenTypes []string, ok bool) {
	t.Helper()
	token := requireEnv(t, "LAB_PANEL_TOKEN")
	url := env("LAB_PANEL_URL") + "/api/v1/events?server_id=" + readAgentConfig(t) +
		"&ip=" + ip + "&since=1%20hour&per_page=100"
	client := &http.Client{Timeout: 10 * time.Second}

	deadline := time.Now().Add(timeout)
	for {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			t.Fatalf("pollForAttackEvent %s: build request: %v", ip, err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			t.Logf("pollForAttackEvent %s: request error (retrying): %v", ip, err)
		} else {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			switch {
			case resp.StatusCode == http.StatusTooManyRequests:
				// Shared rate-limit bucket — back off and retry, not a failure.
				t.Logf("pollForAttackEvent %s: 429 (shared agent-events/dashboard-api bucket) — backing off", ip)
			case resp.StatusCode < 200 || resp.StatusCode >= 300:
				snippet := body
				if len(snippet) > 300 {
					snippet = snippet[:300]
				}
				t.Fatalf("pollForAttackEvent %s: GET /api/v1/events status %d: %s", ip, resp.StatusCode, snippet)
			default:
				var out attackEventsResponse
				if err := json.Unmarshal(body, &out); err != nil {
					t.Fatalf("pollForAttackEvent %s: decode: %v", ip, err)
				}
				seenTypes = seenTypes[:0]
				for _, e := range out.Data {
					if e.SourceIP != ip {
						continue
					}
					seenTypes = append(seenTypes, e.Type)
					if allowed[e.Type] {
						return e.Type, seenTypes, true
					}
				}
			}
		}

		if time.Now().After(deadline) {
			return "", seenTypes, false
		}
		time.Sleep(5 * time.Second)
	}
}

// waitForIpsetBan polls `ipset test defensia-bans <ip>` every 5s, up to
// timeout, for a successful (exit 0) membership test — real firewall
// enforcement, not just a panel-side event record.
func waitForIpsetBan(t *testing.T, ip string, timeout time.Duration) (lastOutput string, ok bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		out, err := sh(t, "ipset", "test", "defensia-bans", ip)
		if err == nil {
			return out, true
		}
		lastOutput = out
		if time.Now().After(deadline) {
			return lastOutput, false
		}
		time.Sleep(5 * time.Second)
	}
}

// TestAttackEventsReachPanel asserts that real brute-force traffic sent by
// lab/attack.sh against this VM (debian12-nocsf) produces real events in
// the local panel (and, for the ssh leg, a real ipset ban) — not a
// fixture, not a simulated call. Subtests are gated on their own
// LAB_ATTACK_*_IP env var so a partial attack run (one leg only) does not
// fail legs that never ran; at least one leg (ssh) is required so this
// test can never pass vacuously when lab/attack.sh was never invoked at
// all (see the negative-path proof in 14-08-SUMMARY.md: unsetting every
// LAB_ATTACK_*_IP makes every subtest Fatal via requireEnv/skip-nothing,
// it never silently passes).
func TestAttackEventsReachPanel(t *testing.T) {
	requireRoot(t)
	requireEnv(t, "LAB_PANEL_URL")
	requireEnv(t, "LAB_PANEL_TOKEN")
	// At least one leg's IP must be set — lab/test.sh always sets all
	// three together (lab/attack.sh ... all), so an empty value here
	// means the attack stage itself did not run, which is a harness bug,
	// not a legitimate "not applicable" case (same convention as
	// requireEnv's non-CI behavior).
	requireEnv(t, "LAB_ATTACK_SSH_IP")

	// Calibrated 2026-11-05 against the live lab (see 14-08-SUMMARY.md):
	// only list types actually observed for each leg. `brute_force` is
	// the SSH watcher's *monitor-mode* event type — this suite always
	// runs with the target's Active Protection on (monitor_mode=false,
	// flipped by attack.sh's `ensure_active_protection`), so the SSH leg
	// only ever reports `ban_created` (via the agent's /bans report), not
	// `brute_force`.
	t.Run("ssh", func(t *testing.T) {
		ip := env("LAB_ATTACK_SSH_IP")
		if ip == "" {
			t.Skip("LAB_ATTACK_SSH_IP not set — ssh leg did not run")
		}
		allowed := map[string]bool{"ban_created": true}
		matched, seen, ok := pollForAttackEvent(t, ip, allowed, 120*time.Second)
		if !ok {
			t.Fatalf("no allowed ssh event (ban_created) for %s within 120s; types seen for this ip: %s", ip, strings.Join(seen, ","))
		}
		t.Logf("ssh: matched event type %q for %s", matched, ip)

		if _, ok := waitForIpsetBan(t, ip, 60*time.Second); !ok {
			t.Fatalf("ipset test defensia-bans %s never succeeded within 60s — panel reported ban_created but the target never actually enforced it", ip)
		}
	})

	t.Run("web", func(t *testing.T) {
		ip := env("LAB_ATTACK_WEB_IP")
		if ip == "" {
			t.Skip("LAB_ATTACK_WEB_IP not set — web leg did not run")
		}
		allowed := map[string]bool{"wp_bruteforce": true, "xmlrpc_abuse": true, "ban_created": true}
		matched, seen, ok := pollForAttackEvent(t, ip, allowed, 120*time.Second)
		if !ok {
			t.Fatalf("no allowed web event (wp_bruteforce/xmlrpc_abuse/ban_created) for %s within 120s; types seen for this ip: %s", ip, strings.Join(seen, ","))
		}
		t.Logf("web: matched event type %q for %s", matched, ip)
	})

	t.Run("mail", func(t *testing.T) {
		ip := env("LAB_ATTACK_MAIL_IP")
		if ip == "" {
			t.Skip("LAB_ATTACK_MAIL_IP not set — mail leg did not run")
		}
		allowed := map[string]bool{"mail_brute_force": true, "ban_created": true}
		matched, seen, ok := pollForAttackEvent(t, ip, allowed, 120*time.Second)
		if !ok {
			t.Fatalf("no allowed mail event (mail_brute_force/ban_created) for %s within 120s; types seen for this ip: %s", ip, strings.Join(seen, ","))
		}
		t.Logf("mail: matched event type %q for %s", matched, ip)
	})
}
