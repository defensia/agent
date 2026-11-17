package main

import (
	"errors"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/defensia/agent/internal/api"
	"github.com/defensia/agent/internal/firewall"
)

// shouldReportBan reports whether a ban attempt's outcome should still be
// recorded with the panel as a ban (ReportBan). A ban refused because no
// firewall backend exists must NOT be reported as applied — the panel would
// otherwise believe the IP is blocked when nothing in the kernel enforces
// it. Every other error keeps origin/main's behaviour: report it anyway, so
// the panel record lets the next sync retry the ban.
func shouldReportBan(err error) bool {
	return err == nil || !errors.Is(err, firewall.ErrNoBackend)
}

// banTTL converts a panel-provided expires_at into a kernel ban timeout.
// Returns 0 (no kernel timeout — expiry is panel-driven instead) when
// expiresAt is nil, unparseable, or already in the past.
func banTTL(expiresAt *string, now time.Time) time.Duration {
	if expiresAt == nil || *expiresAt == "" {
		return 0
	}

	layouts := []string{
		time.RFC3339Nano,
		"2006-01-02T15:04:05.000000Z07:00",
		"2006-01-02 15:04:05", // no zone in the layout -> time.Parse assumes UTC
	}

	var t time.Time
	var parsed bool
	for _, layout := range layouts {
		if tt, err := time.Parse(layout, *expiresAt); err == nil {
			t = tt
			parsed = true
			break
		}
	}
	if !parsed {
		return 0
	}

	d := t.Sub(now)
	if d <= 0 {
		return 0
	}
	return d
}

// eventThrottle rate-limits a recurring event by key, so a condition that
// persists across many sync/heartbeat cycles produces at most one event per
// `every` instead of flooding the panel.
type eventThrottle struct {
	mu   sync.Mutex
	last map[string]time.Time
	now  func() time.Time
}

func newEventThrottle() *eventThrottle {
	return &eventThrottle{last: make(map[string]time.Time), now: time.Now}
}

// allow reports whether an event for key may be sent now, and if so records
// the time so the next call within `every` returns false.
func (t *eventThrottle) allow(key string, every time.Duration) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()
	if last, ok := t.last[key]; ok && now.Sub(last) < every {
		return false
	}
	t.last[key] = now
	return true
}

// fwEventThrottle is the one throttle shared by every firewall_unavailable
// report — "bans" and "geoblock" are independent keys within it.
var fwEventThrottle = newEventThrottle()

// firewallUnavailableEvent builds the firewall_unavailable event payload.
// scope "bans": severity high, details carry bans_not_applied.
// scope "geoblock": severity warning, details carry countries.
func firewallUnavailableEvent(scope, mode, reason string, notApplied uint64, countries int, now time.Time) api.EventRequest {
	severity := "high"
	details := map[string]string{
		"scope":  scope,
		"mode":   mode,
		"reason": reason,
	}
	switch scope {
	case "geoblock":
		severity = "warning"
		details["countries"] = strconv.Itoa(countries)
	default: // "bans"
		details["bans_not_applied"] = strconv.FormatUint(notApplied, 10)
	}
	return api.EventRequest{
		Type:       "firewall_unavailable",
		Severity:   severity,
		Details:    details,
		OccurredAt: now.UTC().Format(time.RFC3339),
	}
}

// reportFirewallUnavailable sends the event in its OWN ReportEvents call: a
// panel that predates the event type rejects the whole batch with 422, so it
// must never share a batch with other events. Throttled to at most once per
// hour per scope so a persisting condition does not flood the panel.
func reportFirewallUnavailable(client *api.Client, scope, reason string, countries int) {
	mode := firewall.Mode()
	log.Printf("[firewall] UNAVAILABLE scope=%s mode=%s: %s", scope, mode, reason)

	if !fwEventThrottle.allow(scope, time.Hour) {
		return
	}

	ev := firewallUnavailableEvent(scope, mode, reason, firewall.NotAppliedBans(), countries, time.Now())
	if err := client.ReportEvents([]api.EventRequest{ev}); err != nil {
		log.Printf("[firewall] could not report %s unavailability: %v", scope, err)
	}
}
