package main

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/defensia/agent/internal/firewall"
)

func strp(s string) *string { return &s }

func TestShouldReportBan(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, true},
		{"wrapped ErrNoBackend", fmt.Errorf("ban 1.2.3.4: %w", firewall.ErrNoBackend), false},
		{"safe-IP refusal (origin/main behaviour kept)", errors.New("refusing to ban safe IP: 127.0.0.1"), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := shouldReportBan(c.err); got != c.want {
				t.Fatalf("shouldReportBan(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

func TestBanTTL(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name      string
		expiresAt *string
		want      time.Duration
	}{
		{"nil", nil, 0},
		{"RFC3339 one hour out", strp("2026-11-04T13:00:00Z"), time.Hour},
		{"RFC3339Nano 30 minutes out", strp("2026-11-04T12:30:00.000000Z"), 30 * time.Minute},
		{"space-separated UTC, 10s out", strp("2026-11-04 12:00:10"), 10 * time.Second},
		{"already in the past", strp("2026-11-04T11:00:00Z"), 0},
		{"garbage", strp("not-a-date"), 0},
		{"empty string", strp(""), 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := banTTL(c.expiresAt, now); got != c.want {
				t.Fatalf("banTTL(%v, %v) = %v, want %v", c.expiresAt, now, got, c.want)
			}
		})
	}
}

func TestEventThrottle(t *testing.T) {
	th := newEventThrottle()
	clock := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	th.now = func() time.Time { return clock }

	if !th.allow("bans", time.Hour) {
		t.Fatalf("first allow(bans) = false, want true")
	}
	clock = clock.Add(10 * time.Minute)
	if th.allow("bans", time.Hour) {
		t.Fatalf("allow(bans) at +10m = true, want false (still throttled)")
	}
	clock = clock.Add(51 * time.Minute) // total +61m from the first allow
	if !th.allow("bans", time.Hour) {
		t.Fatalf("allow(bans) at +61m = false, want true (throttle window elapsed)")
	}

	// Independent keys: "geoblock" must not be affected by "bans"'s state.
	if !th.allow("geoblock", time.Hour) {
		t.Fatalf("first allow(geoblock) = false, want true (independent key)")
	}
}

func TestFirewallUnavailableEvent(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

	t.Run("scope bans", func(t *testing.T) {
		ev := firewallUnavailableEvent("bans", "none", "no usable firewall backend", 5, 0, now)
		if ev.Type != "firewall_unavailable" {
			t.Fatalf("Type = %q, want firewall_unavailable", ev.Type)
		}
		if ev.Severity != "high" {
			t.Fatalf("Severity = %q, want high", ev.Severity)
		}
		want := map[string]string{
			"scope":            "bans",
			"mode":             "none",
			"reason":           "no usable firewall backend",
			"bans_not_applied": "5",
		}
		if len(ev.Details) != len(want) {
			t.Fatalf("Details = %+v, want %+v", ev.Details, want)
		}
		for k, v := range want {
			if ev.Details[k] != v {
				t.Fatalf("Details[%q] = %q, want %q", k, ev.Details[k], v)
			}
		}
		if ev.OccurredAt != "2026-11-04T12:00:00Z" {
			t.Fatalf("OccurredAt = %q, want RFC3339 UTC", ev.OccurredAt)
		}
	})

	t.Run("scope geoblock", func(t *testing.T) {
		ev := firewallUnavailableEvent("geoblock", "iptables", "country blocks need ipset or nftables", 0, 2, now)
		if ev.Severity != "warning" {
			t.Fatalf("Severity = %q, want warning", ev.Severity)
		}
		if ev.Details["countries"] != "2" {
			t.Fatalf("Details[countries] = %q, want 2", ev.Details["countries"])
		}
		if ev.Details["mode"] != "iptables" {
			t.Fatalf("Details[mode] = %q, want iptables", ev.Details["mode"])
		}
	})
}
