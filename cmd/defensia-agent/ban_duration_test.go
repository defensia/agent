package main

import (
	"testing"
	"time"
)

// bf_ban_duration was a dead selector: the panel offered it, saved it and sent it,
// and the agent only ever declared the field. Every ban was reported with no expiry,
// so the backend escalated by offence count and the chosen duration meant nothing.
func TestBanExpiryHonoursConfiguredDuration(t *testing.T) {
	defer banDurationSecs.Store(0)
	banDurationSecs.Store(3600)

	got := banExpiry("brute_force_ssh")
	if got == nil {
		t.Fatal("banExpiry returned nil with a duration configured, so the backend would escalate instead")
	}

	expires, err := time.Parse(time.RFC3339, *got)
	if err != nil {
		t.Fatalf("expiry %q is not RFC3339, which the panel rejects: %v", *got, err)
	}

	if delta := time.Until(expires) - time.Hour; delta > time.Minute || delta < -time.Minute {
		t.Errorf("expiry is %s away, want ~1h", time.Until(expires))
	}
}

// Nil is what the agent has always sent, and it is what the 122 servers that leave
// the duration unset must keep sending after they update.
func TestBanExpiryNilWhenUnset(t *testing.T) {
	defer banDurationSecs.Store(0)

	for _, secs := range []int64{0, -1} {
		banDurationSecs.Store(secs)
		if got := banExpiry("brute_force_ssh"); got != nil {
			t.Errorf("banDurationSecs=%d gave expiry %q, want nil so the backend escalates", secs, *got)
		}
	}
}

// Bot blocks are permanent by policy and country blocks are standing, so a short
// duration must not reach either. A 5-minute geoblock would ban and expire the same
// IP on every request from the blocked country.
func TestBanExpirySkipsPolicyBans(t *testing.T) {
	defer banDurationSecs.Store(0)
	banDurationSecs.Store(300)

	exempt := []string{"bot_blocked", "geoblock_cn", "geoblock_ru"}
	for _, reason := range exempt {
		if got := banExpiry(reason); got != nil {
			t.Errorf("banExpiry(%q) = %q, want nil", reason, *got)
		}
	}

	subject := []string{"brute_force_ssh", "env_probe", "404_flood", "sql_injection"}
	for _, reason := range subject {
		if banExpiry(reason) == nil {
			t.Errorf("banExpiry(%q) = nil, want the configured duration", reason)
		}
	}
}
