package firewall

import (
	"errors"
	"net"
	"testing"
)

// TestSelectBackend covers the detection order and the forced-override env var.
func TestSelectBackend(t *testing.T) {
	t.Run("ipset and iptables present, all ipset commands succeed -> ipset", func(t *testing.T) {
		withFakeFW(t, []string{"ipset", "iptables"}, nil)
		if got := Reselect(); got != "ipset" {
			t.Fatalf("Reselect() = %q, want ipset", got)
		}
	})

	t.Run("ipset present but probe create fails -> iptables", func(t *testing.T) {
		withFakeFW(t, []string{"ipset", "iptables"}, func(c fakeCall) ([]byte, error) {
			if c.Name == "ipset" && len(c.Args) > 0 && c.Args[0] == "create" {
				return []byte("ipset v7.0: Kernel error"), errors.New("exit 1")
			}
			return []byte{}, nil
		})
		if got := Reselect(); got != "iptables" {
			t.Fatalf("Reselect() = %q, want iptables", got)
		}
	})

	t.Run("no ipset, iptables -S INPUT ok -> iptables", func(t *testing.T) {
		withFakeFW(t, []string{"iptables"}, nil)
		if got := Reselect(); got != "iptables" {
			t.Fatalf("Reselect() = %q, want iptables", got)
		}
	})

	t.Run("nothing on PATH -> none, reason mentions both causes", func(t *testing.T) {
		withFakeFW(t, []string{}, nil)
		if got := Reselect(); got != "none" {
			t.Fatalf("Reselect() = %q, want none", got)
		}
		r := SelectionReason()
		if !contains(r, "ipset:") || !contains(r, "iptables:") {
			t.Fatalf("SelectionReason() = %q, want it to mention ipset: and iptables:", r)
		}
	})

	t.Run("DEFENSIA_FIREWALL_BACKEND=iptables with working ipset -> iptables", func(t *testing.T) {
		withFakeFW(t, []string{"ipset", "iptables"}, nil)
		t.Setenv("DEFENSIA_FIREWALL_BACKEND", "iptables")
		if got := Reselect(); got != "iptables" {
			t.Fatalf("Reselect() = %q, want iptables (forced)", got)
		}
	})

	t.Run("DEFENSIA_FIREWALL_BACKEND=ipset with broken ipset -> none (forced never falls through)", func(t *testing.T) {
		withFakeFW(t, []string{"ipset", "iptables"}, func(c fakeCall) ([]byte, error) {
			if c.Name == "ipset" {
				return []byte("broken"), errors.New("exit 1")
			}
			return []byte{}, nil
		})
		t.Setenv("DEFENSIA_FIREWALL_BACKEND", "ipset")
		if got := Reselect(); got != "none" {
			t.Fatalf("Reselect() = %q, want none (forced ipset broken must not fall through to iptables)", got)
		}
	})

	t.Run("DEFENSIA_FIREWALL_BACKEND=none -> none", func(t *testing.T) {
		withFakeFW(t, []string{"ipset", "iptables"}, nil)
		t.Setenv("DEFENSIA_FIREWALL_BACKEND", "none")
		if got := Reselect(); got != "none" {
			t.Fatalf("Reselect() = %q, want none (forced)", got)
		}
	})
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

func TestNoneBackendRefuses(t *testing.T) {
	withFakeFW(t, []string{}, nil)
	Reselect()

	err := BanIPFor("203.0.113.9", 0)
	if !errors.Is(err, ErrNoBackend) {
		t.Fatalf("BanIPFor in none mode: err = %v, want ErrNoBackend", err)
	}
	before := NotAppliedBans()
	_ = BanIPFor("203.0.113.10", 0)
	if NotAppliedBans() != before+1 {
		t.Fatalf("NotAppliedBans did not increment")
	}

	if err := ApplyRule(RuleSpec{Type: "block", Protocol: "all", IPAddress: strPtr("203.0.113.9")}); !errors.Is(err, ErrNoBackend) {
		t.Fatalf("ApplyRule in none mode: err = %v, want ErrNoBackend", err)
	}

	if n := ApplyBanEntries([]BanEntry{{IP: "203.0.113.11"}}); n != 0 {
		t.Fatalf("ApplyBanEntries in none mode = %d, want 0", n)
	}

	st := FirewallStatus()
	if st.Mode != "none" || st.HasIpset || st.Capacity != 0 || st.ActiveBans != 0 {
		t.Fatalf("FirewallStatus in none mode = %+v, want Mode=none Capacity=0 ActiveBans=0", st)
	}
	if st.Reason == "" {
		t.Fatalf("FirewallStatus.Reason must be non-empty in none mode")
	}
}

func TestSafeIPStillRefusedFirst(t *testing.T) {
	for _, mode := range []string{"ipset+iptables", "none"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "none" {
				withFakeFW(t, []string{}, nil)
			} else {
				withFakeFW(t, []string{"ipset", "iptables"}, nil)
			}
			before := NotAppliedBans()
			err := BanIPFor("127.0.0.1", 0)
			if err == nil || !contains(err.Error(), "refusing to ban safe IP") {
				t.Fatalf("BanIPFor(127.0.0.1) = %v, want 'refusing to ban safe IP' error", err)
			}
			if NotAppliedBans() != before {
				t.Fatalf("NotAppliedBans incremented for a safe-IP refusal, should not")
			}
		})
	}
}

func TestGenerationIncrementsOnModeChange(t *testing.T) {
	withFakeFW(t, []string{"ipset", "iptables"}, nil)

	if Generation() != 0 {
		t.Fatalf("Generation() before first selection = %d, want 0", Generation())
	}
	Reselect()
	g1 := Generation()
	if g1 == 0 {
		t.Fatalf("Generation() did not increment on first selection")
	}

	Reselect() // same result (ipset again)
	if Generation() != g1 {
		t.Fatalf("Generation() changed on a no-op reselect: %d -> %d", g1, Generation())
	}

	// Force a change to none.
	t.Setenv("DEFENSIA_FIREWALL_BACKEND", "none")
	Reselect()
	if Generation() != g1+1 {
		t.Fatalf("Generation() = %d after a real mode change, want %d", Generation(), g1+1)
	}
}

func TestEnsureReselectsWhenNone(t *testing.T) {
	f := withFakeFW(t, []string{}, nil)
	Reselect()
	if Mode() != "none" {
		t.Fatalf("precondition: Mode() = %q, want none", Mode())
	}

	// Make iptables available in the fake, then Ensure() should reselect.
	f.bins["iptables"] = true

	if err := Ensure(); err != nil {
		t.Fatalf("Ensure() = %v, want nil once iptables becomes available", err)
	}
	if Mode() != "iptables" {
		t.Fatalf("Mode() after Ensure() = %q, want iptables", Mode())
	}
}

func TestLazySelection(t *testing.T) {
	withFakeFW(t, []string{"ipset", "iptables"}, nil)
	// Do not call Init()/Reselect() explicitly.
	st := FirewallStatus()
	if st.Mode != "ipset" {
		t.Fatalf("FirewallStatus() without explicit Init() = %+v, want lazy selection to ipset", st)
	}
}

func strPtr(s string) *string { return &s }

var _ = net.IPv4len // keep net imported for future tests in this file
