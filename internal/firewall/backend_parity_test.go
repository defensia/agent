package firewall

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeGeoChain stubs geochain.go's own iptablesRun seam (deliberately separate
// from fwRun — geochain.go is out of scope for the fw-seam migration in this
// plan) so ensureGeoChain/rebuildGeoChain/teardownGeoChain never fail or shell
// out for real during tests. Argv-level parity for the chain itself is not
// asserted here: see the Deviations section of 17-03-SUMMARY.md.
func fakeGeoChain(t *testing.T) {
	t.Helper()
	orig := iptablesRun
	iptablesRun = func(args ...string) ([]byte, error) { return []byte{}, nil }
	t.Cleanup(func() { iptablesRun = orig })
}

// bumpGenerationForTest simulates a backend change without going through
// Reselect, for tests that only care about generation-driven invalidation.
func bumpGenerationForTest() { generation.Add(1) }

// failOnDashC makes every call whose argv contains a bare "-C" flag fail,
// which is how origin/main's "does this rule already exist?" checks are
// forced down the "doesn't exist yet, create it" path in these tests.
func failOnDashC(c fakeCall) ([]byte, error) {
	for _, a := range c.Args {
		if a == "-C" {
			return []byte(""), errors.New("exit 1")
		}
	}
	return []byte{}, nil
}

func lastArgv(f *fakeFW) string {
	calls := f.Calls()
	if len(calls) == 0 {
		return ""
	}
	return calls[len(calls)-1].Argv()
}

func TestIpsetParityInit(t *testing.T) {
	f := withFakeFW(t, []string{"ipset", "iptables", "ip6tables"}, failOnDashC)

	Init()

	got := f.Calls()
	want := []string{
		"ipset create defensia-probe hash:ip -exist",
		"ipset destroy defensia-probe",
		"ipset create defensia-bans hash:ip family inet maxelem 65536 -exist",
		"iptables -C INPUT -m set --match-set defensia-bans src -j DROP",
		"iptables -A INPUT -m set --match-set defensia-bans src -j DROP",
		"ipset create defensia-bans6 hash:ip family inet6 maxelem 65536 -exist",
		"ip6tables -C INPUT -m set --match-set defensia-bans6 src -j DROP",
		"ip6tables -A INPUT -m set --match-set defensia-bans6 src -j DROP",
	}
	if len(got) != len(want) {
		t.Fatalf("Init() issued %d calls, want %d\ngot:  %v\nwant: %v", len(got), len(want), argvList(got), want)
	}
	for i, w := range want {
		if got[i].Argv() != w {
			t.Fatalf("call[%d] = %q, want %q", i, got[i].Argv(), w)
		}
	}
	if Mode() != "ipset" {
		t.Fatalf("Mode() = %q, want ipset", Mode())
	}
}

func argvList(calls []fakeCall) []string {
	out := make([]string, len(calls))
	for i, c := range calls {
		out[i] = c.Argv()
	}
	return out
}

func TestIpsetParityBanUnban(t *testing.T) {
	f := withFakeFW(t, []string{"ipset", "iptables"}, nil)
	Reselect()

	if err := BanIP("203.0.113.5"); err != nil {
		t.Fatalf("BanIP v4: %v", err)
	}
	if got := lastArgv(f); got != "ipset add defensia-bans 203.0.113.5 -exist" {
		t.Fatalf("BanIP v4 last call = %q", got)
	}

	if err := BanIP("2001:db8::5"); err != nil {
		t.Fatalf("BanIP v6: %v", err)
	}
	if got := lastArgv(f); got != "ipset add defensia-bans6 2001:db8::5 -exist" {
		t.Fatalf("BanIP v6 last call = %q", got)
	}

	if err := UnbanIP("203.0.113.5"); err != nil {
		t.Fatalf("UnbanIP v4: %v", err)
	}
	if got := lastArgv(f); got != "ipset del defensia-bans 203.0.113.5 -exist" {
		t.Fatalf("UnbanIP v4 last call = %q", got)
	}

	// TTL is accepted but ignored by the ipset backend (no kernel timeout on
	// hash:ip members in this scheme) — same argv as a plain ban.
	if err := BanIPFor("203.0.113.5", time.Hour); err != nil {
		t.Fatalf("BanIPFor with ttl: %v", err)
	}
	if got := lastArgv(f); got != "ipset add defensia-bans 203.0.113.5 -exist" {
		t.Fatalf("BanIPFor(ttl) last call = %q, want the same argv as a plain ban", got)
	}
}

func TestIpsetParityApplyBans(t *testing.T) {
	f := withFakeFW(t, []string{"ipset", "iptables"}, nil)
	Reselect()

	v4a, v4b := "203.0.113.10", "203.0.113.11"
	v6a := "2001:db8::10"

	n := ApplyBans([]string{v4a, v6a, "bad", "127.0.0.1", v4b})
	if n != 3 {
		t.Fatalf("ApplyBans = %d, want 3", n)
	}

	var restores []fakeCall
	for _, c := range f.Calls() {
		if c.Name == "ipset" && len(c.Args) > 0 && c.Args[0] == "restore" {
			restores = append(restores, c)
		}
	}
	if len(restores) != 2 {
		t.Fatalf("got %d 'ipset restore' calls, want 2 (one per family): %v", len(restores), argvList(restores))
	}
	if restores[0].Stdin != "add defensia-bans 203.0.113.10 -exist\nadd defensia-bans 203.0.113.11 -exist\n" {
		t.Fatalf("v4 restore stdin = %q", restores[0].Stdin)
	}
	if restores[1].Stdin != "add defensia-bans6 2001:db8::10 -exist\n" {
		t.Fatalf("v6 restore stdin = %q", restores[1].Stdin)
	}
}

func TestIpsetParityCleanup(t *testing.T) {
	fn := func(c fakeCall) ([]byte, error) {
		if c.Name == "ipset" && len(c.Args) >= 2 && c.Args[0] == "list" {
			switch c.Args[1] {
			case "defensia-bans":
				return []byte("Members:\n203.0.113.1\n203.0.113.2\n203.0.113.3\n"), nil
			case "defensia-bans6":
				return []byte("Members:\n"), nil
			}
		}
		return []byte{}, nil
	}
	f := withFakeFW(t, []string{"ipset", "iptables"}, fn)
	Reselect()

	before := len(f.Calls())
	removed := CleanupStaleBans(
		map[string]bool{"203.0.113.1": true},
		map[string]bool{"203.0.113.3": true}, // must be ignored: ipset mode doesn't consult activeRuleIPs
	)
	if removed != 2 {
		t.Fatalf("CleanupStaleBans = %d, want 2", removed)
	}

	var dels []string
	for _, c := range f.Calls()[before:] {
		if c.Name == "ipset" && len(c.Args) > 0 && c.Args[0] == "del" {
			dels = append(dels, c.Argv())
		}
	}
	want := []string{
		"ipset del defensia-bans 203.0.113.2 -exist",
		"ipset del defensia-bans 203.0.113.3 -exist",
	}
	if len(dels) != len(want) {
		t.Fatalf("del calls = %v, want %v", dels, want)
	}
	for i := range want {
		found := false
		for _, d := range dels {
			if d == want[i] {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing expected del call %q in %v", want[i], dels)
		}
	}
}

func TestIpsetParityGeo(t *testing.T) {
	fakeGeoChain(t)
	f := withFakeFW(t, []string{"ipset", "iptables"}, failOnDashC)
	Reselect()

	gb := NewGeoBlocker(func(cc string) ([]string, error) {
		if cc == "CN" {
			return []string{"1.0.1.0/24", "1.0.2.0/23"}, nil
		}
		return nil, nil
	}, "")
	gb.SetWhitelistedIPs([]string{"203.0.113.50"})

	before := len(f.Calls())
	gb.ApplyCountryBlocks([]string{"cn"})

	got := argvList(f.Calls()[before:])
	want := []string{
		"iptables -C INPUT -s 203.0.113.50 -j ACCEPT",
		"iptables -I INPUT 1 -s 203.0.113.50 -j ACCEPT",
		"ipset create defensia-geo-cn hash:net maxelem 262144 -exist",
		"ipset flush defensia-geo-cn",
		"ipset restore",
		"ipset list defensia-geo-cn -t",
	}
	if len(got) != len(want) {
		t.Fatalf("ApplyCountryBlocks([cn]) calls = %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Fatalf("call[%d] = %q, want %q (full: %v)", i, got[i], w, got)
		}
	}
	restoreCall := f.Calls()[before+4]
	if restoreCall.Stdin != "add defensia-geo-cn 1.0.1.0/24 -exist\nadd defensia-geo-cn 1.0.2.0/23 -exist\n" {
		t.Fatalf("geo restore stdin = %q", restoreCall.Stdin)
	}
	if active := gb.ActiveCountries(); len(active) != 1 || active[0] != "CN" {
		t.Fatalf("ActiveCountries() = %v, want [CN]", active)
	}

	before = len(f.Calls())
	gb.ApplyCountryBlocks([]string{})
	got = argvList(f.Calls()[before:])
	want = []string{
		"ipset flush defensia-geo-cn",
		"ipset destroy defensia-geo-cn",
	}
	if len(got) != len(want) {
		t.Fatalf("ApplyCountryBlocks([]) calls = %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Fatalf("teardown call[%d] = %q, want %q", i, got[i], w)
		}
	}
	if active := gb.ActiveCountries(); len(active) != 0 {
		t.Fatalf("ActiveCountries() after removal = %v, want []", active)
	}
}

func TestIpsetStatusParity(t *testing.T) {
	fn := func(c fakeCall) ([]byte, error) {
		if c.Name == "ipset" && len(c.Args) >= 2 && c.Args[0] == "list" {
			switch c.Args[1] {
			case "defensia-bans":
				return []byte("Name: defensia-bans\nType: hash:ip\nNumber of entries: 4\n"), nil
			case "defensia-bans6":
				return []byte("Name: defensia-bans6\nType: hash:ip\nNumber of entries: 1\n"), nil
			}
		}
		return []byte{}, nil
	}
	withFakeFW(t, []string{"ipset", "iptables"}, fn)
	Reselect()

	st := FirewallStatus()
	if st.Mode != "ipset" || !st.HasIpset || st.Capacity != 65536 || st.ActiveBans != 5 {
		t.Fatalf("FirewallStatus() = %+v, want {Mode:ipset HasIpset:true Capacity:65536 ActiveBans:5}", st)
	}
}

func TestIptablesBackendBans(t *testing.T) {
	fn := func(c fakeCall) ([]byte, error) {
		for _, a := range c.Args {
			if a == "-C" {
				return []byte(""), errors.New("exit 1")
			}
		}
		if len(c.Args) >= 2 && c.Args[0] == "-S" && c.Args[1] == "INPUT" {
			switch c.Name {
			case "iptables":
				return []byte("-P INPUT ACCEPT\n-A INPUT -s 203.0.113.7/32 -j DROP\n"), nil
			case "ip6tables":
				return []byte("-P INPUT ACCEPT\n-A INPUT -s 2001:db8::7/128 -j DROP\n"), nil
			}
		}
		return []byte{}, nil
	}
	f := withFakeFW(t, []string{"iptables", "ip6tables"}, fn) // no ipset -> iptables backend
	if got := Reselect(); got != "iptables" {
		t.Fatalf("Reselect() = %q, want iptables", got)
	}

	if err := BanIP("203.0.113.7"); err != nil {
		t.Fatalf("BanIP v4: %v", err)
	}
	calls := f.Calls()
	n := len(calls)
	if calls[n-2].Argv() != "iptables -C INPUT -s 203.0.113.7 -j DROP" || calls[n-1].Argv() != "iptables -I INPUT 1 -s 203.0.113.7 -j DROP" {
		t.Fatalf("BanIP v4 last 2 calls = %q, %q", calls[n-2].Argv(), calls[n-1].Argv())
	}

	if err := BanIP("2001:db8::7"); err != nil {
		t.Fatalf("BanIP v6: %v", err)
	}
	calls = f.Calls()
	n = len(calls)
	if calls[n-2].Argv() != "ip6tables -C INPUT -s 2001:db8::7 -j DROP" || calls[n-1].Argv() != "ip6tables -I INPUT 1 -s 2001:db8::7 -j DROP" {
		t.Fatalf("BanIP v6 last 2 calls = %q, %q", calls[n-2].Argv(), calls[n-1].Argv())
	}

	st := FirewallStatus()
	if st.Mode != "iptables" || st.HasIpset {
		t.Fatalf("FirewallStatus mode = %+v, want iptables/HasIpset=false", st)
	}
	if st.Capacity != 500 {
		t.Fatalf("Capacity = %d, want 500", st.Capacity)
	}
	if st.ActiveBans != 2 {
		t.Fatalf("ActiveBans = %d, want 2 (one v4 DROP + one v6 DROP with source, no port)", st.ActiveBans)
	}
}

func TestIptablesCleanupRespectsRuleIPs(t *testing.T) {
	fn := func(c fakeCall) ([]byte, error) {
		if len(c.Args) >= 2 && c.Args[0] == "-S" && c.Args[1] == "INPUT" {
			if c.Name == "iptables" {
				return []byte("-P INPUT ACCEPT\n-A INPUT -s 203.0.113.1/32 -j DROP\n-A INPUT -s 203.0.113.2/32 -j DROP\n"), nil
			}
			if c.Name == "ip6tables" {
				return []byte("-P INPUT ACCEPT\n"), nil
			}
		}
		return []byte{}, nil
	}
	f := withFakeFW(t, []string{"iptables", "ip6tables"}, fn)
	Reselect()

	before := len(f.Calls())
	removed := CleanupStaleBans(map[string]bool{}, map[string]bool{"203.0.113.2": true})
	if removed != 1 {
		t.Fatalf("CleanupStaleBans = %d, want 1 (only .1 is neither active nor rule-protected)", removed)
	}

	var deletes []string
	for _, c := range f.Calls()[before:] {
		if c.Name == "iptables" && len(c.Args) > 0 && c.Args[0] == "-D" {
			deletes = append(deletes, c.Argv())
		}
	}
	if len(deletes) != 1 || deletes[0] != "iptables -D INPUT -s 203.0.113.1 -j DROP" {
		t.Fatalf("delete calls = %v, want exactly one: iptables -D INPUT -s 203.0.113.1 -j DROP", deletes)
	}
}

func TestGeoBlockerUnsupportedReportsUnapplied(t *testing.T) {
	fakeGeoChain(t)

	t.Run("iptables backend: nothing applied, nothing executed", func(t *testing.T) {
		f := withFakeFW(t, []string{"iptables"}, nil) // no ipset -> iptables, GeoSupported() == false
		Reselect()

		gb := NewGeoBlocker(func(cc string) ([]string, error) {
			t.Fatalf("cidrProvider must not be called when the backend cannot enforce geo blocks")
			return nil, nil
		}, "")

		before := len(f.Calls())
		gb.ApplyCountryBlocks([]string{"CN", "RU"})
		if got := len(f.Calls()) - before; got != 0 {
			t.Fatalf("ApplyCountryBlocks on an unsupported backend issued %d exec calls, want 0", got)
		}

		n, reason := gb.Unapplied()
		if n != 2 {
			t.Fatalf("Unapplied() count = %d, want 2", n)
		}
		if !strings.Contains(reason, "iptables") {
			t.Fatalf("Unapplied() reason = %q, want it to mention iptables", reason)
		}
	})

	t.Run("ipset backend: provider error counted as unapplied", func(t *testing.T) {
		withFakeFW(t, []string{"ipset", "iptables"}, nil)
		Reselect()

		provErr := errors.New("ru lookup failed: upstream timeout")
		gb := NewGeoBlocker(func(cc string) ([]string, error) {
			if cc == "RU" {
				return nil, provErr
			}
			return []string{"1.0.0.0/24"}, nil
		}, "")

		gb.ApplyCountryBlocks([]string{"RU"})
		n, reason := gb.Unapplied()
		if n != 1 {
			t.Fatalf("Unapplied() count = %d, want 1", n)
		}
		if !strings.Contains(reason, "ru lookup failed") {
			t.Fatalf("Unapplied() reason = %q, want it to contain the provider error", reason)
		}

		gb.ApplyCountryBlocks([]string{})
		n, reason = gb.Unapplied()
		if n != 0 || reason != "" {
			t.Fatalf("Unapplied() after an empty desired list = (%d, %q), want (0, \"\")", n, reason)
		}
	})
}

// TestGeoBlockerNftExemptionsUnsupportedRefusesToEnforce covers phase 17's
// independent review WARN-03 (2026-11-18): the nftables backend has no CIDR
// or port exemption mechanism yet, so blocking a country while exemptions
// are configured would silently drop Googlebot/CDN/mail traffic the
// customer explicitly exempted. The ipset branch already refuses to enforce
// in the equivalent situation (see TestGeoBlockerUnsupportedReportsUnapplied
// and ApplyCountryBlocks' own "lesser harm" comment) — this proves the
// nftables branch now makes the same decision instead of reporting
// enforced=true over a half-honored config.
func TestGeoBlockerNftExemptionsUnsupportedRefusesToEnforce(t *testing.T) {
	fakeGeoChain(t)
	resetNftForTest()

	t.Run("exempt CIDR configured: country NOT enforced, nothing loaded at the kernel", func(t *testing.T) {
		f := withFakeFW(t, []string{"nft"}, nftVersionOKFn(nil))
		if got := Reselect(); got != "nftables" {
			t.Fatalf("Reselect() = %q, want nftables", got)
		}

		gb := NewGeoBlocker(func(cc string) ([]string, error) {
			t.Fatalf("cidrProvider must not be called: exemptions make this country unenforceable before any CIDR lookup")
			return nil, nil
		}, "")
		gb.SetExemptions([]string{"66.249.64.0/19"}, nil) // Googlebot

		before := len(f.Calls())
		gb.ApplyCountryBlocks([]string{"CN"})

		for _, c := range f.Calls()[before:] {
			if c.Name == "nft" {
				t.Fatalf("ApplyCountryBlocks issued an nft call (%v) while exemptions are unsupported — nothing should reach the kernel", c.Argv())
			}
		}

		enforced, n := gb.Enforced()
		if enforced || n != 0 {
			t.Fatalf("Enforced() = (%v, %d), want (false, 0)", enforced, n)
		}
		unapplied, reason := gb.Unapplied()
		if unapplied != 1 {
			t.Fatalf("Unapplied() count = %d, want 1", unapplied)
		}
		if !strings.Contains(reason, "nftables") || !strings.Contains(reason, "exemption") {
			t.Fatalf("Unapplied() reason = %q, want it to mention nftables and exemption", reason)
		}
	})

	t.Run("exempt port configured, no CIDR exemptions: same refusal", func(t *testing.T) {
		resetNftForTest()
		withFakeFW(t, []string{"nft"}, nftVersionOKFn(nil))
		Reselect()

		gb := NewGeoBlocker(func(cc string) ([]string, error) {
			t.Fatalf("cidrProvider must not be called")
			return nil, nil
		}, "")
		gb.SetExemptions(nil, []int{25}) // inbound mail

		gb.ApplyCountryBlocks([]string{"CN"})
		if enforced, _ := gb.Enforced(); enforced {
			t.Fatalf("Enforced() = true, want false with a port exemption configured")
		}
	})

	t.Run("no exemptions configured: nftables enforces normally (unchanged behaviour)", func(t *testing.T) {
		resetNftForTest()
		f := withFakeFW(t, []string{"nft"}, nftVersionOKFn(func(c fakeCall) ([]byte, error) {
			if c.Name == "nft" && len(c.Args) >= 3 && c.Args[0] == "-j" && c.Args[1] == "-a" {
				return []byte(`{"nftables":[{"metainfo":{"version":"1.0.6"}}]}`), nil
			}
			return []byte{}, nil
		}))
		Reselect()

		gb := NewGeoBlocker(func(cc string) ([]string, error) {
			return []string{"1.0.0.0/24"}, nil
		}, "")

		gb.ApplyCountryBlocks([]string{"CN"})
		if enforced, n := gb.Enforced(); !enforced || n != 1 {
			t.Fatalf("Enforced() = (%v, %d), want (true, 1) with no exemptions configured", enforced, n)
		}
		foundLoad := false
		for _, c := range f.Calls() {
			if c.Name == "nft" && (strings.Contains(c.Argv(), "geo_cn") || strings.Contains(c.Stdin, "geo_cn")) {
				foundLoad = true
			}
		}
		if !foundLoad {
			t.Fatalf("no nft call referenced geo_cn (argv or stdin) — the country was never actually loaded")
		}
	})
}

func TestGeoBlockerReappliesAfterGeneration(t *testing.T) {
	fakeGeoChain(t)
	f := withFakeFW(t, []string{"ipset", "iptables"}, nil)
	Reselect()

	gb := NewGeoBlocker(func(cc string) ([]string, error) {
		return []string{"1.0.0.0/24"}, nil
	}, "")

	countCreates := func(calls []fakeCall) int {
		n := 0
		for _, c := range calls {
			if c.Argv() == "ipset create defensia-geo-cn hash:net maxelem 262144 -exist" {
				n++
			}
		}
		return n
	}

	gb.ApplyCountryBlocks([]string{"CN"})
	if n := countCreates(f.Calls()); n != 1 {
		t.Fatalf("first ApplyCountryBlocks: %d create calls, want 1", n)
	}

	// Same desired list, no generation change: must NOT re-run the add.
	gb.ApplyCountryBlocks([]string{"CN"})
	if n := countCreates(f.Calls()); n != 1 {
		t.Fatalf("second ApplyCountryBlocks (no gen change): %d create calls, want still 1", n)
	}

	bumpGenerationForTest()
	gb.ApplyCountryBlocks([]string{"CN"})
	if n := countCreates(f.Calls()); n != 2 {
		t.Fatalf("ApplyCountryBlocks after a generation bump: %d create calls, want 2 (CN reloaded)", n)
	}
}
