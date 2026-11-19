package firewall

import (
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// resetNftForTest resets nftSingleton's cached state. Called from
// withFakeFW's cleanup (fwexec_test.go) so nft tests never leak state into
// unrelated tests, and vice versa.
func resetNftForTest() {
	*nftSingleton = nftBackend{}
}

func TestSelectBackendWithNft(t *testing.T) {
	t.Run("ipset OK -> ipset, nft never probed", func(t *testing.T) {
		f := withFakeFW(t, []string{"ipset", "iptables", "nft"}, nil)
		if got := Reselect(); got != "ipset" {
			t.Fatalf("Reselect() = %q, want ipset", got)
		}
		for _, c := range f.Calls() {
			if c.Name == "nft" {
				t.Fatalf("nft was called even though ipset succeeded: %v", c.Argv())
			}
		}
	})

	t.Run("ipset probe fails, nft 1.0.6 works -> nftables", func(t *testing.T) {
		withFakeFW(t, []string{"ipset", "iptables", "nft"}, func(c fakeCall) ([]byte, error) {
			if c.Name == "ipset" {
				return []byte("broken"), errors.New("exit 1")
			}
			if c.Name == "nft" && len(c.Args) > 0 && c.Args[0] == "--version" {
				return []byte("nftables v1.0.6 (Lester Gooch #5)"), nil
			}
			return []byte{}, nil
		})
		if got := Reselect(); got != "nftables" {
			t.Fatalf("Reselect() = %q, want nftables", got)
		}
	})

	t.Run("no ipset, nft version too old -> iptables", func(t *testing.T) {
		withFakeFW(t, []string{"iptables", "nft"}, func(c fakeCall) ([]byte, error) {
			if c.Name == "nft" && len(c.Args) > 0 && c.Args[0] == "--version" {
				return []byte("nftables v0.9.3 (Topsy)"), nil
			}
			return []byte{}, nil
		})
		if got := Reselect(); got != "iptables" {
			t.Fatalf("Reselect() = %q, want iptables", got)
		}
	})

	t.Run("no ipset, nft OK -> nftables even when iptables also exists", func(t *testing.T) {
		withFakeFW(t, []string{"iptables", "nft"}, func(c fakeCall) ([]byte, error) {
			if c.Name == "nft" && len(c.Args) > 0 && c.Args[0] == "--version" {
				return []byte("nftables v1.0.6 (Lester Gooch #5)"), nil
			}
			return []byte{}, nil
		})
		if got := Reselect(); got != "nftables" {
			t.Fatalf("Reselect() = %q, want nftables", got)
		}
	})

	t.Run("nothing available -> none", func(t *testing.T) {
		withFakeFW(t, []string{}, nil)
		if got := Reselect(); got != "none" {
			t.Fatalf("Reselect() = %q, want none", got)
		}
	})

	t.Run("DEFENSIA_FIREWALL_BACKEND=nftables with working ipset -> nftables", func(t *testing.T) {
		withFakeFW(t, []string{"ipset", "iptables", "nft"}, func(c fakeCall) ([]byte, error) {
			if c.Name == "nft" && len(c.Args) > 0 && c.Args[0] == "--version" {
				return []byte("nftables v1.0.6 (Lester Gooch #5)"), nil
			}
			return []byte{}, nil
		})
		t.Setenv("DEFENSIA_FIREWALL_BACKEND", "nftables")
		if got := Reselect(); got != "nftables" {
			t.Fatalf("Reselect() = %q, want nftables (forced)", got)
		}
	})
}

func nftVersionOKFn(extra func(c fakeCall) ([]byte, error)) func(c fakeCall) ([]byte, error) {
	return func(c fakeCall) ([]byte, error) {
		if c.Name == "nft" && len(c.Args) > 0 && c.Args[0] == "--version" {
			return []byte("nftables v1.0.6 (Lester Gooch #5)"), nil
		}
		if extra != nil {
			return extra(c)
		}
		return []byte{}, nil
	}
}

func TestNftEnsure(t *testing.T) {
	t.Run("table absent: one ensure call with the golden stdin, recreated=true", func(t *testing.T) {
		f := withFakeFW(t, []string{"nft"}, nftVersionOKFn(func(c fakeCall) ([]byte, error) {
			if c.Name == "nft" && len(c.Args) >= 2 && c.Args[0] == "list" && c.Args[1] == "table" {
				return []byte(""), errors.New("No such file or directory")
			}
			return []byte{}, nil
		}))

		recreated, err := nftSingleton.Ensure()
		if err != nil {
			t.Fatalf("Ensure(): %v", err)
		}
		if !recreated {
			t.Fatalf("recreated = false, want true (table was absent)")
		}

		var ensureCalls int
		golden := nftEnsureScript()
		for _, c := range f.Calls() {
			if c.Name == "nft" && len(c.Args) >= 2 && c.Args[0] == "-f" && c.Args[1] == "-" {
				ensureCalls++
				if c.Stdin != golden {
					t.Fatalf("ensure stdin mismatch:\ngot:\n%s\nwant:\n%s", c.Stdin, golden)
				}
			}
		}
		if ensureCalls != 1 {
			t.Fatalf("got %d 'nft -f -' calls, want 1", ensureCalls)
		}
	})

	t.Run("table present: recreated=false", func(t *testing.T) {
		withFakeFW(t, []string{"nft"}, nftVersionOKFn(nil))
		recreated, err := nftSingleton.Ensure()
		if err != nil {
			t.Fatalf("Ensure(): %v", err)
		}
		if recreated {
			t.Fatalf("recreated = true, want false (table already present)")
		}
	})

	t.Run("ensure fails once on an existing table: delete+retry succeeds, recreated=true", func(t *testing.T) {
		attempts := 0
		f := withFakeFW(t, []string{"nft", "iptables"}, nftVersionOKFn(func(c fakeCall) ([]byte, error) {
			if c.Name == "nft" && len(c.Args) >= 2 && c.Args[0] == "-f" && c.Args[1] == "-" && c.Stdin == nftEnsureScript() {
				attempts++
				if attempts == 1 {
					return []byte("Error: File exists"), errors.New("exit 1")
				}
				return []byte{}, nil
			}
			return []byte{}, nil
		}))

		recreated, err := nftSingleton.Ensure()
		if err != nil {
			t.Fatalf("Ensure(): %v", err)
		}
		if !recreated {
			t.Fatalf("recreated = false, want true")
		}

		var deleteCalls int
		for _, c := range f.Calls() {
			if c.Name == "nft" && len(c.Args) >= 3 && c.Args[0] == "delete" && c.Args[1] == "table" {
				deleteCalls++
			}
		}
		if deleteCalls != 1 {
			t.Fatalf("got %d 'nft delete table' calls, want 1", deleteCalls)
		}
		if attempts != 2 {
			t.Fatalf("ensure script issued %d times, want 2 (first fails, retry succeeds)", attempts)
		}
	})

	t.Run("ensure fails twice on an existing table: error", func(t *testing.T) {
		withFakeFW(t, []string{"nft"}, nftVersionOKFn(func(c fakeCall) ([]byte, error) {
			if c.Name == "nft" && len(c.Args) >= 2 && c.Args[0] == "-f" && c.Args[1] == "-" && c.Stdin == nftEnsureScript() {
				return []byte("Error: File exists"), errors.New("exit 1")
			}
			return []byte{}, nil
		}))

		_, err := nftSingleton.Ensure()
		if err == nil {
			t.Fatalf("Ensure(): want an error when the retry also fails")
		}
	})
}

func TestNftLegacyIpsetRuleCleanup(t *testing.T) {
	f := withFakeFW(t, []string{"nft", "iptables"}, nftVersionOKFn(nil))

	if _, err := nftSingleton.Ensure(); err != nil {
		t.Fatalf("first Ensure(): %v", err)
	}
	var legacyCalls []string
	for _, c := range f.Calls() {
		if (c.Name == "iptables" || c.Name == "ip6tables") && len(c.Args) > 0 && c.Args[0] == "-D" {
			legacyCalls = append(legacyCalls, c.Argv())
		}
	}
	want := []string{
		"iptables -D INPUT -m set --match-set defensia-bans src -j DROP",
		"ip6tables -D INPUT -m set --match-set defensia-bans6 src -j DROP",
	}
	if len(legacyCalls) != len(want) {
		t.Fatalf("got %v, want %v", legacyCalls, want)
	}
	for i := range want {
		if legacyCalls[i] != want[i] {
			t.Fatalf("call[%d] = %q, want %q", i, legacyCalls[i], want[i])
		}
	}

	before := len(f.Calls())
	if _, err := nftSingleton.Ensure(); err != nil {
		t.Fatalf("second Ensure(): %v", err)
	}
	for _, c := range f.Calls()[before:] {
		if (c.Name == "iptables" || c.Name == "ip6tables") && len(c.Args) > 0 && c.Args[0] == "-D" {
			t.Fatalf("legacy cleanup repeated on the second Ensure(): %v", c.Argv())
		}
	}
}

func TestNftBanUnban(t *testing.T) {
	f := withFakeFW(t, []string{"nft"}, nftVersionOKFn(nil))

	if err := nftSingleton.Ban(mustParseIP(t, "203.0.113.5"), 0); err != nil {
		t.Fatalf("Ban v4: %v", err)
	}
	if got := f.Calls()[len(f.Calls())-1]; got.Stdin != "add element inet defensia bans4 { 203.0.113.5 }\n" {
		t.Fatalf("Ban v4 stdin = %q", got.Stdin)
	}

	if err := nftSingleton.Ban(mustParseIP(t, "2001:db8::5"), 90*time.Second); err != nil {
		t.Fatalf("Ban v6 with ttl: %v", err)
	}
	if got := f.Calls()[len(f.Calls())-1]; got.Stdin != "add element inet defensia bans6 { 2001:db8::5 timeout 90s }\n" {
		t.Fatalf("Ban v6 stdin = %q", got.Stdin)
	}

	withFakeFW(t, []string{"nft"}, nftVersionOKFn(func(c fakeCall) ([]byte, error) {
		if c.Name == "nft" && len(c.Args) >= 2 && c.Args[0] == "-f" && c.Args[1] == "-" && strings.HasPrefix(c.Stdin, "delete element") {
			return []byte("Error: Could not process rule: No such file or directory"), errors.New("exit 1")
		}
		return []byte{}, nil
	}))
	if err := nftSingleton.Unban(mustParseIP(t, "203.0.113.5")); err != nil {
		t.Fatalf("Unban of an absent element must be nil, got: %v", err)
	}

	withFakeFW(t, []string{"nft"}, nftVersionOKFn(func(c fakeCall) ([]byte, error) {
		if c.Name == "nft" && len(c.Args) >= 2 && c.Args[0] == "-f" && c.Args[1] == "-" && strings.HasPrefix(c.Stdin, "delete element") {
			return []byte("Error: Operation not permitted"), errors.New("exit 1")
		}
		return []byte{}, nil
	}))
	if err := nftSingleton.Unban(mustParseIP(t, "203.0.113.5")); err == nil {
		t.Fatalf("Unban with a real error must be returned, got nil")
	}
}

func TestNftBanBatchPerFamily(t *testing.T) {
	t.Run("both families succeed: two calls", func(t *testing.T) {
		f := withFakeFW(t, []string{"nft"}, nftVersionOKFn(nil))
		n, err := nftSingleton.BanBatch([]BanEntry{{IP: "203.0.113.5"}, {IP: "2001:db8::5"}})
		if err != nil {
			t.Fatalf("BanBatch: %v", err)
		}
		if n != 2 {
			t.Fatalf("applied = %d, want 2", n)
		}
		var scripts int
		for _, c := range f.Calls() {
			if c.Name == "nft" && len(c.Args) >= 2 && c.Args[0] == "-f" {
				scripts++
			}
		}
		if scripts != 2 {
			t.Fatalf("got %d nft -f - calls, want 2 (one per family)", scripts)
		}
	})

	t.Run("v4 fails: only v6 counted, error returned", func(t *testing.T) {
		withFakeFW(t, []string{"nft"}, nftVersionOKFn(func(c fakeCall) ([]byte, error) {
			if c.Name == "nft" && len(c.Args) >= 2 && c.Args[0] == "-f" && strings.Contains(c.Stdin, "bans4") {
				return []byte("error"), errors.New("exit 1")
			}
			return []byte{}, nil
		}))
		n, err := nftSingleton.BanBatch([]BanEntry{{IP: "203.0.113.5"}, {IP: "203.0.113.6"}, {IP: "2001:db8::5"}})
		if err == nil {
			t.Fatalf("BanBatch: want an error when the v4 call fails")
		}
		if n != 1 {
			t.Fatalf("applied = %d, want 1 (only v6)", n)
		}
	})
}

func TestNftMembersAndCount(t *testing.T) {
	withFakeFW(t, []string{"nft"}, nftVersionOKFn(func(c fakeCall) ([]byte, error) {
		if c.Name == "nft" && len(c.Args) >= 6 && c.Args[0] == "-j" && c.Args[1] == "list" && c.Args[2] == "set" {
			switch c.Args[5] {
			case "bans4":
				return readFixtureFile(t, "set_bans4_mixed.json"), nil
			case "bans6":
				return readFixtureFile(t, "set_empty.json"), nil
			}
		}
		return []byte{}, nil
	}))

	v4, v6, err := nftSingleton.Members()
	if err != nil {
		t.Fatalf("Members(): %v", err)
	}
	if len(v4) != 3 || len(v6) != 0 {
		t.Fatalf("Members() = %v, %v, want 3 v4 and 0 v6", v4, v6)
	}
	if got := nftSingleton.Count(); got != 3 {
		t.Fatalf("Count() = %d, want 3", got)
	}
	if got := nftSingleton.Capacity(); got != nftBanSetSize {
		t.Fatalf("Capacity() = %d, want %d", got, nftBanSetSize)
	}
}

func readFixtureFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/nft/" + name)
	if err != nil {
		t.Fatalf("reading testdata/nft/%s: %v", name, err)
	}
	return b
}

func TestNftRulesIdempotent(t *testing.T) {
	spec := RuleSpec{Type: "block", Protocol: "tcp", Port: intPtr(8080)}

	var ruleAdded bool
	f := withFakeFW(t, []string{"nft"}, nftVersionOKFn(func(c fakeCall) ([]byte, error) {
		if c.Name == "nft" && len(c.Args) >= 3 && c.Args[0] == "-j" && c.Args[1] == "-a" {
			if ruleAdded {
				return readFixtureFile(t, "chain_rules.json"), nil
			}
			return []byte(`{"nftables":[{"metainfo":{"version":"1.0.6"}}]}`), nil
		}
		if c.Name == "nft" && len(c.Args) >= 2 && c.Args[0] == "-f" && strings.HasPrefix(c.Stdin, "add rule") {
			ruleAdded = true
			return []byte{}, nil
		}
		return []byte{}, nil
	}))

	if err := nftSingleton.ApplyRule(spec); err != nil {
		t.Fatalf("first ApplyRule: %v", err)
	}
	var addCalls int
	for _, c := range f.Calls() {
		if c.Name == "nft" && strings.HasPrefix(c.Stdin, "add rule") {
			addCalls++
		}
	}
	if addCalls != 1 {
		t.Fatalf("got %d 'add rule' calls after the first apply, want 1", addCalls)
	}

	before := len(f.Calls())
	if err := nftSingleton.ApplyRule(spec); err != nil {
		t.Fatalf("second ApplyRule: %v", err)
	}
	for _, c := range f.Calls()[before:] {
		if strings.HasPrefix(c.Stdin, "add rule") {
			t.Fatalf("second ApplyRule issued another add rule: %v", c.Argv())
		}
	}

	if err := nftSingleton.RemoveRule(spec); err != nil {
		t.Fatalf("RemoveRule: %v", err)
	}

	unknown := RuleSpec{Type: "block", Protocol: "udp", Port: intPtr(9999)}
	resetNftForTest()
	withFakeFW(t, []string{"nft"}, nftVersionOKFn(func(c fakeCall) ([]byte, error) {
		return []byte(`{"nftables":[{"metainfo":{"version":"1.0.6"}}]}`), nil
	}))
	if err := nftSingleton.RemoveRule(unknown); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("RemoveRule(unknown) = %v, want an error containing 'not found'", err)
	}

	resetNftForTest()
	withFakeFW(t, []string{"nft"}, nftVersionOKFn(func(c fakeCall) ([]byte, error) {
		if c.Name == "nft" && len(c.Args) >= 3 && c.Args[0] == "-j" && c.Args[1] == "-a" {
			return readFixtureFile(t, "chain_rules.json"), nil
		}
		return []byte{}, nil
	}))
	rules, err := nftSingleton.ListRules()
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("ListRules() = %+v, want exactly 1 (only defensia-rule comments, not defensia-geo)", rules)
	}
	if rules[0].Protocol != "tcp" || rules[0].Port != 8080 {
		t.Fatalf("ListRules()[0] = %+v, want Protocol=tcp Port=8080", rules[0])
	}
}

func TestNftGeoReplaceAndRemove(t *testing.T) {
	t.Run("no existing rule: addRule via fwExecLong", func(t *testing.T) {
		f := withFakeFW(t, []string{"nft"}, nftVersionOKFn(func(c fakeCall) ([]byte, error) {
			if c.Name == "nft" && len(c.Args) >= 3 && c.Args[0] == "-j" && c.Args[1] == "-a" {
				return []byte(`{"nftables":[{"metainfo":{"version":"1.0.6"}}]}`), nil
			}
			return []byte{}, nil
		}))
		n, err := nftSingleton.GeoReplace("CN", []string{"1.0.1.0/24", "1.0.2.0/23"})
		if err != nil {
			t.Fatalf("GeoReplace: %v", err)
		}
		if n != 2 {
			t.Fatalf("GeoReplace returned %d, want 2", n)
		}
		var sawRule bool
		for _, c := range f.Calls() {
			if strings.Contains(c.Stdin, "add rule") && strings.Contains(c.Stdin, "geo_cn") {
				sawRule = true
			}
		}
		if !sawRule {
			t.Fatalf("expected an add rule for geo_cn when no existing rule, calls: %v", argvList(f.Calls()))
		}
	})

	t.Run("existing rule: addRule omitted", func(t *testing.T) {
		f := withFakeFW(t, []string{"nft"}, nftVersionOKFn(func(c fakeCall) ([]byte, error) {
			if c.Name == "nft" && len(c.Args) >= 3 && c.Args[0] == "-j" && c.Args[1] == "-a" {
				return readFixtureFile(t, "chain_rules.json"), nil // handle 7, comment defensia-geo:cn
			}
			return []byte{}, nil
		}))
		_, err := nftSingleton.GeoReplace("CN", []string{"1.0.1.0/24"})
		if err != nil {
			t.Fatalf("GeoReplace: %v", err)
		}
		for _, c := range f.Calls() {
			if strings.Contains(c.Stdin, "add rule") && strings.Contains(c.Stdin, "geo_cn") {
				t.Fatalf("GeoReplace issued an add rule when one already exists: %v", c.Stdin)
			}
		}
	})

	t.Run("GeoRemove with an existing handle", func(t *testing.T) {
		f := withFakeFW(t, []string{"nft"}, nftVersionOKFn(func(c fakeCall) ([]byte, error) {
			if c.Name == "nft" && len(c.Args) >= 3 && c.Args[0] == "-j" && c.Args[1] == "-a" {
				return readFixtureFile(t, "chain_rules.json"), nil // handle 7, comment defensia-geo:cn
			}
			return []byte{}, nil
		}))
		if err := nftSingleton.GeoRemove("CN"); err != nil {
			t.Fatalf("GeoRemove: %v", err)
		}
		var got string
		for _, c := range f.Calls() {
			if c.Name == "nft" && len(c.Args) >= 2 && c.Args[0] == "-f" {
				got = c.Stdin
			}
		}
		want := "delete rule inet defensia geo handle 7\ndelete set inet defensia geo_cn\n"
		if got != want {
			t.Fatalf("GeoRemove stdin = %q, want %q", got, want)
		}
	})

	t.Run("GeoRemove when the set does not exist -> nil", func(t *testing.T) {
		withFakeFW(t, []string{"nft"}, nftVersionOKFn(func(c fakeCall) ([]byte, error) {
			if c.Name == "nft" && len(c.Args) >= 3 && c.Args[0] == "-j" && c.Args[1] == "-a" {
				return []byte(`{"nftables":[{"metainfo":{"version":"1.0.6"}}]}`), nil
			}
			if c.Name == "nft" && len(c.Args) >= 2 && c.Args[0] == "-f" {
				return []byte("Error: No such file or directory"), errors.New("exit 1")
			}
			return []byte{}, nil
		}))
		if err := nftSingleton.GeoRemove("CN"); err != nil {
			t.Fatalf("GeoRemove on an absent set: %v, want nil", err)
		}
	})
}

func TestNftGeoReplaceTwoStepFallback(t *testing.T) {
	var atomicAttempted, setupCalled, elementsCalled bool
	withFakeFW(t, []string{"nft"}, nftVersionOKFn(func(c fakeCall) ([]byte, error) {
		if c.Name == "nft" && len(c.Args) >= 3 && c.Args[0] == "-j" && c.Args[1] == "-a" {
			return []byte(`{"nftables":[{"metainfo":{"version":"1.0.6"}}]}`), nil
		}
		if c.Name == "nft" && len(c.Args) >= 2 && c.Args[0] == "-f" {
			if strings.Contains(c.Stdin, "add element") && strings.Contains(c.Stdin, "add set") {
				// the atomic (one-shot) script: fail once with an interval error
				atomicAttempted = true
				return []byte("Error: interval overlap"), errors.New("exit 1")
			}
			if strings.Contains(c.Stdin, "add set") {
				setupCalled = true
				return []byte{}, nil
			}
			if strings.Contains(c.Stdin, "add element") {
				elementsCalled = true
				return []byte{}, nil
			}
		}
		return []byte{}, nil
	}))

	n, err := nftSingleton.GeoReplace("CN", []string{"1.0.1.0/24"})
	if err != nil {
		t.Fatalf("GeoReplace with fallback: %v", err)
	}
	if n != 1 {
		t.Fatalf("GeoReplace returned %d, want 1", n)
	}
	if !atomicAttempted || !setupCalled || !elementsCalled {
		t.Fatalf("fallback sequence incomplete: atomicAttempted=%v setupCalled=%v elementsCalled=%v", atomicAttempted, setupCalled, elementsCalled)
	}
}

func TestNftEnsureAccept(t *testing.T) {
	f := withFakeFW(t, []string{"nft"}, nftVersionOKFn(nil))
	if err := nftSingleton.EnsureAccept([]string{"203.0.113.10", "2001:db8::10", "bad"}); err != nil {
		t.Fatalf("EnsureAccept: %v", err)
	}
	got := f.Calls()[len(f.Calls())-1].Stdin
	want := nftProtectedScript([]string{"203.0.113.10"}, []string{"2001:db8::10"})
	if got != want {
		t.Fatalf("EnsureAccept stdin = %q, want %q", got, want)
	}
}

func TestNftEndToEndViaPackageAPI(t *testing.T) {
	var deleted []string
	f := withFakeFW(t, []string{"nft"}, nftVersionOKFn(func(c fakeCall) ([]byte, error) {
		if c.Name == "nft" && len(c.Args) >= 6 && c.Args[0] == "-j" && c.Args[1] == "list" && c.Args[2] == "set" {
			switch c.Args[5] {
			case "bans4":
				// Two members: 203.0.113.7 (active, must survive cleanup) and
				// 203.0.113.99 (stale, must be deleted).
				return []byte(`{"nftables":[{"set":{"elem":["203.0.113.7","203.0.113.99"]}}]}`), nil
			case "bans6":
				return []byte(`{"nftables":[{"set":{}}]}`), nil
			}
		}
		if c.Name == "nft" && len(c.Args) >= 2 && c.Args[0] == "-f" && strings.HasPrefix(c.Stdin, "delete element") {
			deleted = append(deleted, c.Stdin)
		}
		return []byte{}, nil
	}))

	if got := Reselect(); got != "nftables" {
		t.Fatalf("Reselect() = %q, want nftables", got)
	}

	if err := BanIPFor("203.0.113.7", time.Hour); err != nil {
		t.Fatalf("BanIPFor: %v", err)
	}
	if got := f.Calls()[len(f.Calls())-1]; !strings.Contains(got.Stdin, "timeout 3600s") {
		t.Fatalf("BanIPFor(ttl=1h) stdin = %q, want it to contain 'timeout 3600s'", got.Stdin)
	}

	removed := CleanupStaleBans(map[string]bool{"203.0.113.7": true}, nil)
	if removed != 1 {
		t.Fatalf("CleanupStaleBans = %d, want 1 (only .99 is stale)", removed)
	}
	if len(deleted) != 1 || !strings.Contains(deleted[0], "203.0.113.99") {
		t.Fatalf("delete element calls = %v, want exactly one targeting 203.0.113.99", deleted)
	}

	st := FirewallStatus()
	if st.Mode != "nftables" {
		t.Fatalf("FirewallStatus().Mode = %q, want nftables", st.Mode)
	}
	if st.Capacity != nftBanSetSize {
		t.Fatalf("FirewallStatus().Capacity = %d, want %d", st.Capacity, nftBanSetSize)
	}
}

func mustParseIP(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("invalid test IP: %s", s)
	}
	return ip
}
