package firewall

import (
	"os"
	"testing"
)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/nft/" + name)
	if err != nil {
		t.Fatalf("reading testdata/nft/%s: %v", name, err)
	}
	return b
}

func TestParseNftSetElements(t *testing.T) {
	t.Run("mixed plain and object elements", func(t *testing.T) {
		got, err := parseNftSetElements(readTestdata(t, "set_bans4_mixed.json"))
		if err != nil {
			t.Fatalf("parseNftSetElements: %v", err)
		}
		want := []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"}
		if len(got) != len(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("index %d: got %q, want %q", i, got[i], want[i])
			}
		}
	})

	t.Run("empty set (no elem key)", func(t *testing.T) {
		got, err := parseNftSetElements(readTestdata(t, "set_empty.json"))
		if err != nil {
			t.Fatalf("parseNftSetElements: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("got %v, want empty", got)
		}
	})

	t.Run("interval set: prefix, range, plain", func(t *testing.T) {
		got, err := parseNftSetElements(readTestdata(t, "set_geo_interval.json"))
		if err != nil {
			t.Fatalf("parseNftSetElements: %v", err)
		}
		want := []string{"1.0.1.0/24", "1.0.4.0-1.0.7.255", "1.0.9.9"}
		if len(got) != len(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("index %d: got %q, want %q", i, got[i], want[i])
			}
		}
	})

	t.Run("malformed JSON errors", func(t *testing.T) {
		if _, err := parseNftSetElements([]byte("{not json")); err == nil {
			t.Fatalf("parseNftSetElements(malformed): want error")
		}
	})
}

func TestParseNftChainRules(t *testing.T) {
	got, err := parseNftChainRules(readTestdata(t, "chain_rules.json"))
	if err != nil {
		t.Fatalf("parseNftChainRules: %v", err)
	}
	want := []nftRuleRef{
		{Handle: 4, Comment: "defensia-rule:block:tcp:-:8080"},
		{Handle: 7, Comment: "defensia-geo:cn"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("index %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestNftVersion(t *testing.T) {
	cases := []struct {
		out       string
		wantOk    bool
		wantMaj   int
		wantMinor int
		wantPatch int
		atLeast   bool
	}{
		{out: "nftables v1.0.6 (Lester Gooch #5)", wantOk: true, wantMaj: 1, wantMinor: 0, wantPatch: 6, atLeast: true},
		{out: "nftables v0.9.3 (Topsy)", wantOk: true, wantMaj: 0, wantMinor: 9, wantPatch: 3, atLeast: false},
		{out: "nftables v1.1.1 (Commodore Bullmoose #2)", wantOk: true, wantMaj: 1, wantMinor: 1, wantPatch: 1, atLeast: true},
		{out: "garbage", wantOk: false, atLeast: false},
	}
	for _, c := range cases {
		t.Run(c.out, func(t *testing.T) {
			maj, minor, patch, ok := parseNftVersion(c.out)
			if ok != c.wantOk {
				t.Fatalf("ok = %v, want %v", ok, c.wantOk)
			}
			if ok {
				if maj != c.wantMaj || minor != c.wantMinor || patch != c.wantPatch {
					t.Fatalf("got %d.%d.%d, want %d.%d.%d", maj, minor, patch, c.wantMaj, c.wantMinor, c.wantPatch)
				}
			}
			if got := nftVersionAtLeast(c.out, nftMinVersion); got != c.atLeast {
				t.Fatalf("nftVersionAtLeast(%q, %q) = %v, want %v", c.out, nftMinVersion, got, c.atLeast)
			}
		})
	}
}

func TestIsNftNotFound(t *testing.T) {
	if !isNftNotFound([]byte("Error: Could not process rule: No such file or directory")) {
		t.Fatalf("want true for a 'No such file or directory' output")
	}
	if isNftNotFound([]byte("Error: Operation not permitted")) {
		t.Fatalf("want false for an unrelated error")
	}
}

// TestParseNftRealAlma10Fixtures parses real `nft -j` output captured from
// alma10-noiptables (plan 17-06, LAB_CAPTURE_NFT_FIXTURES=1) — proof that
// the hand-written fixtures elsewhere in this package match what a real
// nftables v1.1.5 kernel actually emits, not just what we assumed it would.
func TestParseNftRealAlma10Fixtures(t *testing.T) {
	t.Run("set_bans4.json: mixed permanent and timed elements", func(t *testing.T) {
		got, err := parseNftSetElements(readTestdata(t, "real-alma10/set_bans4.json"))
		if err != nil {
			t.Fatalf("parseNftSetElements: %v", err)
		}
		want := []string{"198.51.100.10", "198.51.100.201", "198.51.100.202", "198.51.100.203"}
		if len(got) != len(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("index %d: got %q, want %q", i, got[i], want[i])
			}
		}
	})

	t.Run("set_geo_zy.json: three adjacent /24s auto-merged into one range", func(t *testing.T) {
		got, err := parseNftSetElements(readTestdata(t, "real-alma10/set_geo_zy.json"))
		if err != nil {
			t.Fatalf("parseNftSetElements: %v", err)
		}
		want := []string{"192.0.2.0-192.0.4.255"}
		if len(got) != 1 || got[0] != want[0] {
			t.Fatalf("got %v, want %v (auto-merge should have coalesced 192.0.2.0/24 + 192.0.3.0/24 + 192.0.4.0/24)", got, want)
		}
	})

	t.Run("chain_rules.json: one portrules rule", func(t *testing.T) {
		got, err := parseNftChainRules(readTestdata(t, "real-alma10/chain_rules.json"))
		if err != nil {
			t.Fatalf("parseNftChainRules: %v", err)
		}
		want := []nftRuleRef{{Handle: 32, Comment: "defensia-rule:block:tcp:-:18099"}}
		if len(got) != len(want) || got[0] != want[0] {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})
}
