package firewall

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestNftEnsureScriptGolden(t *testing.T) {
	want, err := os.ReadFile("testdata/nft/ensure.nft")
	if err != nil {
		t.Fatalf("reading golden file: %v", err)
	}
	if got := nftEnsureScript(); got != string(want) {
		t.Fatalf("nftEnsureScript() mismatch.\ngot:\n%s\nwant:\n%s", got, string(want))
	}
}

func TestNftBanScript(t *testing.T) {
	t.Run("mixed ttl, two entries", func(t *testing.T) {
		got := nftBanScript("bans4", []BanEntry{
			{IP: "1.2.3.4", TTL: 0},
			{IP: "5.6.7.8", TTL: 3600 * time.Second},
		})
		want := "add element inet defensia bans4 { 1.2.3.4, 5.6.7.8 timeout 3600s }\n"
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("sub-second ttl rounds up", func(t *testing.T) {
		got := nftBanScript("bans4", []BanEntry{{IP: "1.2.3.4", TTL: 1500 * time.Millisecond}})
		want := "add element inet defensia bans4 { 1.2.3.4 timeout 2s }\n"
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("chunks of 1000", func(t *testing.T) {
		entries := make([]BanEntry, 2500)
		for i := range entries {
			entries[i] = BanEntry{IP: "10.0.0.1"}
		}
		got := nftBanScript("bans4", entries)
		lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
		if len(lines) != 3 {
			t.Fatalf("got %d lines, want 3 (chunks of 1000 over 2500 entries)", len(lines))
		}
	})

	t.Run("empty", func(t *testing.T) {
		if got := nftBanScript("bans4", nil); got != "" {
			t.Fatalf("got %q, want empty string", got)
		}
	})
}

func TestNftUnbanScript(t *testing.T) {
	got := nftUnbanScript("bans6", "2001:db8::1")
	want := "delete element inet defensia bans6 { 2001:db8::1 }\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNftRuleExpr(t *testing.T) {
	strp := func(s string) *string { return &s }
	intp := func(i int) *int { return &i }

	cases := []struct {
		name     string
		spec     RuleSpec
		wantExpr string
		wantKey  string
		wantErr  bool
	}{
		{
			name:     "block tcp with IP and port",
			spec:     RuleSpec{Type: "block", Protocol: "tcp", IPAddress: strp("203.0.113.4"), Port: intp(22)},
			wantExpr: "ip saddr 203.0.113.4 tcp dport 22 drop",
			wantKey:  "defensia-rule:block:tcp:203.0.113.4:22",
		},
		{
			name:     "allow all with CIDR",
			spec:     RuleSpec{Type: "allow", Protocol: "all", IPRange: strp("10.0.0.0/8")},
			wantExpr: "ip saddr 10.0.0.0/8 accept",
			wantKey:  "defensia-rule:allow:all:10.0.0.0/8:0",
		},
		{
			name:     "empty protocol with port and no source normalises to tcp",
			spec:     RuleSpec{Type: "block", Protocol: "", Port: intp(8080)},
			wantExpr: "tcp dport 8080 drop",
			wantKey:  "defensia-rule:block:tcp:-:8080",
		},
		{
			name:     "udp with port, no source",
			spec:     RuleSpec{Type: "block", Protocol: "udp", Port: intp(53)},
			wantExpr: "udp dport 53 drop",
			wantKey:  "defensia-rule:block:udp:-:53",
		},
		{
			name:     "icmp with IPv6 CIDR source, no port",
			spec:     RuleSpec{Type: "block", Protocol: "icmp", IPRange: strp("2001:db8::/32")},
			wantExpr: "ip6 saddr 2001:db8::/32 meta l4proto ipv6-icmp drop",
			wantKey:  "defensia-rule:block:icmp:2001:db8::/32:0",
		},
		{
			name:     "tcp no port with source",
			spec:     RuleSpec{Type: "block", Protocol: "tcp", IPAddress: strp("203.0.113.9")},
			wantExpr: "ip saddr 203.0.113.9 meta l4proto tcp drop",
			wantKey:  "defensia-rule:block:tcp:203.0.113.9:0",
		},
		{
			name:     "IPRange normalised to network address",
			spec:     RuleSpec{Type: "block", Protocol: "tcp", IPRange: strp("203.0.113.77/24"), Port: intp(80)},
			wantExpr: "ip saddr 203.0.113.0/24 tcp dport 80 drop",
			wantKey:  "defensia-rule:block:tcp:203.0.113.0/24:80",
		},
		{
			name:    "no source and no port errors",
			spec:    RuleSpec{Type: "block", Protocol: "all"},
			wantErr: true,
		},
		{
			name:    "invalid IP errors",
			spec:    RuleSpec{Type: "block", Protocol: "tcp", IPAddress: strp("not-an-ip"), Port: intp(80)},
			wantErr: true,
		},
		{
			name:    "icmp with port but no source errors (port ignored, nothing left to match)",
			spec:    RuleSpec{Type: "block", Protocol: "icmp", Port: intp(8)},
			wantErr: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			expr, key, err := nftRuleExpr(c.spec)
			if c.wantErr {
				if err == nil {
					t.Fatalf("nftRuleExpr(%+v) = nil error, want an error", c.spec)
				}
				return
			}
			if err != nil {
				t.Fatalf("nftRuleExpr(%+v): unexpected error: %v", c.spec, err)
			}
			if expr != c.wantExpr {
				t.Fatalf("expr = %q, want %q", expr, c.wantExpr)
			}
			if key != c.wantKey {
				t.Fatalf("key = %q, want %q", key, c.wantKey)
			}
		})
	}
}

func TestDecodeRuleKey(t *testing.T) {
	keys := []string{
		"defensia-rule:block:tcp:203.0.113.4:22",
		"defensia-rule:allow:all:10.0.0.0/8:0",
		"defensia-rule:block:tcp:-:8080",
		"defensia-rule:block:udp:-:53",
		"defensia-rule:block:icmp:2001:db8::/32:0",
		"defensia-rule:block:tcp:203.0.113.9:0",
		"defensia-rule:block:tcp:203.0.113.0/24:80",
	}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			rule, ok := decodeRuleKey(key)
			if !ok {
				t.Fatalf("decodeRuleKey(%q): ok = false, want true", key)
			}
			if rule.RawRule != key {
				t.Fatalf("RawRule = %q, want %q", rule.RawRule, key)
			}
			// Round trip: Source "" must render as "-" in the key and back.
			if rule.Source == "" && !strings.Contains(key, ":-:") {
				t.Fatalf("decoded empty Source but key has no '-' placeholder: %q", key)
			}
		})
	}

	t.Run("foreign comment", func(t *testing.T) {
		if _, ok := decodeRuleKey("defensia-geo:cn"); ok {
			t.Fatalf("decodeRuleKey on a foreign (geo) comment: ok = true, want false")
		}
		if _, ok := decodeRuleKey("something-else"); ok {
			t.Fatalf("decodeRuleKey on an unrelated comment: ok = true, want false")
		}
	})
}

func TestNftGeoScript(t *testing.T) {
	t.Run("addRule true", func(t *testing.T) {
		got, err := nftGeoReplaceScript("cn", []string{"1.0.1.0/24", "1.0.2.0/23"}, true)
		if err != nil {
			t.Fatalf("nftGeoReplaceScript: %v", err)
		}
		want := "add set inet defensia geo_cn { type ipv4_addr; flags interval; auto-merge; }\n" +
			"flush set inet defensia geo_cn\n" +
			"add element inet defensia geo_cn { 1.0.1.0/24, 1.0.2.0/23 }\n" +
			`add rule inet defensia geo ip saddr @geo_cn drop comment "defensia-geo:cn"` + "\n"
		if got != want {
			t.Fatalf("got:\n%q\nwant:\n%q", got, want)
		}
	})

	t.Run("addRule false omits the rule line", func(t *testing.T) {
		got, err := nftGeoReplaceScript("cn", []string{"1.0.1.0/24"}, false)
		if err != nil {
			t.Fatalf("nftGeoReplaceScript: %v", err)
		}
		if strings.Contains(got, "add rule") {
			t.Fatalf("addRule=false but script contains an add rule line: %q", got)
		}
	})

	t.Run("2500 cidrs chunk into 3 element lines", func(t *testing.T) {
		cidrs := make([]string, 2500)
		for i := range cidrs {
			cidrs[i] = "1.0.0.1/32"
		}
		got, err := nftGeoReplaceScript("cn", cidrs, false)
		if err != nil {
			t.Fatalf("nftGeoReplaceScript: %v", err)
		}
		n := strings.Count(got, "add element")
		if n != 3 {
			t.Fatalf("got %d 'add element' lines, want 3", n)
		}
	})

	t.Run("invalid cc errors", func(t *testing.T) {
		if _, err := nftGeoReplaceScript("C1", nil, false); err == nil {
			t.Fatalf("nftGeoReplaceScript(\"C1\", ...): want error")
		}
		if _, err := nftGeoReplaceScript("CHN", nil, false); err == nil {
			t.Fatalf("nftGeoReplaceScript(\"CHN\", ...): want error")
		}
	})
}

func TestNftGeoValidate(t *testing.T) {
	got := filterGeoCIDRs([]string{
		"1.0.1.0/24",
		"2001:db8::/32", // IPv6, dropped
		"0.0.0.0/0",     // default route, dropped
		"not-a-cidr",    // garbage, dropped
		"1.0.1.0/24",    // duplicate, dropped
		"1.0.9.9",       // bare IPv4 -> /32
		"1.0.2.0/23",
	})
	want := []string{"1.0.1.0/24", "1.0.9.9/32", "1.0.2.0/23"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("index %d: got %q, want %q (order matters: first occurrence)", i, got[i], want[i])
		}
	}
}

func TestNftProtectedScript(t *testing.T) {
	got := nftProtectedScript([]string{"a"}, nil)
	want := "flush set inet defensia protected4\n" +
		"add element inet defensia protected4 { a }\n" +
		"flush set inet defensia protected6\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
