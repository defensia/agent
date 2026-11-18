//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/defensia/agent/internal/firewall"
)

// nftApplicable guards every test in this file: nftables-only, requires
// root, pauses the agent, and re-selects nftables explicitly so a test
// never silently runs against whatever backend Reselect would pick by
// accident. Returns false (and logs n/a) when this VM isn't an nftables VM.
func nftApplicable(t *testing.T) bool {
	t.Helper()
	requireRoot(t)
	if fwMode(t) != "nftables" {
		t.Logf("n/a: nftables-only test, this VM's expected backend is %q", fwMode(t))
		return false
	}
	pauseAgent(t)
	if got := firewall.Reselect(); got != "nftables" {
		t.Fatalf("Reselect() = %q, want nftables", got)
	}
	return true
}

func TestLabNftTableShape(t *testing.T) {
	if !nftApplicable(t) {
		return
	}

	out, err := sh(t, "nft", "-j", "list", "table", "inet", "defensia")
	if err != nil {
		t.Fatalf("nft -j list table inet defensia: %v", err)
	}
	gotNames := nftJSONNames(t, out)
	for _, want := range []string{"input", "protected", "portrules", "geo", "bans4", "bans6", "protected4", "protected6"} {
		if !gotNames[want] {
			t.Errorf("nft -j list table inet defensia missing chain/set named %q\noutput: %s", want, out)
		}
	}

	chainOut, err := sh(t, "nft", "-j", "list", "chain", "inet", "defensia", "input")
	if err != nil {
		t.Fatalf("nft -j list chain inet defensia input: %v", err)
	}
	var chainTop struct {
		Nftables []struct {
			Chain *struct {
				Hook   string `json:"hook"`
				Prio   int    `json:"prio"`
				Policy string `json:"policy"`
			} `json:"chain"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(chainOut), &chainTop); err != nil {
		t.Fatalf("parse nft -j list chain inet defensia input: %v\n%s", err, chainOut)
	}
	found := false
	for _, e := range chainTop.Nftables {
		if e.Chain != nil && e.Chain.Hook != "" {
			found = true
			if e.Chain.Hook != "input" || e.Chain.Prio != -10 || e.Chain.Policy != "accept" {
				t.Errorf("input chain = hook=%q prio=%d policy=%q, want hook=input prio=-10 policy=accept", e.Chain.Hook, e.Chain.Prio, e.Chain.Policy)
			}
		}
	}
	if !found {
		t.Errorf("nft -j list chain inet defensia input has no hook/prio/policy entry\noutput: %s", chainOut)
	}

	bans4Out, err := sh(t, "nft", "-j", "list", "set", "inet", "defensia", "bans4")
	if err != nil {
		t.Fatalf("nft -j list set inet defensia bans4: %v", err)
	}
	if !strings.Contains(bans4Out, "timeout") || !strings.Contains(bans4Out, "65536") {
		t.Errorf("nft -j list set inet defensia bans4 missing timeout flag or size 65536\noutput: %s", bans4Out)
	}

	version, _ := sh(t, "nft", "--version")
	t.Logf("nft --version: %s", version)
}

// nftJSONNames extracts every "name" field nft -j reports for a table's
// chains and sets (structural parse, robust to nft's own JSON formatting —
// unlike substring matching on raw text).
func nftJSONNames(t *testing.T, out string) map[string]bool {
	t.Helper()
	var top struct {
		Nftables []struct {
			Chain *struct {
				Name string `json:"name"`
			} `json:"chain"`
			Set *struct {
				Name string `json:"name"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(out), &top); err != nil {
		t.Fatalf("parse nft JSON: %v\n%s", err, out)
	}
	names := map[string]bool{}
	for _, e := range top.Nftables {
		if e.Chain != nil {
			names[e.Chain.Name] = true
		}
		if e.Set != nil {
			names[e.Set.Name] = true
		}
	}
	return names
}

// countNftSetElements structurally parses `nft -j list set ...` and returns
// the number of elements, correctly handling both bare-string elements
// (ipset-style, no extra metadata) and {"elem":{"val":...}} wrapped elements
// (timeout/interval sets) — a plain substring count of `"elem"` undercounts
// whichever representation nft chose not to use for a given element.
func countNftSetElements(t *testing.T, set string) int {
	t.Helper()
	out, err := sh(t, "nft", "-j", "list", "set", "inet", "defensia", set)
	if err != nil {
		t.Fatalf("nft -j list set inet defensia %s: %v", set, err)
	}
	var top struct {
		Nftables []struct {
			Set *struct {
				Elem []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(out), &top); err != nil {
		t.Fatalf("parse nft set JSON for %s: %v\n%s", set, err, out)
	}
	for _, e := range top.Nftables {
		if e.Set != nil {
			return len(e.Set.Elem)
		}
	}
	return 0
}

func TestLabNftBanDropsPackets(t *testing.T) {
	if !nftApplicable(t) {
		return
	}
	_, nsV4, _, nsV6 := setupNetns(t)

	v4URL := fmt.Sprintf("http://%s:%s/", hostV4Addr, httpPort)
	v6URL := fmt.Sprintf("http://[%s]:%s/", hostV6Addr, httpPort)

	if !nsReach(t, v4URL) {
		t.Fatalf("lab netns broken: v4 control probe unreachable before any ban")
	}
	if !nsReach(t, v6URL) {
		t.Fatalf("lab netns broken: v6 control probe unreachable before any ban")
	}

	if err := firewall.BanIP(nsV4); err != nil {
		t.Fatalf("BanIP(%s): %v", nsV4, err)
	}
	if nsReach(t, v4URL) {
		t.Fatalf("v4 still reachable after BanIP(%s)", nsV4)
	}

	if err := firewall.BanIP(nsV6); err != nil {
		t.Fatalf("BanIP(%s): %v", nsV6, err)
	}
	if nsReach(t, v6URL) {
		t.Fatalf("v6 still reachable after BanIP(%s)", nsV6)
	}

	if err := firewall.UnbanIP(nsV4); err != nil {
		t.Fatalf("UnbanIP(%s): %v", nsV4, err)
	}
	if err := firewall.UnbanIP(nsV6); err != nil {
		t.Fatalf("UnbanIP(%s): %v", nsV6, err)
	}
	if !nsReach(t, v4URL) {
		t.Fatalf("v4 still unreachable after UnbanIP(%s)", nsV4)
	}
	if !nsReach(t, v6URL) {
		t.Fatalf("v6 still unreachable after UnbanIP(%s)", nsV6)
	}
}

func TestLabNftBanExpiry(t *testing.T) {
	if !nftApplicable(t) {
		return
	}
	_, nsV4, _, _ := setupNetns(t)
	v4URL := fmt.Sprintf("http://%s:%s/", hostV4Addr, httpPort)

	if err := firewall.BanIPFor(nsV4, 4*time.Second); err != nil {
		t.Fatalf("BanIPFor(%s, 4s): %v", nsV4, err)
	}

	setOut, err := sh(t, "nft", "-j", "list", "set", "inet", "defensia", "bans4")
	if err != nil {
		t.Fatalf("nft -j list set inet defensia bans4: %v", err)
	}
	if !strings.Contains(setOut, "timeout") {
		t.Fatalf("banned element has no timeout in the kernel: %s", setOut)
	}
	if nsReach(t, v4URL) {
		t.Fatalf("v4 still reachable immediately after a 4s ban")
	}

	time.Sleep(7 * time.Second)

	if _, err := sh(t, "nft", "get", "element", "inet", "defensia", "bans4", "{", nsV4, "}"); err == nil {
		t.Fatalf("element %s still present in bans4 after its 4s timeout should have expired", nsV4)
	}
	if !nsReach(t, v4URL) {
		t.Fatalf("v4 still unreachable after the ban's timeout expired")
	}
}

// nftElementTimeout reads one set element's current `timeout` (seconds) via
// `nft -j list set`. Returns (0, false) if the element is not present.
func nftElementTimeout(t *testing.T, set, ip string) (int, bool) {
	t.Helper()
	out, err := sh(t, "nft", "-j", "list", "set", "inet", "defensia", set)
	if err != nil {
		t.Fatalf("nft -j list set inet defensia %s: %v", set, err)
	}
	var top struct {
		Nftables []struct {
			Set *struct {
				Elem []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(out), &top); err != nil {
		t.Fatalf("parse %s JSON: %v", set, err)
	}
	for _, entry := range top.Nftables {
		if entry.Set == nil {
			continue
		}
		for _, raw := range entry.Set.Elem {
			var obj struct {
				Elem struct {
					Val     string `json:"val"`
					Timeout int    `json:"timeout"`
				} `json:"elem"`
			}
			if err := json.Unmarshal(raw, &obj); err == nil && obj.Elem.Val == ip {
				return obj.Elem.Timeout, true
			}
		}
	}
	return 0, false
}

// TestLabNftBanReAddRefreshesTTL settles phase 17's independent review
// WARN-05 (2026-11-18): "`add element` never *updates* an element already
// present... I could not settle [whether a duplicate aborts the whole
// chunk] from the repo, and nothing in it tries to." The self-heal design
// documented in 17-RESEARCH.md depends on `BanBatch` tolerating (and
// ideally refreshing) a re-add of an IP the panel already has banned with
// an older TTL — e.g. after the ban-escalation 24h -> 7d bump, or after a
// restart re-syncs the full ban list. This proves it against the real
// kernel instead of assuming: a mixed batch (one already-present IP with a
// new, longer TTL, plus two brand-new IPs) in the exact same ApplyBanEntries
// call that production code uses.
func TestLabNftBanReAddRefreshesTTL(t *testing.T) {
	if !nftApplicable(t) {
		return
	}
	firewall.CleanupStaleBans(map[string]bool{}, nil)

	existing := "198.51.100.254"
	fresh1 := "198.51.100.246"
	fresh2 := "198.51.100.247"

	if applied := firewall.ApplyBanEntries([]firewall.BanEntry{{IP: existing, TTL: 5 * time.Second}}); applied != 1 {
		t.Fatalf("first ApplyBanEntries(%s, 5s) applied=%d, want 1", existing, applied)
	}
	before, ok := nftElementTimeout(t, "bans4", existing)
	if !ok {
		t.Fatalf("%s not found in bans4 right after the first ApplyBanEntries", existing)
	}
	if before < 1 || before > 5 {
		t.Fatalf("%s initial timeout = %d, want 1-5 (just set to 5s)", existing, before)
	}

	// The batch that matters: existing + new TTL, alongside two IPs that
	// have never been banned, all three in one BanBatch/nft -f - transaction
	// — exactly the shape a panel sync produces after a TTL escalation.
	batch := []firewall.BanEntry{
		{IP: existing, TTL: 600 * time.Second},
		{IP: fresh1, TTL: 600 * time.Second},
		{IP: fresh2, TTL: 600 * time.Second},
	}
	if applied := firewall.ApplyBanEntries(batch); applied != 3 {
		t.Fatalf("second ApplyBanEntries (existing + 2 new, mixed TTLs) applied=%d, want 3 — "+
			"a duplicate element must not abort the whole nft transaction", applied)
	}

	after, ok := nftElementTimeout(t, "bans4", existing)
	if !ok {
		t.Fatalf("%s missing from bans4 after the re-add batch", existing)
	}
	if after <= before {
		t.Fatalf("%s timeout after re-add = %d, want > %d (the panel's longer TTL should have been re-armed, not left at the original ~5s)", existing, after, before)
	}
	if after < 500 {
		t.Fatalf("%s timeout after re-add = %d, want close to 600 (the new TTL)", existing, after)
	}

	for _, ip := range []string{fresh1, fresh2} {
		tt, ok := nftElementTimeout(t, "bans4", ip)
		if !ok {
			t.Fatalf("%s (brand-new in the same batch as a duplicate) never reached the kernel", ip)
		}
		if tt < 500 {
			t.Fatalf("%s timeout = %d, want close to 600", ip, tt)
		}
	}

	if removed := firewall.CleanupStaleBans(map[string]bool{}, nil); removed != 3 {
		t.Fatalf("cleanup removed=%d, want 3", removed)
	}
}

func TestLabNftBatchAndCleanup(t *testing.T) {
	if !nftApplicable(t) {
		return
	}

	// Start from a known-empty baseline: a leftover element from an earlier
	// run or a preceding test (e.g. one that bans with a long TTL) would
	// otherwise inflate this test's exact-count assertions below.
	firewall.CleanupStaleBans(map[string]bool{}, nil)

	entries := make([]firewall.BanEntry, 0, 3500)
	var v4IPs, v6IPs []string
	for i := 0; i < 3000; i++ {
		ip := fmt.Sprintf("198.18.%d.%d", i/250, i%250+1)
		entries = append(entries, firewall.BanEntry{IP: ip})
		v4IPs = append(v4IPs, ip)
	}
	for i := 0; i < 500; i++ {
		ip := fmt.Sprintf("2001:db8:b17::%x", i+1)
		entries = append(entries, firewall.BanEntry{IP: ip})
		v6IPs = append(v6IPs, ip)
	}

	start := time.Now()
	applied := firewall.ApplyBanEntries(entries)
	t.Logf("ApplyBanEntries(%d entries) took %s", len(entries), time.Since(start))
	if applied != 3500 {
		t.Fatalf("ApplyBanEntries = %d, want 3500", applied)
	}

	countSet := func(set string) int { return countNftSetElements(t, set) }
	if n := countSet("bans4"); n != 3000 {
		t.Fatalf("bans4 element count = %d, want 3000", n)
	}
	if n := countSet("bans6"); n != 500 {
		t.Fatalf("bans6 element count = %d, want 500", n)
	}

	active := make(map[string]bool, 110)
	for _, ip := range v4IPs[:100] {
		active[ip] = true
	}
	for _, ip := range v6IPs[:10] {
		active[ip] = true
	}
	removed := firewall.CleanupStaleBans(active, nil)
	if removed != 3390 {
		t.Fatalf("CleanupStaleBans(100 v4 + 10 v6 active) = %d, want 3390", removed)
	}
	if n := countSet("bans4"); n != 100 {
		t.Fatalf("bans4 element count after cleanup = %d, want 100", n)
	}
	if n := countSet("bans6"); n != 10 {
		t.Fatalf("bans6 element count after cleanup = %d, want 10", n)
	}

	if removed := firewall.CleanupStaleBans(map[string]bool{}, nil); removed != 110 {
		t.Fatalf("final CleanupStaleBans({}, nil) = %d, want 110 (empties both sets)", removed)
	}
	if n := countSet("bans4"); n != 0 {
		t.Fatalf("bans4 not empty after final cleanup: %d elements", n)
	}
	if n := countSet("bans6"); n != 0 {
		t.Fatalf("bans6 not empty after final cleanup: %d elements", n)
	}
}

func TestLabNftRulesLifecycle(t *testing.T) {
	if !nftApplicable(t) {
		return
	}
	setupNetns(t)
	extraAddr := hostV4Addr + ":18081"
	closeExtra := startExtraListener(t, extraAddr)
	t.Cleanup(closeExtra)

	port := 18081
	spec := firewall.RuleSpec{Type: "block", Protocol: "tcp", Port: &port}

	if err := firewall.ApplyRule(spec); err != nil {
		t.Fatalf("ApplyRule (1st): %v", err)
	}
	if err := firewall.ApplyRule(spec); err != nil {
		t.Fatalf("ApplyRule (2nd, idempotent): %v", err)
	}

	rulesOut, err := sh(t, "nft", "-a", "list", "chain", "inet", "defensia", "portrules")
	if err != nil {
		t.Fatalf("nft -a list chain inet defensia portrules: %v", err)
	}
	wantComment := `defensia-rule:block:tcp:-:18081`
	n := strings.Count(rulesOut, wantComment)
	if n != 1 {
		t.Fatalf("comment %q appears %d times in the rules chain, want exactly 1:\n%s", wantComment, n, rulesOut)
	}

	url18081 := "http://" + extraAddr + "/"
	url18080 := fmt.Sprintf("http://%s:%s/", hostV4Addr, httpPort)
	if nsReach(t, url18081) {
		t.Fatalf("port 18081 still reachable after ApplyRule blocked it")
	}
	if !nsReach(t, url18080) {
		t.Fatalf("port 18080 (unrelated) became unreachable — rule leaked beyond its port")
	}

	rules, err := firewall.ListRules()
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	found := false
	for _, r := range rules {
		if r.Type == "block" && r.Protocol == "tcp" && r.Port == 18081 {
			found = true
		}
	}
	if !found {
		t.Fatalf("ListRules() = %+v, missing the block/tcp/18081 rule", rules)
	}

	if err := firewall.RemoveRule(spec); err != nil {
		t.Fatalf("RemoveRule: %v", err)
	}
	if !nsReach(t, url18081) {
		t.Fatalf("port 18081 still unreachable after RemoveRule")
	}

	cidrSpec := firewall.RuleSpec{Type: "allow", Protocol: "all", IPRange: strPtrLocal("203.0.113.0/24")}
	if err := firewall.ApplyRule(cidrSpec); err != nil {
		t.Fatalf("ApplyRule (CIDR allow): %v", err)
	}
	rules, err = firewall.ListRules()
	if err != nil {
		t.Fatalf("ListRules after CIDR rule: %v", err)
	}
	foundCIDR := false
	for _, r := range rules {
		if r.Type == "allow" && r.Source == "203.0.113.0/24" {
			foundCIDR = true
		}
	}
	if !foundCIDR {
		t.Fatalf("ListRules() = %+v, missing the allow/203.0.113.0/24 rule", rules)
	}
	if err := firewall.RemoveRule(cidrSpec); err != nil {
		t.Fatalf("RemoveRule (CIDR allow): %v", err)
	}
}

func strPtrLocal(s string) *string { return &s }

func TestLabNftGeoblock(t *testing.T) {
	if !nftApplicable(t) {
		return
	}
	// This test whitelists nsV4 into protected4 — that set is NOT reset by
	// Ensure() (only the input/protected CHAIN RULES are flushed and
	// rebuilt; set CONTENTS persist across tests), so a later test banning
	// the same fixed nsV4Addr would otherwise find it still "protected" and
	// see its own ban silently overridden. Always clear both on exit.
	t.Cleanup(func() {
		_, _ = sh(t, "nft", "flush", "set", "inet", "defensia", "protected4")
		_, _ = sh(t, "nft", "flush", "set", "inet", "defensia", "protected6")
	})
	_, nsV4, _, _ := setupNetns(t)
	v4URL := fmt.Sprintf("http://%s:%s/", hostV4Addr, httpPort)
	v6URL := fmt.Sprintf("http://[%s]:%s/", hostV6Addr, httpPort)

	provider := func(cc string) ([]string, error) {
		if cc != "ZZ" {
			return nil, nil
		}
		cidrs := make([]string, 0, 60002)
		for i := 0; i < 60000; i++ {
			cidrs = append(cidrs, fmt.Sprintf("11.%d.%d.0/24", i/256, i%256))
		}
		cidrs = append(cidrs, "11.0.0.0/16") // deliberate overlap with the /24s above
		cidrs = append(cidrs, hostV4Addr+"/24")
		return cidrs, nil
	}

	gb := firewall.NewGeoBlocker(provider, "")

	start := time.Now()
	gb.ApplyCountryBlocks([]string{"ZZ"})
	elapsed := time.Since(start)
	t.Logf("ApplyCountryBlocks([ZZ], ~60k overlapping CIDRs) took %s", elapsed)
	if elapsed > 60*time.Second {
		t.Fatalf("ApplyCountryBlocks took %s, want < 60s", elapsed)
	}
	if n, why := gb.Unapplied(); n != 0 {
		t.Fatalf("Unapplied() = (%d, %q), want (0, \"\")", n, why)
	}

	setOut, err := sh(t, "nft", "list", "set", "inet", "defensia", "geo_zz")
	if err != nil || strings.TrimSpace(setOut) == "" {
		t.Fatalf("nft list set inet defensia geo_zz empty or missing: %v", err)
	}
	chainOut, err := sh(t, "nft", "list", "chain", "inet", "defensia", "geo")
	if err != nil || !strings.Contains(chainOut, "defensia-geo:zz") {
		t.Fatalf("geo chain missing defensia-geo:zz comment: %v\n%s", err, chainOut)
	}

	if nsReach(t, v4URL) {
		t.Fatalf("v4 still reachable after blocking ZZ (which includes the host's own /24)")
	}
	if !nsReach(t, v6URL) {
		t.Fatalf("v6 became unreachable — IPv4 country sets must not affect v6 traffic")
	}

	// Country-block matching is on the packet's SOURCE address, and the
	// traffic under test flows ns -> host (source = nsV4, not hostV4Addr) —
	// whitelisting must protect the actual source being blocked.
	gb.SetWhitelistedIPs([]string{nsV4})
	gb.ApplyCountryBlocks([]string{"ZZ"})

	protectedOut, err := sh(t, "nft", "list", "set", "inet", "defensia", "protected4")
	if err != nil || !strings.Contains(protectedOut, nsV4) {
		t.Fatalf("protected4 does not contain %s: %v\n%s", nsV4, err, protectedOut)
	}
	if !nsReach(t, v4URL) {
		t.Fatalf("v4 still unreachable after whitelisting the ns source IP")
	}

	gb.ApplyCountryBlocks(nil)
	if _, err := sh(t, "nft", "list", "set", "inet", "defensia", "geo_zz"); err == nil {
		t.Fatalf("geo_zz set still exists after ApplyCountryBlocks(nil)")
	}
	chainOut, _ = sh(t, "nft", "list", "chain", "inet", "defensia", "geo")
	if strings.Contains(chainOut, "defensia-geo:zz") {
		t.Fatalf("geo chain still has the defensia-geo:zz rule after ApplyCountryBlocks(nil)")
	}
	if !nsReach(t, v4URL) {
		t.Fatalf("v4 still unreachable after removing every country block")
	}
}

func TestLabNftSelfHealAfterTableDelete(t *testing.T) {
	if !nftApplicable(t) {
		return
	}
	_, nsV4, _, _ := setupNetns(t)
	v4URL := fmt.Sprintf("http://%s:%s/", hostV4Addr, httpPort)

	if n := firewall.ApplyBanEntries([]firewall.BanEntry{{IP: nsV4}}); n != 1 {
		t.Fatalf("ApplyBanEntries = %d, want 1", n)
	}
	if nsReach(t, v4URL) {
		t.Fatalf("v4 still reachable right after banning it")
	}

	gen := firewall.Generation()

	if _, err := sh(t, "nft", "delete", "table", "inet", "defensia"); err != nil {
		t.Fatalf("nft delete table inet defensia: %v", err)
	}
	if !nsReach(t, v4URL) {
		t.Fatalf("v4 still unreachable right after the table was deleted (state should be lost)")
	}

	if err := firewall.Ensure(); err != nil {
		t.Fatalf("Ensure() after table delete: %v", err)
	}
	if firewall.Generation() <= gen {
		t.Fatalf("Generation() did not increase after Ensure() recreated the table")
	}

	if n := firewall.ApplyBanEntries([]firewall.BanEntry{{IP: nsV4}}); n != 1 {
		t.Fatalf("ApplyBanEntries after self-heal = %d, want 1", n)
	}
	if nsReach(t, v4URL) {
		t.Fatalf("v4 still reachable after re-banning post self-heal")
	}
	if err := firewall.UnbanIP(nsV4); err != nil {
		t.Fatalf("UnbanIP: %v", err)
	}
}

func TestLabNftCoexistsFirewalld(t *testing.T) {
	if !nftApplicable(t) {
		return
	}
	if out, err := sh(t, "systemctl", "is-active", "firewalld"); err != nil || out != "active" {
		t.Logf("n/a: firewalld is not active on this VM")
		return
	}
	// exec.LookPath("csf") is Go's equivalent of `command -v csf`: never run
	// `nft flush ruleset` on a VM where csf is installed (its rollback does
	// not expect the whole ruleset to disappear mid-restart).
	if _, err := exec.LookPath("csf"); err == nil {
		t.Logf("n/a: csf is present on this VM — never run nft flush ruleset where csf is installed")
		return
	}

	setupNetns(t)
	v4URL := fmt.Sprintf("http://%s:%s/", hostV4Addr, httpPort)
	if err := firewall.BanIP(nsV4Addr); err != nil {
		t.Fatalf("BanIP: %v", err)
	}
	if nsReach(t, v4URL) {
		t.Fatalf("v4 still reachable right after banning it")
	}

	checkPresent := func(step string) {
		if _, err := sh(t, "nft", "get", "element", "inet", "defensia", "bans4", "{", nsV4Addr, "}"); err != nil {
			t.Fatalf("ban element gone after %s: %v", step, err)
		}
	}

	if _, err := sh(t, "firewall-cmd", "--reload"); err != nil {
		t.Fatalf("firewall-cmd --reload: %v", err)
	}
	checkPresent("firewall-cmd --reload")

	if _, err := sh(t, "systemctl", "restart", "firewalld"); err != nil {
		t.Fatalf("systemctl restart firewalld: %v", err)
	}
	checkPresent("systemctl restart firewalld")

	// firewalld reports "active" as soon as systemd starts it, but it
	// re-populates its own nftables table asynchronously right after —
	// poll briefly instead of treating the first check as authoritative.
	var fwTableErr error
	for i := 0; i < 30; i++ {
		if _, err := sh(t, "nft", "list", "table", "inet", "firewalld"); err == nil {
			fwTableErr = nil
			break
		} else {
			fwTableErr = err
		}
		time.Sleep(200 * time.Millisecond)
	}
	if fwTableErr != nil {
		t.Fatalf("nft list table inet firewalld: %v (firewalld's own table should exist independently)", fwTableErr)
	}

	if _, err := sh(t, "nft", "flush", "ruleset"); err != nil {
		t.Fatalf("nft flush ruleset: %v", err)
	}
	if _, err := sh(t, "nft", "list", "table", "inet", "defensia"); err == nil {
		t.Fatalf("table inet defensia still exists after nft flush ruleset (test setup invalid)")
	}

	if err := firewall.Ensure(); err != nil {
		t.Fatalf("Ensure() after flush ruleset: %v", err)
	}
	if n := firewall.ApplyBanEntries([]firewall.BanEntry{{IP: nsV4Addr}}); n != 1 {
		t.Fatalf("ApplyBanEntries after self-heal = %d, want 1", n)
	}
	checkPresent("Ensure + ApplyBanEntries after flush ruleset")

	t.Cleanup(func() {
		_, _ = sh(t, "systemctl", "restart", "firewalld")
		// `firewall-cmd --state` can print a transient dbus-connection
		// warning line before "running" right after a restart — poll
		// briefly instead of treating the very first check as final.
		for i := 0; i < 30; i++ {
			if out, err := sh(t, "firewall-cmd", "--state"); err == nil && strings.Contains(out, "running") {
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
		out, err := sh(t, "firewall-cmd", "--state")
		t.Errorf("firewalld did not come back up after test cleanup: out=%q err=%v", out, err)
	})
}

func TestLabNftCoexistsCSF(t *testing.T) {
	if !nftApplicable(t) {
		return
	}
	if _, err := exec.LookPath("csf"); err != nil {
		t.Logf("n/a: no csf on this VM")
		return
	}
	if _, err := sh(t, "csf", "-v"); err != nil {
		t.Logf("n/a: csf present but not active/working on this VM")
		return
	}

	setupNetns(t)
	if err := firewall.BanIP(nsV4Addr); err != nil {
		t.Fatalf("BanIP: %v", err)
	}

	if _, err := shTimeout(t, 120*time.Second, "csf", "-r"); err != nil {
		t.Fatalf("csf -r: %v", err)
	}

	if _, err := sh(t, "nft", "get", "element", "inet", "defensia", "bans4", "{", nsV4Addr, "}"); err != nil {
		t.Fatalf("ban element gone after csf -r: %v", err)
	}
	rulesOut, err := sh(t, "iptables", "-S", "INPUT")
	if err != nil {
		t.Fatalf("iptables -S INPUT: %v", err)
	}
	if n := len(strings.Split(strings.TrimSpace(rulesOut), "\n")); n <= 3 {
		t.Fatalf("iptables -S INPUT has only %d lines after csf -r, want CSF's own rules restored (> 3)", n)
	}
	if _, err := sh(t, "nft", "list", "table", "inet", "defensia"); err != nil {
		t.Fatalf("nft list table inet defensia: %v (table must survive csf -r)", err)
	}
}

func TestLabNftCaptureFixtures(t *testing.T) {
	if !nftApplicable(t) {
		return
	}
	if os.Getenv("LAB_CAPTURE_NFT_FIXTURES") != "1" {
		t.Logf("n/a: LAB_CAPTURE_NFT_FIXTURES not set")
		return
	}

	outDir := "/root/nft-fixtures"
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", outDir, err)
	}

	// bans4: two timed elements + one permanent.
	if err := firewall.BanIPFor("198.51.100.201", 300*time.Second); err != nil {
		t.Fatalf("BanIPFor 1: %v", err)
	}
	if err := firewall.BanIPFor("198.51.100.202", 600*time.Second); err != nil {
		t.Fatalf("BanIPFor 2: %v", err)
	}
	if err := firewall.BanIP("198.51.100.203"); err != nil {
		t.Fatalf("BanIP (permanent): %v", err)
	}
	bans4Out, err := sh(t, "nft", "-j", "list", "set", "inet", "defensia", "bans4")
	if err != nil {
		t.Fatalf("nft -j list set inet defensia bans4: %v", err)
	}
	if err := os.WriteFile(outDir+"/set_bans4.json", []byte(bans4Out), 0o644); err != nil {
		t.Fatalf("write set_bans4.json: %v", err)
	}

	// A small 3-CIDR country for a clean geo fixture (distinct cc "ZY" so it
	// never collides with TestLabNftGeoblock's "ZZ").
	gbProvider := func(cc string) ([]string, error) {
		if cc != "ZY" {
			return nil, nil
		}
		return []string{"192.0.2.0/24", "192.0.3.0/24", "192.0.4.0/24"}, nil
	}
	gb := firewall.NewGeoBlocker(gbProvider, "")
	gb.ApplyCountryBlocks([]string{"ZY"})
	geoOut, err := sh(t, "nft", "-j", "list", "set", "inet", "defensia", "geo_zy")
	if err != nil {
		t.Fatalf("nft -j list set inet defensia geo_zy: %v", err)
	}
	if err := os.WriteFile(outDir+"/set_geo_zy.json", []byte(geoOut), 0o644); err != nil {
		t.Fatalf("write set_geo_zy.json: %v", err)
	}
	gb.ApplyCountryBlocks(nil)

	// One real rule, then capture the chain listing.
	port := 18099
	spec := firewall.RuleSpec{Type: "block", Protocol: "tcp", Port: &port}
	if err := firewall.ApplyRule(spec); err != nil {
		t.Fatalf("ApplyRule: %v", err)
	}
	rulesOut, err := sh(t, "nft", "-j", "-a", "list", "chain", "inet", "defensia", "portrules")
	if err != nil {
		t.Fatalf("nft -j -a list chain inet defensia portrules: %v", err)
	}
	if err := os.WriteFile(outDir+"/chain_rules.json", []byte(rulesOut), 0o644); err != nil {
		t.Fatalf("write chain_rules.json: %v", err)
	}
	_ = firewall.RemoveRule(spec)

	t.Logf("captured fixtures to %s: set_bans4.json, set_geo_zy.json, chain_rules.json", outDir)
}

// shTimeout runs sh under a hard deadline, failing (not hanging) if the
// command doesn't finish in time. Used for csf -r, which has its own
// internal retry/backoff and can legitimately take tens of seconds.
func shTimeout(t *testing.T, timeout time.Duration, name string, args ...string) (string, error) {
	t.Helper()
	done := make(chan struct{})
	var out string
	var err error
	go func() {
		out, err = sh(t, name, args...)
		close(done)
	}()
	select {
	case <-done:
		return out, err
	case <-time.After(timeout):
		t.Fatalf("%s %v did not complete within %s", name, args, timeout)
		return "", nil
	}
}
