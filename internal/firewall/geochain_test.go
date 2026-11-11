package firewall

import (
	"errors"
	"strings"
	"testing"
)

// fakeIptables models just enough of iptables for geoChain: which chains
// exist and the ordered rules inside each.
type fakeIptables struct {
	chains map[string][]string
	calls  []string
}

func newFakeIptables(chains ...string) *fakeIptables {
	f := &fakeIptables{chains: map[string][]string{}}
	for _, c := range chains {
		f.chains[c] = nil
	}
	return f
}

func (f *fakeIptables) run(args ...string) ([]byte, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	if len(args) < 2 {
		return nil, errors.New("bad args")
	}
	op, chain := args[0], args[1]
	rule := strings.Join(args[2:], " ")
	rules, exists := f.chains[chain]
	switch op {
	case "-S":
		if !exists {
			return []byte("No chain/target/match by that name."), errors.New("exit 1")
		}
	case "-N":
		if exists {
			return []byte("Chain already exists."), errors.New("exit 1")
		}
		f.chains[chain] = nil
	case "-X":
		delete(f.chains, chain)
	case "-F":
		if !exists {
			return nil, errors.New("exit 1")
		}
		f.chains[chain] = nil
	case "-A":
		f.chains[chain] = append(rules, rule)
	case "-I":
		// -I CHAIN 1 <rule>
		rule = strings.Join(args[3:], " ")
		f.chains[chain] = append([]string{rule}, rules...)
	case "-C", "-D":
		for i, r := range rules {
			if r == rule {
				if op == "-D" {
					f.chains[chain] = append(rules[:i:i], rules[i+1:]...)
				}
				return nil, nil
			}
		}
		return nil, errors.New("exit 1")
	}
	return nil, nil
}

func withFake(t *testing.T, f *fakeIptables) {
	t.Helper()
	orig := iptablesRun
	iptablesRun = f.run
	t.Cleanup(func() { iptablesRun = orig })
}

const jump = "-m conntrack --ctstate NEW -j DEFENSIA-GEO"

func TestEnsureGeoChainJumpsFirstFromInput(t *testing.T) {
	f := newFakeIptables("INPUT")
	f.chains["INPUT"] = []string{"-p tcp --dport 80 -j ACCEPT"} // e.g. ufw / hand-written allow
	withFake(t, f)

	if err := ensureGeoChain(); err != nil {
		t.Fatal(err)
	}
	if got := f.chains["INPUT"][0]; got != jump {
		t.Fatalf("INPUT[0] = %q, want the geo jump ahead of the existing ACCEPT", got)
	}
	if _, ok := f.chains["DOCKER-USER"]; ok {
		t.Fatal("DOCKER-USER must not be created on a host without Docker")
	}
}

func TestEnsureGeoChainCoversDockerPublishedPorts(t *testing.T) {
	f := newFakeIptables("INPUT", "DOCKER-USER")
	withFake(t, f)

	if err := ensureGeoChain(); err != nil {
		t.Fatal(err)
	}
	if len(f.chains["DOCKER-USER"]) != 1 || f.chains["DOCKER-USER"][0] != jump {
		t.Fatalf("DOCKER-USER = %v, want the geo jump", f.chains["DOCKER-USER"])
	}
}

func TestEnsureGeoChainIsIdempotent(t *testing.T) {
	f := newFakeIptables("INPUT", "DOCKER-USER")
	withFake(t, f)

	for i := 0; i < 3; i++ {
		if err := ensureGeoChain(); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(f.chains["INPUT"]); n != 1 {
		t.Fatalf("INPUT has %d rules after 3 syncs, want 1 jump", n)
	}
	if n := len(f.chains["DOCKER-USER"]); n != 1 {
		t.Fatalf("DOCKER-USER has %d rules after 3 syncs, want 1 jump", n)
	}
}

func TestGeoJumpOnlyMatchesNewConnections(t *testing.T) {
	// Replies to connections the server opens must never hit a country DROP.
	if !strings.Contains(strings.Join(geoJumpSpec(), " "), "--ctstate NEW") {
		t.Fatal("geo jump must be limited to NEW connections")
	}
}

func TestRebuildGeoChainPutsProtectedIPsFirst(t *testing.T) {
	f := newFakeIptables("INPUT", geoChain)
	f.chains[geoChain] = []string{"-m set --match-set defensia-geo-xx src -j DROP"} // stale
	withFake(t, f)

	if err := rebuildGeoChain([]string{"203.0.113.7", "198.51.100.1"}, false, nil, []string{"defensia-geo-cn", "defensia-geo-ru"}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"-s 203.0.113.7 -j RETURN",
		"-s 198.51.100.1 -j RETURN",
		"-m set --match-set defensia-geo-cn src -j DROP",
		"-m set --match-set defensia-geo-ru src -j DROP",
	}
	got := f.chains[geoChain]
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("chain = %v\nwant    %v", got, want)
	}
}

func TestTeardownGeoChainLeavesNoTrace(t *testing.T) {
	f := newFakeIptables("INPUT", "DOCKER-USER")
	withFake(t, f)
	if err := ensureGeoChain(); err != nil {
		t.Fatal(err)
	}
	if err := rebuildGeoChain(nil, false, nil, []string{"defensia-geo-cn"}); err != nil {
		t.Fatal(err)
	}

	teardownGeoChain()

	if _, ok := f.chains[geoChain]; ok {
		t.Fatal("chain still exists")
	}
	if len(f.chains["INPUT"]) != 0 || len(f.chains["DOCKER-USER"]) != 0 {
		t.Fatalf("jumps left behind: INPUT=%v DOCKER-USER=%v", f.chains["INPUT"], f.chains["DOCKER-USER"])
	}
}

func TestRemoveLegacyGeoRuleDropsEveryCopy(t *testing.T) {
	f := newFakeIptables("INPUT")
	legacy := "-m set --match-set defensia-geo-us src -j DROP"
	f.chains["INPUT"] = []string{legacy, "-j ACCEPT", legacy}
	withFake(t, f)

	removeLegacyGeoRule("defensia-geo-us")

	if strings.Join(f.chains["INPUT"], "|") != "-j ACCEPT" {
		t.Fatalf("INPUT = %v, want only the unrelated rule", f.chains["INPUT"])
	}
}

func TestRebuildGeoChainExemptionsComeBeforeEveryCountryDrop(t *testing.T) {
	f := newFakeIptables("INPUT", geoChain)
	withFake(t, f)

	if err := rebuildGeoChain([]string{"203.0.113.7"}, true, []int{25, 465, 587, 80}, []string{"defensia-geo-us"}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"-s 203.0.113.7 -j RETURN",
		"-m set --match-set defensia-geo-exempt src -j RETURN",
		"-p tcp -m multiport --dports 25,465,587,80 -j RETURN",
		"-m set --match-set defensia-geo-us src -j DROP",
	}
	if got := f.chains[geoChain]; strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("chain = %v\nwant    %v", got, want)
	}
}

func TestRebuildGeoChainWithoutExemptionsHasNoReturnForThem(t *testing.T) {
	f := newFakeIptables("INPUT", geoChain)
	withFake(t, f)

	if err := rebuildGeoChain(nil, false, nil, []string{"defensia-geo-cn"}); err != nil {
		t.Fatal(err)
	}
	if got := f.chains[geoChain]; len(got) != 1 || !strings.HasSuffix(got[0], "-j DROP") {
		t.Fatalf("chain = %v, want just the country DROP", got)
	}
}

func TestSetExemptionsKeepsOnlyValidIPv4AndCapsPorts(t *testing.T) {
	g := &GeoBlocker{activeCountries: map[string]bool{}}
	ports := []int{25, 465, 587, 80, 0, 70000}
	for i := 1000; i < 1020; i++ {
		ports = append(ports, i)
	}
	g.SetExemptions([]string{"66.249.64.0/27", " 40.77.167.0/24 ", "2001:4860:4801::/48", "nonsense", "66.249.64.5/27"}, ports)

	if strings.Join(g.exemptCIDRs, ",") != "40.77.167.0/24,66.249.64.0/27,66.249.64.0/27" {
		t.Fatalf("exemptCIDRs = %v", g.exemptCIDRs)
	}
	if len(g.exemptPorts) != 15 || g.exemptPorts[0] != 25 || g.exemptPorts[3] != 80 {
		t.Fatalf("exemptPorts = %v, want 15 valid ports starting 25,465,587,80", g.exemptPorts)
	}
}
