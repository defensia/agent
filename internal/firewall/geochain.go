package firewall

import (
	"fmt"
	"os/exec"
	"strings"
)

// geoChain holds every country-block rule. INPUT (and DOCKER-USER, when Docker
// is present) jump to it at position 1 for NEW connections only.
//
// The country DROP rules used to be appended to the end of INPUT, matching every
// packet. Three things followed from that:
//   - any earlier ACCEPT (ufw, firewalld, a hand-written "allow 80/443") let the
//     traffic through before it reached the DROP;
//   - published Docker ports never pass through INPUT at all, so a dockerised
//     site was never geoblocked;
//   - had it worked, it would also have dropped the replies to connections the
//     server opens itself, so blocking the US would have cut the server off from
//     every US API and package mirror.
//
// Matching NEW connections from position 1 of a dedicated chain fixes all three.
const geoChain = "DEFENSIA-GEO"

// iptablesRun runs iptables. Tests replace it.
var iptablesRun = func(args ...string) ([]byte, error) {
	return exec.Command("iptables", args...).CombinedOutput()
}

func chainExists(name string) bool {
	_, err := iptablesRun("-S", name)
	return err == nil
}

// geoParents returns the chains that must jump to geoChain on this host.
func geoParents() []string {
	parents := []string{"INPUT"}
	if chainExists("DOCKER-USER") {
		parents = append(parents, "DOCKER-USER")
	}
	return parents
}

func geoJumpSpec() []string {
	return []string{"-m", "conntrack", "--ctstate", "NEW", "-j", geoChain}
}

// ensureGeoChain creates geoChain if needed and makes sure every parent chain
// jumps to it first. Safe to call on every sync: Docker recreating DOCKER-USER
// or someone flushing INPUT is repaired on the next pass.
func ensureGeoChain() error {
	if !chainExists(geoChain) {
		if out, err := iptablesRun("-N", geoChain); err != nil {
			return fmt.Errorf("create chain %s: %s (%w)", geoChain, strings.TrimSpace(string(out)), err)
		}
	}

	for _, parent := range geoParents() {
		spec := geoJumpSpec()
		if _, err := iptablesRun(append([]string{"-C", parent}, spec...)...); err == nil {
			continue
		}
		args := append([]string{"-I", parent, "1"}, spec...)
		if out, err := iptablesRun(args...); err != nil {
			return fmt.Errorf("jump %s -> %s: %s (%w)", parent, geoChain, strings.TrimSpace(string(out)), err)
		}
	}
	return nil
}

// rebuildGeoChain replaces the chain's contents: a RETURN for each protected IP
// (panel and whitelist) first, then one DROP per country set. The chain is only
// empty for the few milliseconds between flush and refill, and empty means
// nothing is blocked, never that everything is.
func rebuildGeoChain(protectedIPs, sets []string) error {
	if out, err := iptablesRun("-F", geoChain); err != nil {
		return fmt.Errorf("flush %s: %s (%w)", geoChain, strings.TrimSpace(string(out)), err)
	}
	for _, ip := range protectedIPs {
		if out, err := iptablesRun("-A", geoChain, "-s", ip, "-j", "RETURN"); err != nil {
			return fmt.Errorf("protect %s in %s: %s (%w)", ip, geoChain, strings.TrimSpace(string(out)), err)
		}
	}
	for _, set := range sets {
		if out, err := iptablesRun("-A", geoChain, "-m", "set", "--match-set", set, "src", "-j", "DROP"); err != nil {
			return fmt.Errorf("add %s to %s: %s (%w)", set, geoChain, strings.TrimSpace(string(out)), err)
		}
	}
	return nil
}

// teardownGeoChain removes the jumps and the chain, so a server with no country
// blocks carries no geoblock rules at all.
func teardownGeoChain() {
	if !chainExists(geoChain) {
		return
	}
	for _, parent := range []string{"INPUT", "DOCKER-USER"} {
		spec := geoJumpSpec()
		for i := 0; i < 5; i++ { // a duplicated jump is removed one copy at a time
			if _, err := iptablesRun(append([]string{"-D", parent}, spec...)...); err != nil {
				break
			}
		}
	}
	_, _ = iptablesRun("-F", geoChain)
	_, _ = iptablesRun("-X", geoChain)
}

// removeLegacyGeoRule deletes the old per-country DROP appended to INPUT by
// earlier agent versions, so a country set can be destroyed and is not matched
// twice.
func removeLegacyGeoRule(set string) {
	for i := 0; i < 5; i++ {
		if _, err := iptablesRun("-D", "INPUT", "-m", "set", "--match-set", set, "src", "-j", "DROP"); err != nil {
			return
		}
	}
}
