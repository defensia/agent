package firewall

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
)

// ipsetAvailable is true when the `ipset` binary is found on the system.
var ipsetAvailable bool
var ipsetOnce sync.Once

// checkIpset detects whether ipset is available on this system.
func checkIpset() bool {
	ipsetOnce.Do(func() {
		_, err := exec.LookPath("ipset")
		ipsetAvailable = err == nil
		if ipsetAvailable {
			log.Println("[firewall] ipset detected — using hash:net for country blocks")
		} else {
			log.Println("[firewall] ipset not found — country geoblocking requires ipset (apt install ipset)")
		}
	})
	return ipsetAvailable
}

// HasIpset returns true if ipset is available on this system.
func HasIpset() bool {
	return checkIpset()
}

// ipsetSetName returns the ipset set name for a country code.
func ipsetSetName(countryCode string) string {
	return fmt.Sprintf("defensia-geo-%s", strings.ToLower(countryCode))
}

// createIpsetHashNet creates an ipset hash:net set if it doesn't exist.
// maxelem defaults to 131072 (enough for any country).
func createIpsetHashNet(name string) error {
	// Try to create — if it already exists, ipset returns error code 1
	out, err := exec.Command("ipset", "create", name, "hash:net",
		"maxelem", "131072", "-exist").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipset create %s: %s (%w)", name, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// flushIpset removes all entries from an ipset set.
func flushIpset(name string) error {
	out, err := exec.Command("ipset", "flush", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipset flush %s: %s (%w)", name, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// destroyIpset destroys an ipset set (must be flushed and unlinked from iptables first).
func destroyIpset(name string) error {
	out, err := exec.Command("ipset", "destroy", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipset destroy %s: %s (%w)", name, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// populateIpsetBatch adds CIDRs to an ipset using `ipset restore` for maximum speed.
// This is orders of magnitude faster than individual `ipset add` commands.
func populateIpsetBatch(setName string, cidrs []string) error {
	if len(cidrs) == 0 {
		return nil
	}

	var b strings.Builder
	for _, cidr := range cidrs {
		fmt.Fprintf(&b, "add %s %s -exist\n", setName, cidr)
	}

	cmd := exec.Command("ipset", "restore")
	cmd.Stdin = strings.NewReader(b.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipset restore for %s (%d CIDRs): %s (%w)",
			setName, len(cidrs), strings.TrimSpace(string(out)), err)
	}
	return nil
}

// addIptablesIpsetRule adds an iptables rule that matches traffic from an ipset set.
// The rule is: iptables -I INPUT 1 -m set --match-set <setName> src -j DROP
func addIptablesIpsetRule(setName string) error {
	// Check if rule already exists
	if exec.Command("iptables", "-C", "INPUT",
		"-m", "set", "--match-set", setName, "src", "-j", "DROP").Run() == nil {
		return nil // already exists
	}

	out, err := exec.Command("iptables", "-I", "INPUT", "1",
		"-m", "set", "--match-set", setName, "src", "-j", "DROP").CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables add ipset rule for %s: %s (%w)",
			setName, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// removeIptablesIpsetRule removes the iptables rule referencing an ipset set.
func removeIptablesIpsetRule(setName string) error {
	out, err := exec.Command("iptables", "-D", "INPUT",
		"-m", "set", "--match-set", setName, "src", "-j", "DROP").CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables remove ipset rule for %s: %s (%w)",
			setName, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// ipsetEntryCount returns how many entries are in a set (for logging).
func ipsetEntryCount(setName string) int {
	out, err := exec.Command("ipset", "list", setName, "-t").CombinedOutput()
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "Number of entries:") {
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				var n int
				fmt.Sscanf(parts[3], "%d", &n)
				return n
			}
		}
	}
	return 0
}
