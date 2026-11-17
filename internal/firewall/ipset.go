package firewall

import (
	"fmt"
	"strings"
)

// HasIpset returns true when the active backend is ipset.
func HasIpset() bool {
	return current().Name() == "ipset"
}

// ipsetSetName returns the ipset set name for a country code.
func ipsetSetName(countryCode string) string {
	return fmt.Sprintf("defensia-geo-%s", strings.ToLower(countryCode))
}

// createIpsetHashNet creates an ipset hash:net set if it doesn't exist.
// maxelem is 262144: the United States alone is ~151,000 IPv4 networks in the
// country databases, so the old 131072 made blocking it fail every time.
func createIpsetHashNet(name string) error {
	out, err := fwExec("ipset", "create", name, "hash:net", "maxelem", "262144", "-exist")
	if err != nil {
		return fmt.Errorf("ipset create %s: %s (%w)", name, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// flushIpset removes all entries from an ipset set.
func flushIpset(name string) error {
	out, err := fwExec("ipset", "flush", name)
	if err != nil {
		return fmt.Errorf("ipset flush %s: %s (%w)", name, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// destroyIpset destroys an ipset set (must be flushed and unlinked from iptables first).
func destroyIpset(name string) error {
	out, err := fwExec("ipset", "destroy", name)
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

	out, err := fwExecIn(b.String(), "ipset", "restore")
	if err != nil {
		return fmt.Errorf("ipset restore for %s (%d CIDRs): %s (%w)",
			setName, len(cidrs), strings.TrimSpace(string(out)), err)
	}
	return nil
}

// addIptablesIpsetRule adds an iptables rule that matches traffic from an ipset set.
// Uses -A (append) so protected IP ACCEPT rules (inserted with -I at position 1) always come first.
func addIptablesIpsetRule(setName string) error {
	// Check if rule already exists
	if fwOK("iptables", "-C", "INPUT", "-m", "set", "--match-set", setName, "src", "-j", "DROP") {
		return nil // already exists
	}

	out, err := fwExec("iptables", "-A", "INPUT", "-m", "set", "--match-set", setName, "src", "-j", "DROP")
	if err != nil {
		return fmt.Errorf("iptables add ipset rule for %s: %s (%w)",
			setName, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// addIp6tablesIpsetRule adds an ip6tables rule that matches traffic from an ipset set (IPv6).
func addIp6tablesIpsetRule(setName string) error {
	if fwOK("ip6tables", "-C", "INPUT", "-m", "set", "--match-set", setName, "src", "-j", "DROP") {
		return nil // already exists
	}
	out, err := fwExec("ip6tables", "-A", "INPUT", "-m", "set", "--match-set", setName, "src", "-j", "DROP")
	if err != nil {
		return fmt.Errorf("ip6tables add ipset rule for %s: %s (%w)",
			setName, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// removeIptablesIpsetRule removes the iptables rule referencing an ipset set.
func removeIptablesIpsetRule(setName string) error {
	out, err := fwExec("iptables", "-D", "INPUT", "-m", "set", "--match-set", setName, "src", "-j", "DROP")
	if err != nil {
		return fmt.Errorf("iptables remove ipset rule for %s: %s (%w)",
			setName, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// createIpsetHashIP creates an ipset hash:ip set for individual IP bans (IPv4, family inet).
func createIpsetHashIP(name string) error {
	out, err := fwExec("ipset", "create", name, "hash:ip", "family", "inet", "maxelem", "65536", "-exist")
	if err != nil {
		return fmt.Errorf("ipset create %s hash:ip inet: %s (%w)", name, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// createIpsetHashIP6 creates an ipset hash:ip set for IPv6 bans (family inet6).
func createIpsetHashIP6(name string) error {
	out, err := fwExec("ipset", "create", name, "hash:ip", "family", "inet6", "maxelem", "65536", "-exist")
	if err != nil {
		return fmt.Errorf("ipset create %s hash:ip inet6: %s (%w)", name, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// ipsetAdd adds a single IP to an ipset set.
func ipsetAdd(setName, ip string) error {
	out, err := fwExec("ipset", "add", setName, ip, "-exist")
	if err != nil {
		return fmt.Errorf("ipset add %s to %s: %s (%w)", ip, setName, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// ipsetDel removes a single IP from an ipset set.
func ipsetDel(setName, ip string) error {
	out, err := fwExec("ipset", "del", setName, ip, "-exist")
	if err != nil {
		return fmt.Errorf("ipset del %s from %s: %s (%w)", ip, setName, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// ipsetBatchAdd adds multiple IPs to an ipset using `ipset restore` for speed.
func ipsetBatchAdd(setName string, ips []string) error {
	if len(ips) == 0 {
		return nil
	}
	var b strings.Builder
	for _, ip := range ips {
		fmt.Fprintf(&b, "add %s %s -exist\n", setName, ip)
	}
	out, err := fwExecIn(b.String(), "ipset", "restore")
	if err != nil {
		return fmt.Errorf("ipset batch add to %s (%d IPs): %s (%w)",
			setName, len(ips), strings.TrimSpace(string(out)), err)
	}
	return nil
}

// ipsetListMembers returns all IPs in an ipset set.
func ipsetListMembers(setName string) []string {
	out, err := fwExec("ipset", "list", setName)
	if err != nil {
		return nil
	}
	var members []string
	inMembers := false
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "Members:" {
			inMembers = true
			continue
		}
		if inMembers && line != "" {
			members = append(members, line)
		}
	}
	return members
}

// ipsetEntryCount returns how many entries are in a set (for logging).
func ipsetEntryCount(setName string) int {
	out, err := fwExec("ipset", "list", setName, "-t")
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
