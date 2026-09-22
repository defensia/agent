package firewall

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

const banSetName = "defensia-bans"
const banSet6Name = "defensia-bans6"

// Init initializes the firewall backend: detects ipset availability
// and creates the defensia-bans hash:ip set(s) if ipset is present.
func Init() {
	if !checkIpset() {
		return
	}
	// Create the IPv4 bans set (hash:ip family inet, 65536 max)
	if err := createIpsetHashIP(banSetName); err != nil {
		log.Printf("[firewall] failed to create ban set: %v", err)
		return
	}
	if err := addIptablesIpsetRule(banSetName); err != nil {
		log.Printf("[firewall] failed to add iptables rule for ban set: %v", err)
		return
	}
	// Create the IPv6 bans set (hash:ip family inet6, 65536 max)
	if err := createIpsetHashIP6(banSet6Name); err != nil {
		log.Printf("[firewall] failed to create IPv6 ban set: %v", err)
		// Non-fatal — IPv4 still works
	} else if err := addIp6tablesIpsetRule(banSet6Name); err != nil {
		log.Printf("[firewall] failed to add ip6tables rule for ban set: %v", err)
	}
	log.Printf("[firewall] ipset ban sets ready: %s (inet) + %s (inet6)", banSetName, banSet6Name)
}

// SetK8sHook registers a Kubernetes-level firewall implementation.
// When set, BanIP will also call the K8s hook to update ConfigMap deny rules.
func SetK8sHook(hook interface{}) {
	// K8s firewall hook — stored for future use when K8s integration is active
	log.Printf("[firewall] K8s firewall hook registered")
}

// FirewallStatus returns the current firewall backend status.
type Status struct {
	Mode       string    // "ipset" or "iptables"
	HasIpset   bool
	Capacity   int
	ActiveBans int
	CSF        CSFStatus // CSF info (empty if not installed)
}

// FirewallStatus returns mode, capacity, active ban count, and CSF info.
func FirewallStatus() Status {
	csf := CSFInfo()

	if HasIpset() {
		return Status{
			Mode:       "ipset",
			HasIpset:   true,
			Capacity:   65536,
			ActiveBans: ipsetEntryCount(banSetName) + ipsetEntryCount(banSet6Name),
			CSF:        csf,
		}
	}
	rules, err := ListRules()
	bans := 0
	if err == nil {
		for _, r := range rules {
			if r.Type == "block" && r.Source != "" && r.Port == 0 {
				bans++
			}
		}
	}
	return Status{Mode: "iptables", HasIpset: false, Capacity: 500, ActiveBans: bans, CSF: csf}
}

// RuleSpec describes a firewall rule to apply.
type RuleSpec struct {
	Type      string  // "block" or "allow"
	Protocol  string  // "tcp", "udp", "icmp", "all"
	IPAddress *string // single IP
	IPRange   *string // CIDR range
	Port      *int    // destination port (only for tcp/udp)
}

// ApplyRule adds an iptables rule based on a RuleSpec.
// Returns nil if the rule was applied successfully.
func ApplyRule(spec RuleSpec) error {
	args := buildRuleArgs(spec)

	// Check if rule already exists
	checkArgs := append([]string{"-C", "INPUT"}, args...)
	if exec.Command("iptables", checkArgs...).Run() == nil {
		log.Printf("[firewall] rule already exists, skipping")
		return nil
	}

	// Insert at top of chain
	insertArgs := append([]string{"-I", "INPUT", "1"}, args...)
	if err := exec.Command("iptables", insertArgs...).Run(); err != nil {
		return fmt.Errorf("iptables apply rule: %w", err)
	}

	log.Printf("[firewall] applied rule: %v", args)
	return nil
}

// RemoveRule removes an iptables rule matching the given RuleSpec.
func RemoveRule(spec RuleSpec) error {
	args := buildRuleArgs(spec)
	deleteArgs := append([]string{"-D", "INPUT"}, args...)

	if err := exec.Command("iptables", deleteArgs...).Run(); err != nil {
		return fmt.Errorf("iptables remove rule: %w", err)
	}

	log.Printf("[firewall] removed rule: %v", args)
	return nil
}

// buildRuleArgs constructs iptables arguments for a RuleSpec.
func buildRuleArgs(spec RuleSpec) []string {
	var args []string

	// Source IP/range
	src := source(spec)
	if src != "" {
		args = append(args, "-s", src)
	}

	// Protocol
	proto := spec.Protocol
	if proto == "" || proto == "all" {
		// Only add protocol if port is specified (port requires tcp/udp)
		if spec.Port != nil {
			proto = "tcp"
			args = append(args, "-p", proto)
		}
	} else {
		args = append(args, "-p", proto)
	}

	// Destination port (only for tcp/udp)
	if spec.Port != nil && (proto == "tcp" || proto == "udp") {
		args = append(args, "--dport", strconv.Itoa(*spec.Port))
	}

	// Target (ACCEPT or DROP)
	target := "DROP"
	if spec.Type == "allow" {
		target = "ACCEPT"
	}
	args = append(args, "-j", target)

	return args
}

// source returns the source argument from the RuleSpec.
func source(spec RuleSpec) string {
	if spec.IPAddress != nil && *spec.IPAddress != "" {
		return *spec.IPAddress
	}
	if spec.IPRange != nil && *spec.IPRange != "" {
		return *spec.IPRange
	}
	return ""
}

// protectedIPs holds additional IPs that must never be banned (e.g. the API server).
var protectedIPs = make(map[string]bool)

// AddProtectedIPs registers IPs that must never be banned (e.g. the Defensia API server).
func AddProtectedIPs(ips ...string) {
	for _, ip := range ips {
		if parsed := net.ParseIP(ip); parsed != nil {
			protectedIPs[parsed.String()] = true
			log.Printf("[firewall] added protected IP: %s", parsed)
		}
	}
}

// localIPs caches the server's own IP addresses (collected once at first use).
var localIPs map[string]bool
var localIPsOnce sync.Once

// collectLocalIPs gathers all IP addresses assigned to local network interfaces.
func collectLocalIPs() map[string]bool {
	ips := make(map[string]bool)
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Printf("[firewall] warning: could not enumerate local IPs: %v", err)
		return ips
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip != nil {
			ips[ip.String()] = true
		}
	}
	log.Printf("[firewall] collected %d local IPs for self-protection", len(ips))
	return ips
}

// isLocalIP returns true if the given IP belongs to this server.
func isLocalIP(ip net.IP) bool {
	localIPsOnce.Do(func() { localIPs = collectLocalIPs() })
	return localIPs[ip.String()]
}

// isReservedIP returns true for loopback, link-local, and private IPs
// that must never be banned via iptables.
func isReservedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate()
}

// isSafeIP returns true if the IP must not be banned (reserved, own server, or protected).
func isSafeIP(ip net.IP) bool {
	return isReservedIP(ip) || isLocalIP(ip) || protectedIPs[ip.String()]
}

// BanIP adds a DROP rule for the given IP address.
// When ipset is available, adds to the appropriate set (IPv4 → defensia-bans, IPv6 → defensia-bans6).
// Otherwise falls back to individual iptables/ip6tables rules.
func BanIP(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	if isSafeIP(parsed) {
		return fmt.Errorf("refusing to ban safe IP: %s", ip)
	}

	if HasIpset() {
		if parsed.To4() != nil {
			return ipsetAdd(banSetName, ip)
		}
		return ipsetAdd(banSet6Name, ip)
	}

	return ApplyRule(RuleSpec{
		Type:      "block",
		Protocol:  "all",
		IPAddress: &ip,
	})
}

// UnbanIP removes the DROP rule for the given IP address.
func UnbanIP(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	if HasIpset() {
		if parsed.To4() != nil {
			return ipsetDel(banSetName, ip)
		}
		return ipsetDel(banSet6Name, ip)
	}

	return RemoveRule(RuleSpec{
		Type:      "block",
		Protocol:  "all",
		IPAddress: &ip,
	})
}

// ApplyBans applies a list of IPs from the server sync.
// When ipset is available, uses batch restore for maximum speed.
// Splits IPv4 and IPv6 into separate sets to prevent ipset restore atomicity failures.
// Returns the number of IPs actually applied to the kernel.
func ApplyBans(ips []string) int {
	if HasIpset() && len(ips) > 0 {
		// Split by address family — ipset restore is atomic, one bad entry kills the whole batch
		var v4, v6 []string
		for _, ip := range ips {
			parsed := net.ParseIP(ip)
			if parsed == nil || isSafeIP(parsed) {
				continue
			}
			if parsed.To4() != nil {
				v4 = append(v4, ip)
			} else {
				v6 = append(v6, ip)
			}
		}
		v4applied, v6applied := 0, 0
		if len(v4) > 0 {
			if err := ipsetBatchAdd(banSetName, v4); err != nil {
				log.Printf("[firewall] ipset batch ban failed (v4, %d IPs): %v", len(v4), err)
			} else {
				v4applied = len(v4)
			}
		}
		if len(v6) > 0 {
			if err := ipsetBatchAdd(banSet6Name, v6); err != nil {
				log.Printf("[firewall] ipset batch ban failed (v6, %d IPs): %v", len(v6), err)
			} else {
				v6applied = len(v6)
			}
		}
		return v4applied + v6applied
	}
	applied := 0
	for _, ip := range ips {
		if err := BanIP(ip); err != nil {
			log.Printf("[firewall] error applying ban for %s: %v", ip, err)
		} else {
			applied++
		}
	}
	return applied
}

// CleanupStaleBans removes bans for IPs that are no longer in the active ban list.
// When ipset is available, cleans both IPv4 and IPv6 sets.
// When using iptables, removes individual DROP rules.
func CleanupStaleBans(activeBanIPs map[string]bool, activeRuleIPs map[string]bool) int {
	if HasIpset() {
		return cleanupIpsetBans(activeBanIPs)
	}
	return cleanupIptablesBans(activeBanIPs, activeRuleIPs)
}

// cleanupIpsetBans syncs both IPv4 and IPv6 ipsets to match exactly the active bans.
func cleanupIpsetBans(activeBanIPs map[string]bool) int {
	removed := 0
	// Clean IPv4 set
	for _, ip := range ipsetListMembers(banSetName) {
		if !activeBanIPs[ip] {
			if err := ipsetDel(banSetName, ip); err == nil {
				removed++
			}
		}
	}
	// Clean IPv6 set
	for _, ip := range ipsetListMembers(banSet6Name) {
		if !activeBanIPs[ip] {
			if err := ipsetDel(banSet6Name, ip); err == nil {
				removed++
			}
		}
	}
	if removed > 0 {
		log.Printf("[firewall] cleanup: removed %d expired bans from ipset", removed)
	}
	return removed
}

// cleanupIptablesBans removes individual iptables DROP rules for expired bans.
func cleanupIptablesBans(activeBanIPs map[string]bool, activeRuleIPs map[string]bool) int {
	current, err := ListRules()
	if err != nil {
		log.Printf("[firewall] cleanup: cannot list rules: %v", err)
		return 0
	}

	removed := 0
	for _, r := range current {
		if r.Type != "block" || r.Source == "" || r.Port != 0 || r.Protocol != "all" {
			continue
		}
		if activeBanIPs[r.Source] {
			continue
		}
		if activeRuleIPs[r.Source] {
			continue
		}
		if err := UnbanIP(r.Source); err != nil {
			log.Printf("[firewall] cleanup: failed to remove stale ban for %s: %v", r.Source, err)
		} else {
			removed++
		}
	}

	if removed > 0 {
		log.Printf("[firewall] cleanup: removed %d expired iptables bans", removed)
	}
	return removed
}

// ParsedRule represents an iptables rule parsed from `iptables -S INPUT`.
type ParsedRule struct {
	RawRule   string
	Type      string // "block" or "allow"
	Protocol  string // "tcp", "udp", "icmp", "all"
	Source    string // IP address (no CIDR /32)
	Port      int    // 0 means no port
}

// ListRules reads existing INPUT chain rules via `iptables -S INPUT`
// and returns only simple rules Defensia can manage.
func ListRules() ([]ParsedRule, error) {
	out, err := exec.Command("iptables", "-S", "INPUT").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("iptables -S INPUT: %w", err)
	}

	var rules []ParsedRule
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Only parse -A INPUT rules (skip -P INPUT ACCEPT/DROP policy)
		if !strings.HasPrefix(line, "-A INPUT") {
			continue
		}
		parsed, ok := parseLine(line)
		if ok {
			rules = append(rules, parsed)
		}
	}

	log.Printf("[firewall] listed %d manageable rules from iptables", len(rules))
	return rules, nil
}

// parseLine parses a single iptables -S line into a ParsedRule.
// Returns false if the rule is too complex for Defensia to manage.
func parseLine(line string) (ParsedRule, bool) {
	fields := strings.Fields(line)

	// Skip rules with interface binds (-i, -o) or negations (!)
	for _, f := range fields {
		switch f {
		case "-i", "-o", "!":
			return ParsedRule{}, false
		}
	}

	// Check -m modules: allow simple protocol matches (tcp, udp, icmp)
	// but skip complex modules (state, conntrack, multiport, limit, comment, etc.)
	for i, f := range fields {
		if f == "-m" && i+1 < len(fields) {
			mod := fields[i+1]
			switch mod {
			case "tcp", "udp", "icmp":
				// Simple protocol match — OK
			default:
				// Complex module — skip this rule
				return ParsedRule{}, false
			}
		}
	}

	rule := ParsedRule{
		RawRule:  line,
		Protocol: "all",
	}

	for i := 0; i < len(fields); i++ {
		switch fields[i] {
		case "-j":
			if i+1 < len(fields) {
				switch fields[i+1] {
				case "DROP", "REJECT":
					rule.Type = "block"
				case "ACCEPT":
					rule.Type = "allow"
				default:
					// Custom chain target — skip
					return ParsedRule{}, false
				}
				i++
			}
		case "-s":
			if i+1 < len(fields) {
				src := fields[i+1]
				// Strip /32 suffix from single IPs
				src = strings.TrimSuffix(src, "/32")
				rule.Source = src
				i++
			}
		case "-p":
			if i+1 < len(fields) {
				rule.Protocol = fields[i+1]
				i++
			}
		case "--dport":
			if i+1 < len(fields) {
				if p, err := strconv.Atoi(fields[i+1]); err == nil {
					rule.Port = p
				}
				i++
			}
		case "-m":
			// Skip the module name (already validated above)
			i++
		}
	}

	// Must have a target (block or allow)
	if rule.Type == "" {
		return ParsedRule{}, false
	}

	// Must have at least a source IP or a port to be meaningful
	if rule.Source == "" && rule.Port == 0 {
		return ParsedRule{}, false
	}

	// Skip safe IPs (reserved or own server) — they should never be managed or imported
	if rule.Source != "" {
		if ip := net.ParseIP(rule.Source); ip != nil && isSafeIP(ip) {
			return ParsedRule{}, false
		}
	}

	return rule, true
}
