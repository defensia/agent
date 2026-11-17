package firewall

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
)

const banSetName = "defensia-bans"
const banSet6Name = "defensia-bans6"

// Init runs backend detection (see Reselect). Kept as a named entry point —
// main.go calls Init() once at startup; phase 17 replaces its ipset-only
// body with the full functional-probe selection.
func Init() {
	mode := Reselect()
	log.Printf("[firewall] backend selected: %s", mode)
}

// SetK8sHook registers a Kubernetes-level firewall implementation.
// When set, BanIP will also call the K8s hook to update ConfigMap deny rules.
func SetK8sHook(hook interface{}) {
	// K8s firewall hook — stored for future use when K8s integration is active
	log.Printf("[firewall] K8s firewall hook registered")
}

// Status is the current firewall backend status.
type Status struct {
	Mode       string // "ipset", "iptables", "nftables" or "none"
	HasIpset   bool
	Capacity   int
	ActiveBans int
	CSF        CSFStatus // CSF info (empty if not installed)
	Reason     string    // non-empty only when Mode == "none" (phase 17)
}

// FirewallStatus returns mode, capacity, active ban count, and CSF info.
func FirewallStatus() Status {
	csf := csfStatusFromSnapshot(CurrentCSFSnapshot())
	b := current()
	return Status{
		Mode:       b.Name(),
		HasIpset:   b.Name() == "ipset",
		Capacity:   b.Capacity(),
		ActiveBans: b.Count(),
		CSF:        csf,
		Reason:     SelectionReason(),
	}
}

// RuleSpec describes a firewall rule to apply.
type RuleSpec struct {
	Type      string  // "block" or "allow"
	Protocol  string  // "tcp", "udp", "icmp", "all"
	IPAddress *string // single IP
	IPRange   *string // CIDR range
	Port      *int    // destination port (only for tcp/udp)
}

// ApplyRule delegates to the active backend.
func ApplyRule(spec RuleSpec) error { return current().ApplyRule(spec) }

// RemoveRule delegates to the active backend.
func RemoveRule(spec RuleSpec) error { return current().RemoveRule(spec) }

// ListRules delegates to the active backend.
func ListRules() ([]ParsedRule, error) { return current().ListRules() }

// iptablesApplyRule adds an iptables rule based on a RuleSpec.
// Returns nil if the rule was applied successfully.
func iptablesApplyRule(spec RuleSpec) error {
	args := buildRuleArgs(spec)

	// Check if rule already exists
	checkArgs := append([]string{"-C", "INPUT"}, args...)
	if fwOK("iptables", checkArgs...) {
		log.Printf("[firewall] rule already exists, skipping")
		return nil
	}

	// Insert at top of chain
	insertArgs := append([]string{"-I", "INPUT", "1"}, args...)
	if _, err := fwExec("iptables", insertArgs...); err != nil {
		return fmt.Errorf("iptables apply rule: %w", err)
	}

	log.Printf("[firewall] applied rule: %v", args)
	return nil
}

// iptablesRemoveRule removes an iptables rule matching the given RuleSpec.
func iptablesRemoveRule(spec RuleSpec) error {
	args := buildRuleArgs(spec)
	deleteArgs := append([]string{"-D", "INPUT"}, args...)

	if _, err := fwExec("iptables", deleteArgs...); err != nil {
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

// BanIP adds a DROP rule for the given IP address via the active backend.
func BanIP(ip string) error { return BanIPFor(ip, 0) }

// UnbanIP removes the DROP rule for the given IP address via the active backend.
func UnbanIP(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	return current().Unban(parsed)
}

// ApplyBans applies a list of IPs from the server sync (no TTL). Returns the
// number of IPs actually applied to the kernel.
func ApplyBans(ips []string) int {
	entries := make([]BanEntry, 0, len(ips))
	for _, ip := range ips {
		entries = append(entries, BanEntry{IP: ip})
	}
	return ApplyBanEntries(entries)
}

// CleanupStaleBans removes bans for IPs that are no longer in the active ban
// list. activeRuleIPs is only consulted for the iptables backend (ipset and
// nftables semantics: only active bans are kept, matching origin/main's
// ipset-mode behaviour).
func CleanupStaleBans(activeBanIPs map[string]bool, activeRuleIPs map[string]bool) int {
	b := current()

	normalised := make(map[string]bool, len(activeBanIPs))
	for k, v := range activeBanIPs {
		if ip := net.ParseIP(k); ip != nil {
			normalised[ip.String()] = v
		} else {
			normalised[k] = v
		}
	}

	v4, v6, err := b.Members()
	if err != nil {
		log.Printf("[firewall] cleanup: cannot list bans: %v", err)
		return 0
	}

	removed := 0
	for _, m := range append(v4, v6...) {
		ipStr := m
		if ip := net.ParseIP(m); ip != nil {
			ipStr = ip.String()
		}
		if normalised[ipStr] {
			continue
		}
		if b.Name() == "iptables" && activeRuleIPs[ipStr] {
			continue
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if err := b.Unban(ip); err != nil {
			log.Printf("[firewall] cleanup: failed to remove stale ban for %s: %v", ipStr, err)
			continue
		}
		removed++
	}

	if removed > 0 {
		switch b.Name() {
		case "ipset":
			log.Printf("[firewall] cleanup: removed %d expired bans from ipset", removed)
		case "nftables":
			log.Printf("[firewall] cleanup: removed %d expired bans from nftables", removed)
		default:
			log.Printf("[firewall] cleanup: removed %d expired iptables bans", removed)
		}
	}
	return removed
}

// ParsedRule represents a firewall rule parsed from `iptables -S INPUT` (or
// the equivalent listing for another backend).
type ParsedRule struct {
	RawRule  string
	Type     string // "block" or "allow"
	Protocol string // "tcp", "udp", "icmp", "all"
	Source   string // IP address (no CIDR /32 or /128)
	Port     int    // 0 means no port
}

// iptablesListRules reads existing INPUT chain rules via `iptables -S INPUT`
// and returns only simple rules Defensia can manage.
func iptablesListRules() ([]ParsedRule, error) {
	out, err := fwExec("iptables", "-S", "INPUT")
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
		parsed, ok := parseLine(line, "/32")
		if ok {
			rules = append(rules, parsed)
		}
	}

	log.Printf("[firewall] listed %d manageable rules from iptables", len(rules))
	return rules, nil
}

// ip6tablesListRules reads existing INPUT chain rules via `ip6tables -S INPUT`.
func ip6tablesListRules() ([]ParsedRule, error) {
	out, err := fwExec("ip6tables", "-S", "INPUT")
	if err != nil {
		return nil, fmt.Errorf("ip6tables -S INPUT: %w", err)
	}

	var rules []ParsedRule
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "-A INPUT") {
			continue
		}
		parsed, ok := parseLine(line, "/128")
		if ok {
			rules = append(rules, parsed)
		}
	}
	return rules, nil
}

// parseLine parses a single iptables/ip6tables -S line into a ParsedRule.
// cidrSuffix ("/32" or "/128") is stripped from a bare single-IP source.
// Returns false if the rule is too complex for Defensia to manage.
func parseLine(line string, cidrSuffix string) (ParsedRule, bool) {
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
				src = strings.TrimSuffix(src, cidrSuffix)
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
