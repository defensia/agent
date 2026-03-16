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

// RuleSpec describes a firewall rule to apply.
type RuleSpec struct {
	Type      string  // "block" or "allow"
	Protocol  string  // "tcp", "udp", "icmp", "all"
	IPAddress *string // single IP
	IPRange   *string // CIDR range
	Port      *int    // destination port (only for tcp/udp)
}

const (
	ipsetName    = "defensia-bans"
	ipsetMaxElem = 65536
	iptablesMax  = 500
)

var (
	mu       sync.Mutex
	useIPSet bool
	maxBans  int = iptablesMax
	banSet   map[string]bool
	banOrder []string // FIFO for iptables mode rotation
)

// Status reports the current firewall backend state.
type Status struct {
	Mode       string `json:"mode"`
	Capacity   int    `json:"capacity"`
	ActiveBans int    `json:"active_bans"`
}

// Init detects ipset availability and sets up the firewall backend.
// Must be called once at agent startup, before any ban operations.
func Init() {
	mu.Lock()
	defer mu.Unlock()

	banSet = make(map[string]bool)

	// Try ipset
	if tryIPSetInit() {
		useIPSet = true
		maxBans = ipsetMaxElem
		log.Printf("[firewall] using ipset backend (capacity=%d)", maxBans)
		migrateToIPSet()
		populateBanSetFromIPSet()
	} else {
		useIPSet = false
		maxBans = iptablesMax
		log.Printf("[firewall] ipset unavailable — using iptables backend (capacity=%d, FIFO rotation)", maxBans)
		populateBanSetFromIPTables()
	}
}

// tryIPSetInit attempts to create the ipset and add the iptables match rule.
func tryIPSetInit() bool {
	// Check if ipset binary exists
	if _, err := exec.LookPath("ipset"); err != nil {
		log.Printf("[firewall] ipset binary not found: %v", err)
		return false
	}

	// Create set (idempotent with -exist)
	out, err := exec.Command("ipset", "create", ipsetName, "hash:ip",
		"hashsize", "4096", "maxelem", strconv.Itoa(ipsetMaxElem), "-exist").CombinedOutput()
	if err != nil {
		log.Printf("[firewall] ipset create failed: %v (%s)", err, strings.TrimSpace(string(out)))
		return false
	}

	// Check if iptables rule already exists
	checkArgs := []string{"-C", "INPUT", "-m", "set", "--match-set", ipsetName, "src", "-j", "DROP"}
	if exec.Command("iptables", checkArgs...).Run() == nil {
		return true // already set up
	}

	// Insert the single iptables rule
	insertArgs := []string{"-I", "INPUT", "1", "-m", "set", "--match-set", ipsetName, "src", "-j", "DROP"}
	out, err = exec.Command("iptables", insertArgs...).CombinedOutput()
	if err != nil {
		log.Printf("[firewall] iptables ipset rule failed: %v (%s)", err, strings.TrimSpace(string(out)))
		// Destroy the set since we can't use it
		exec.Command("ipset", "destroy", ipsetName).Run()
		return false
	}

	return true
}

// migrateToIPSet moves existing individual DROP rules into the ipset.
func migrateToIPSet() {
	rules, err := listRulesLocked()
	if err != nil {
		log.Printf("[firewall] migration: cannot list rules: %v", err)
		return
	}

	migrated := 0
	for _, r := range rules {
		if r.Type != "block" || r.Source == "" || r.Port != 0 || r.Protocol != "all" {
			continue
		}

		// Add to ipset
		if err := exec.Command("ipset", "add", ipsetName, r.Source, "-exist").Run(); err != nil {
			log.Printf("[firewall] migration: failed to add %s to ipset: %v", r.Source, err)
			continue
		}

		// Remove individual iptables rule
		exec.Command("iptables", "-D", "INPUT", "-s", r.Source, "-j", "DROP").Run()
		migrated++
	}

	if migrated > 0 {
		log.Printf("[firewall] migrated %d individual iptables rules to ipset", migrated)
	}
}

// populateBanSetFromIPSet reads current ipset members into banSet.
func populateBanSetFromIPSet() {
	members := ipsetMembers()
	for _, ip := range members {
		banSet[ip] = true
	}
	log.Printf("[firewall] loaded %d existing bans from ipset", len(banSet))
}

// populateBanSetFromIPTables reads current iptables DROP rules into banSet/banOrder.
// If there are more bans than maxBans, trims the oldest to stay within capacity.
func populateBanSetFromIPTables() {
	rules, err := listRulesLocked()
	if err != nil {
		log.Printf("[firewall] cannot list rules for ban tracking: %v", err)
		return
	}

	for _, r := range rules {
		if r.Type == "block" && r.Source != "" && r.Port == 0 && r.Protocol == "all" {
			if !banSet[r.Source] {
				banSet[r.Source] = true
				banOrder = append(banOrder, r.Source)
			}
		}
	}

	loaded := len(banSet)
	log.Printf("[firewall] loaded %d existing bans from iptables", loaded)

	// Trim to capacity: remove oldest bans (first in FIFO) to stay within maxBans.
	// The newest bans (most recent threats) are kept.
	if loaded > maxBans {
		excess := loaded - maxBans
		log.Printf("[firewall] trimming %d oldest bans to fit within %d capacity", excess, maxBans)
		for i := 0; i < excess && len(banOrder) > 0; i++ {
			evicted := banOrder[0]
			banOrder = banOrder[1:]
			delete(banSet, evicted)
			exec.Command("iptables", "-D", "INPUT", "-s", evicted, "-j", "DROP").Run()
		}
		log.Printf("[firewall] trimmed to %d bans", len(banSet))
	}
}

// FirewallStatus returns the current firewall backend status.
func FirewallStatus() Status {
	mu.Lock()
	defer mu.Unlock()
	mode := "iptables"
	if useIPSet {
		mode = "ipset"
	}
	return Status{
		Mode:       mode,
		Capacity:   maxBans,
		ActiveBans: len(banSet),
	}
}

// ApplyRule adds an iptables rule based on a RuleSpec.
// Returns nil if the rule was applied successfully.
func ApplyRule(spec RuleSpec) error {
	args := buildRuleArgs(spec)

	// Check if rule already exists (silent — expected on restart with active bans)
	checkArgs := append([]string{"-C", "INPUT"}, args...)
	if exec.Command("iptables", checkArgs...).Run() == nil {
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
func BanIP(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	if isSafeIP(parsed) {
		log.Printf("[firewall] refusing to ban safe IP (reserved or self): %s", ip)
		return fmt.Errorf("refusing to ban safe IP: %s", ip)
	}

	mu.Lock()
	defer mu.Unlock()

	// Already banned
	if banSet[ip] {
		return nil
	}

	if useIPSet {
		return banIPSet(ip)
	}
	return banIPTables(ip)
}

// banIPSet adds an IP to the ipset.
func banIPSet(ip string) error {
	if err := exec.Command("ipset", "add", ipsetName, ip, "-exist").Run(); err != nil {
		return fmt.Errorf("ipset add %s: %w", ip, err)
	}
	banSet[ip] = true
	log.Printf("[firewall] banned %s (ipset, %d/%d)", ip, len(banSet), maxBans)
	return nil
}

// banIPTables adds an IP via iptables with FIFO rotation when at capacity.
func banIPTables(ip string) error {
	// FIFO rotation: evict oldest ban if at capacity
	if len(banSet) >= maxBans {
		evicted := banOrder[0]
		banOrder = banOrder[1:]
		delete(banSet, evicted)
		exec.Command("iptables", "-D", "INPUT", "-s", evicted, "-j", "DROP").Run()
		log.Printf("[firewall] FIFO evicted %s to make room (at capacity %d)", evicted, maxBans)
	}

	// Check if rule already exists
	if exec.Command("iptables", "-C", "INPUT", "-s", ip, "-j", "DROP").Run() == nil {
		banSet[ip] = true
		banOrder = append(banOrder, ip)
		return nil
	}

	// Insert new rule
	if err := exec.Command("iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP").Run(); err != nil {
		return fmt.Errorf("iptables ban %s: %w", ip, err)
	}

	banSet[ip] = true
	banOrder = append(banOrder, ip)
	log.Printf("[firewall] banned %s (iptables, %d/%d)", ip, len(banSet), maxBans)
	return nil
}

// UnbanIP removes the DROP rule for the given IP address.
func UnbanIP(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	mu.Lock()
	defer mu.Unlock()

	if useIPSet {
		return unbanIPSet(ip)
	}
	return unbanIPTables(ip)
}

// unbanIPSet removes an IP from the ipset.
func unbanIPSet(ip string) error {
	if err := exec.Command("ipset", "del", ipsetName, ip, "-exist").Run(); err != nil {
		return fmt.Errorf("ipset del %s: %w", ip, err)
	}
	delete(banSet, ip)
	log.Printf("[firewall] unbanned %s (ipset, %d/%d)", ip, len(banSet), maxBans)
	return nil
}

// unbanIPTables removes an IP from iptables.
func unbanIPTables(ip string) error {
	if err := exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP").Run(); err != nil {
		return fmt.Errorf("iptables unban %s: %w", ip, err)
	}
	delete(banSet, ip)
	// Remove from FIFO order
	for i, v := range banOrder {
		if v == ip {
			banOrder = append(banOrder[:i], banOrder[i+1:]...)
			break
		}
	}
	log.Printf("[firewall] unbanned %s (iptables, %d/%d)", ip, len(banSet), maxBans)
	return nil
}

// ApplyBans applies a list of IPs from the server sync.
func ApplyBans(ips []string) {
	for _, ip := range ips {
		if err := BanIP(ip); err != nil {
			log.Printf("[firewall] error applying ban for %s: %v", ip, err)
		}
	}
}

// CleanupStaleBans removes bans for IPs that are no longer
// in the active ban list from the server (e.g. expired bans).
func CleanupStaleBans(activeBanIPs map[string]bool, activeRuleIPs map[string]bool) int {
	mu.Lock()
	defer mu.Unlock()

	if useIPSet {
		return cleanupIPSet(activeBanIPs, activeRuleIPs)
	}
	return cleanupIPTables(activeBanIPs, activeRuleIPs)
}

// cleanupIPSet removes stale IPs from the ipset.
func cleanupIPSet(activeBanIPs map[string]bool, activeRuleIPs map[string]bool) int {
	members := ipsetMembers()
	removed := 0

	for _, ip := range members {
		if activeBanIPs[ip] || activeRuleIPs[ip] {
			continue
		}

		if err := exec.Command("ipset", "del", ipsetName, ip, "-exist").Run(); err != nil {
			log.Printf("[firewall] cleanup: failed to remove %s from ipset: %v", ip, err)
		} else {
			delete(banSet, ip)
			log.Printf("[firewall] cleanup: removed expired ban %s from ipset", ip)
			removed++
		}
	}

	return removed
}

// cleanupIPTables removes stale IPs from iptables (original logic).
func cleanupIPTables(activeBanIPs map[string]bool, activeRuleIPs map[string]bool) int {
	current, err := listRulesLocked()
	if err != nil {
		log.Printf("[firewall] cleanup: cannot list rules: %v", err)
		return 0
	}

	removed := 0
	for _, r := range current {
		if r.Type != "block" || r.Source == "" || r.Port != 0 || r.Protocol != "all" {
			continue
		}

		if activeBanIPs[r.Source] || activeRuleIPs[r.Source] {
			continue
		}

		if err := exec.Command("iptables", "-D", "INPUT", "-s", r.Source, "-j", "DROP").Run(); err != nil {
			log.Printf("[firewall] cleanup: failed to remove stale ban for %s: %v", r.Source, err)
		} else {
			delete(banSet, r.Source)
			// Remove from FIFO order
			for i, v := range banOrder {
				if v == r.Source {
					banOrder = append(banOrder[:i], banOrder[i+1:]...)
					break
				}
			}
			log.Printf("[firewall] cleanup: removed expired ban for %s", r.Source)
			removed++
		}
	}

	return removed
}

// ipsetMembers returns all IPs currently in the defensia-bans ipset.
func ipsetMembers() []string {
	out, err := exec.Command("ipset", "list", ipsetName, "-output", "plain").CombinedOutput()
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
			// Each line is an IP address
			if ip := net.ParseIP(line); ip != nil {
				members = append(members, ip.String())
			}
		}
	}

	return members
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
	mu.Lock()
	defer mu.Unlock()
	return listRulesLocked()
}

// listRulesLocked is the internal version (caller must hold mu).
func listRulesLocked() ([]ParsedRule, error) {
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
	// Also skip ipset match rules (managed by Init, not individual rules)
	for i, f := range fields {
		if f == "-m" && i+1 < len(fields) {
			mod := fields[i+1]
			switch mod {
			case "tcp", "udp", "icmp":
				// Simple protocol match — OK
			default:
				// Complex module (including "set" for ipset) — skip
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
