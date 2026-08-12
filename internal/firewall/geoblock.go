package firewall

import (
	"log"
	"net"
	"net/url"
	"os/exec"
	"strings"
	"sync"
)

// CIDRProvider is a function that returns CIDRs for a given country code.
// This avoids importing geoip in the firewall package.
type CIDRProvider func(countryCode string) ([]string, error)

// GeoBlocker manages ipset-based country blocking.
// Each blocked country gets its own ipset hash:net set with all CIDRs loaded.
type GeoBlocker struct {
	mu              sync.Mutex
	activeCountries map[string]bool // currently blocked country codes (uppercase)
	cidrProvider    CIDRProvider
	protectedIPs    []string // IPs that must never be geo-blocked (panel server, etc.)
}

// NewGeoBlocker creates a GeoBlocker with the given CIDR provider.
// panelURL is the Defensia panel URL (e.g. "https://api.defensia.cloud") —
// its IP will always be whitelisted in iptables before any geo DROP rules.
func NewGeoBlocker(provider CIDRProvider, panelURL string) *GeoBlocker {
	gb := &GeoBlocker{
		activeCountries: make(map[string]bool),
		cidrProvider:    provider,
	}

	// Resolve panel URL to IP and protect it
	if panelURL != "" {
		if u, err := url.Parse(panelURL); err == nil && u.Hostname() != "" {
			if ips, err := net.LookupHost(u.Hostname()); err == nil {
				for _, ip := range ips {
					if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() != nil {
						gb.protectedIPs = append(gb.protectedIPs, ip)
					}
				}
				if len(gb.protectedIPs) > 0 {
					log.Printf("[geoblock] panel IP(s) protected from geoblocking: %v", gb.protectedIPs)
				}
			}
		}
	}

	return gb
}

// ApplyCountryBlocks synchronizes the ipset country blocks with the desired list.
// It adds sets for new countries and removes sets for countries no longer blocked.
// Protected IPs (panel server) always get an ACCEPT rule before any geo DROP.
func (g *GeoBlocker) ApplyCountryBlocks(countries []string) {
	if !HasIpset() {
		if len(countries) > 0 {
			log.Printf("[geoblock] WARNING: %d countries configured for blocking but ipset is not installed — country blocks NOT applied at kernel level (falling back to reactive per-IP blocking)", len(countries))
		}
		return
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	// Ensure protected IPs have ACCEPT rules before any geo DROP
	if len(countries) > 0 {
		g.ensureProtectedIPs()
	}

	// Build desired set (uppercase, deduplicated)
	desired := make(map[string]bool, len(countries))
	for _, cc := range countries {
		cc = strings.ToUpper(strings.TrimSpace(cc))
		if cc != "" && len(cc) == 2 {
			desired[cc] = true
		}
	}

	// Remove countries that are no longer blocked
	for cc := range g.activeCountries {
		if !desired[cc] {
			g.removeCountry(cc)
		}
	}

	// Add countries that are newly blocked
	for cc := range desired {
		if !g.activeCountries[cc] {
			g.addCountry(cc)
		}
	}
}

// addCountry creates an ipset set for the country, loads CIDRs, and adds the iptables rule.
func (g *GeoBlocker) addCountry(cc string) {
	setName := ipsetSetName(cc)

	// Get CIDRs from provider
	cidrs, err := g.cidrProvider(cc)
	if err != nil {
		log.Printf("[geoblock] error getting CIDRs for %s: %v", cc, err)
		return
	}
	if len(cidrs) == 0 {
		log.Printf("[geoblock] no CIDRs found for %s — skipping", cc)
		return
	}

	// Create the ipset set
	if err := createIpsetHashNet(setName); err != nil {
		log.Printf("[geoblock] failed to create set %s: %v", setName, err)
		return
	}

	// Flush any stale entries
	if err := flushIpset(setName); err != nil {
		log.Printf("[geoblock] failed to flush set %s: %v", setName, err)
	}

	// Populate with CIDRs using batch restore (fast)
	if err := populateIpsetBatch(setName, cidrs); err != nil {
		log.Printf("[geoblock] failed to populate set %s with %d CIDRs: %v", setName, len(cidrs), err)
		// Cleanup on failure
		_ = destroyIpset(setName)
		return
	}

	// Add iptables rule pointing to this set
	if err := addIptablesIpsetRule(setName); err != nil {
		log.Printf("[geoblock] failed to add iptables rule for %s: %v", setName, err)
		_ = flushIpset(setName)
		_ = destroyIpset(setName)
		return
	}

	g.activeCountries[cc] = true
	count := ipsetEntryCount(setName)
	log.Printf("[geoblock] ✓ blocked %s: %d CIDRs loaded into %s", cc, count, setName)
}

// removeCountry removes the iptables rule and destroys the ipset set for a country.
func (g *GeoBlocker) removeCountry(cc string) {
	setName := ipsetSetName(cc)

	// Remove iptables rule first (must happen before destroying the set)
	if err := removeIptablesIpsetRule(setName); err != nil {
		log.Printf("[geoblock] warning: failed to remove iptables rule for %s: %v", setName, err)
	}

	// Flush and destroy the set
	_ = flushIpset(setName)
	if err := destroyIpset(setName); err != nil {
		log.Printf("[geoblock] warning: failed to destroy set %s: %v", setName, err)
	}

	delete(g.activeCountries, cc)
	log.Printf("[geoblock] ✓ unblocked %s: set %s removed", cc, setName)
}

// ActiveCountries returns the list of currently blocked countries.
func (g *GeoBlocker) ActiveCountries() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	result := make([]string, 0, len(g.activeCountries))
	for cc := range g.activeCountries {
		result = append(result, cc)
	}
	return result
}

// SetWhitelistedIPs adds extra IPs that must be protected from geoblocking.
// Called during sync when whitelists are applied.
func (g *GeoBlocker) SetWhitelistedIPs(ips []string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Rebuild protected list: panel IPs + whitelisted IPs
	panelIPs := make([]string, 0)
	for _, ip := range g.protectedIPs {
		// Keep only the original panel IPs (non-whitelist)
		panelIPs = append(panelIPs, ip)
		if len(panelIPs) >= 5 { // cap at max 5 panel IPs
			break
		}
	}
	g.protectedIPs = panelIPs
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip != "" && net.ParseIP(ip) != nil {
			g.protectedIPs = append(g.protectedIPs, ip)
		}
	}
}

// ensureProtectedIPs inserts iptables ACCEPT rules for all protected IPs.
// These ACCEPT rules are inserted at position 1, before any geo DROP rules.
func (g *GeoBlocker) ensureProtectedIPs() {
	for _, ip := range g.protectedIPs {
		// Check if ACCEPT rule already exists
		if exec.Command("iptables", "-C", "INPUT", "-s", ip, "-j", "ACCEPT").Run() == nil {
			continue // already exists
		}
		// Insert at position 1 (before any DROP rules)
		out, err := exec.Command("iptables", "-I", "INPUT", "1", "-s", ip, "-j", "ACCEPT").CombinedOutput()
		if err != nil {
			log.Printf("[geoblock] failed to add ACCEPT rule for protected IP %s: %s", ip, strings.TrimSpace(string(out)))
		} else {
			log.Printf("[geoblock] ✓ protected IP %s: ACCEPT rule added (immune to geoblocking)", ip)
		}
	}
}

// Cleanup removes all geoblock ipset sets and iptables rules (used on shutdown).
func (g *GeoBlocker) Cleanup() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for cc := range g.activeCountries {
		g.removeCountry(cc)
	}
}
