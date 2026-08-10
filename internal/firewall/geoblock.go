package firewall

import (
	"log"
	"strings"
	"sync"
)

// CIDRProvider is a function that returns CIDRs for a given country code.
// This avoids importing geoip in the firewall package.
type CIDRProvider func(countryCode string) ([]string, error)

// GeoBlocker manages ipset-based country blocking.
// Each blocked country gets its own ipset hash:net set with all CIDRs loaded.
type GeoBlocker struct {
	mu            sync.Mutex
	activeCountries map[string]bool // currently blocked country codes (uppercase)
	cidrProvider  CIDRProvider
}

// NewGeoBlocker creates a GeoBlocker with the given CIDR provider.
func NewGeoBlocker(provider CIDRProvider) *GeoBlocker {
	return &GeoBlocker{
		activeCountries: make(map[string]bool),
		cidrProvider:    provider,
	}
}

// ApplyCountryBlocks synchronizes the ipset country blocks with the desired list.
// It adds sets for new countries and removes sets for countries no longer blocked.
func (g *GeoBlocker) ApplyCountryBlocks(countries []string) {
	if !HasIpset() {
		if len(countries) > 0 {
			log.Printf("[geoblock] WARNING: %d countries configured for blocking but ipset is not installed — country blocks NOT applied at kernel level (falling back to reactive per-IP blocking)", len(countries))
		}
		return
	}

	g.mu.Lock()
	defer g.mu.Unlock()

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

// Cleanup removes all geoblock ipset sets and iptables rules (used on shutdown).
func (g *GeoBlocker) Cleanup() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for cc := range g.activeCountries {
		g.removeCountry(cc)
	}
}
