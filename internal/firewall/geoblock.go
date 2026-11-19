package firewall

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// CIDRProvider is a function that returns CIDRs for a given country code.
// This avoids importing geoip in the firewall package.
type CIDRProvider func(countryCode string) ([]string, error)

// GeoBlocker manages country blocking on top of the active Backend.
// Each blocked country gets its own backend-managed set (ipset hash:net on
// ipset hosts) with all CIDRs loaded; geoChain (see geochain.go) is the
// iptables-level enforcement, unchanged by backend selection.
type GeoBlocker struct {
	mu              sync.Mutex
	activeCountries map[string]bool // currently blocked country codes (uppercase)
	cidrProvider    CIDRProvider
	protectedIPs    []string // IPs that must never be geo-blocked (panel server, etc.)
	enforced        bool     // geoChain is live and points at activeCountries
	exemptCIDRs     []string // never dropped: CDNs, crawlers, monitors
	exemptPorts     []int    // TCP destination ports never dropped
	exemptKey       string   // exemptCIDRs as last loaded into geoExemptSet
	exemptLoaded    bool

	appliedGen      uint64 // backend generation activeCountries was built against (phase 17)
	unapplied       int    // countries not enforced at kernel level on the last ApplyCountryBlocks
	unappliedReason string
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

// ApplyCountryBlocks synchronizes the backend's country sets with the desired
// list. Sets for new countries are loaded first, then geoChain is rebuilt to
// point at exactly the active sets, and only then are sets for dropped
// countries destroyed — a set still referenced by geoChain cannot be destroyed.
//
// On a backend that cannot load country sets (iptables, no ipset/nftables),
// nothing is applied at the kernel level; Unapplied() reports how many
// countries and why, instead of failing silently.
func (g *GeoBlocker) ApplyCountryBlocks(countries []string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	// A backend change invalidates what we think is loaded: the new backend
	// has its own (empty) sets, so every country must be reloaded.
	if gen := Generation(); gen != g.appliedGen {
		g.activeCountries = make(map[string]bool)
		g.appliedGen = gen
	}

	b := current()

	// Build desired set (uppercase, deduplicated)
	desired := make(map[string]bool, len(countries))
	for _, cc := range countries {
		cc = strings.ToUpper(strings.TrimSpace(cc))
		if cc != "" && len(cc) == 2 {
			desired[cc] = true
		}
	}

	if !b.GeoSupported() {
		if len(desired) > 0 {
			log.Printf("[geoblock] WARNING: %d countries configured for blocking but the %s backend cannot load country sets — country blocks NOT applied at kernel level (falling back to reactive per-IP blocking)", len(desired), b.Name())
			g.unapplied = len(desired)
			g.unappliedReason = "country blocks need ipset or nftables; active backend: " + b.Name()
		} else {
			g.unapplied = 0
			g.unappliedReason = ""
		}
		g.enforced = false
		return
	}

	// nftables (and any future GeoSupported backend without an exemption
	// mechanism) has no way to exempt a CIDR or a port from a country block
	// yet: nft_script.go's geo DROP rule is unconditional
	// (`ip saddr @geo_xx drop`), unlike the ipset branch below, whose
	// DEFENSIA-GEO iptables chain already refuses to enforce rather than
	// cut off a customer's configured exemptions (crawlers, CDN edges,
	// mail ports) when the exemption set itself fails to sync. Mirror that
	// same "lesser harm" decision here instead of silently blocking with
	// the exemptions ignored (phase 17 independent review, WARN-03,
	// 2026-11-18): treat every desired country as unenforceable — same
	// outcome as if nothing were configured to block — until the backend
	// can actually honor the configured exemptions.
	if b.Name() != "ipset" && len(desired) > 0 && (len(g.exemptCIDRs) > 0 || len(g.exemptPorts) > 0) {
		log.Printf("[geoblock] WARNING: %d exempt CIDRs / %d exempt ports configured but the %s backend has no exemption mechanism yet — country blocks NOT enforced (enforcing anyway would also block the configured exemptions: crawlers/CDN/mail)", len(g.exemptCIDRs), len(g.exemptPorts), b.Name())
		for cc := range g.activeCountries {
			g.removeCountry(b, cc)
		}
		g.enforced = false
		g.unapplied = len(desired)
		g.unappliedReason = fmt.Sprintf("%s backend has no exemption mechanism for the configured CIDR/port exemptions", b.Name())
		return
	}

	g.unapplied = 0
	g.unappliedReason = ""

	// Ensure protected IPs have ACCEPT rules before any geo DROP
	if len(desired) > 0 {
		if err := b.EnsureAccept(g.protectedIPs); err != nil {
			log.Printf("[geoblock] failed to add ACCEPT rule(s) for protected IPs: %v", err)
		}
	}

	// Load sets for countries that are newly blocked
	for cc := range desired {
		if !g.activeCountries[cc] {
			g.addCountry(b, cc)
		}
	}

	// geochain.go's DEFENSIA-GEO iptables chain references ipset sets by
	// name via `-m set --match-set` — that only ever resolves on the ipset
	// backend. Every other GeoSupported backend (nftables) wires its own
	// per-country DROP rule directly inside Backend.GeoReplace/GeoRemove
	// (backend_nft.go's `geo` chain), so there is no separate chain-rebuild
	// step for it — rebuilding geoChain against a backend without matching
	// ipset sets fails with "Set ... doesn't exist", not a no-op.
	if b.Name() == "ipset" {
		// Point the chain at what is actually loaded
		var sets []string
		for cc := range desired {
			if g.activeCountries[cc] {
				sets = append(sets, ipsetSetName(cc))
			}
		}
		sort.Strings(sets)
		if len(sets) == 0 {
			teardownGeoChain()
			g.dropExemptSet()
		} else if exemptOK := g.syncExemptSet(); len(g.exemptCIDRs) > 0 && !exemptOK {
			// Blocking without the exemptions would cut off search engines and CDN
			// edges; leaving countries unblocked until the next sync is the lesser harm.
			teardownGeoChain()
			g.enforced = false
		} else if err := ensureGeoChain(); err != nil {
			log.Printf("[geoblock] %v — country blocks NOT enforced", err)
			g.enforced = false
		} else if err := rebuildGeoChain(g.protectedIPs, exemptOK, g.exemptPorts, sets); err != nil {
			log.Printf("[geoblock] %v — country blocks NOT enforced", err)
			g.enforced = false
		} else {
			g.enforced = true
		}
		if len(sets) == 0 {
			g.enforced = false
		}
	} else {
		// No exemptions configured — the early return above already
		// handles the case where there are any. Just report whether every
		// desired country actually loaded at the kernel level.
		enforcedCount := 0
		for cc := range desired {
			if g.activeCountries[cc] {
				enforcedCount++
			}
		}
		g.enforced = enforcedCount > 0 && enforcedCount == len(desired)
	}

	// Destroy sets for countries that are no longer blocked
	for cc := range g.activeCountries {
		if !desired[cc] {
			g.removeCountry(b, cc)
		}
	}
}

// addCountry asks the backend to load the country's CIDRs into its set. The
// iptables-level DROP rule is geoChain's job, rebuilt by the caller.
func (g *GeoBlocker) addCountry(b Backend, cc string) {
	cidrs, err := g.cidrProvider(cc)
	if err != nil {
		log.Printf("[geoblock] error getting CIDRs for %s: %v", cc, err)
		g.unapplied++
		g.unappliedReason = err.Error()
		return
	}
	if len(cidrs) == 0 {
		log.Printf("[geoblock] no CIDRs found for %s — skipping", cc)
		g.unapplied++
		g.unappliedReason = fmt.Sprintf("no CIDRs found for %s", cc)
		return
	}

	loaded, err := b.GeoReplace(cc, cidrs)
	if err != nil {
		log.Printf("[geoblock] failed to load country set for %s: %v", cc, err)
		g.unapplied++
		g.unappliedReason = err.Error()
		return
	}

	g.activeCountries[cc] = true
	log.Printf("[geoblock] ✓ blocked %s: %d CIDRs loaded (%s)", cc, loaded, b.Name())
}

// removeCountry asks the backend to destroy the country's set. Callers must
// rebuild geoChain without it first.
func (g *GeoBlocker) removeCountry(b Backend, cc string) {
	if err := b.GeoRemove(cc); err != nil {
		log.Printf("[geoblock] warning: failed to remove country set for %s: %v", cc, err)
	}
	delete(g.activeCountries, cc)
	log.Printf("[geoblock] ✓ unblocked %s", cc)
}

// Invalidate forgets which sets are loaded, so the next ApplyCountryBlocks
// reloads every country — used after the GeoIP database is replaced.
func (g *GeoBlocker) Invalidate() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.activeCountries = make(map[string]bool)
}

// Enforced reports whether country blocks are live in the kernel right now,
// and how many countries they cover.
func (g *GeoBlocker) Enforced() (bool, int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.enforced {
		return false, 0
	}
	return true, len(g.activeCountries)
}

// Unapplied reports how many desired countries were NOT enforced at the
// kernel level on the last ApplyCountryBlocks call, and why. (0, "") means
// everything desired is enforced (or nothing was desired).
func (g *GeoBlocker) Unapplied() (int, string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.unapplied, g.unappliedReason
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

// Cleanup removes all geoblock sets and iptables rules (used on shutdown).
func (g *GeoBlocker) Cleanup() {
	g.mu.Lock()
	defer g.mu.Unlock()
	teardownGeoChain()
	g.dropExemptSet()
	b := current()
	for cc := range g.activeCountries {
		g.removeCountry(b, cc)
	}
	g.enforced = false
}

// SetExemptions records the CIDRs and TCP ports geoblocking must never drop.
// Applied on the next ApplyCountryBlocks.
func (g *GeoBlocker) SetExemptions(cidrs []string, ports []int) {
	g.mu.Lock()
	defer g.mu.Unlock()

	clean := make([]string, 0, len(cidrs))
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if _, n, err := net.ParseCIDR(c); err == nil && n.IP.To4() != nil {
			clean = append(clean, n.String())
		}
	}
	sort.Strings(clean)
	g.exemptCIDRs = clean

	g.exemptPorts = g.exemptPorts[:0]
	for _, p := range ports {
		if p > 0 && p < 65536 && len(g.exemptPorts) < 15 {
			g.exemptPorts = append(g.exemptPorts, p)
		}
	}
}

// syncExemptSet loads geoExemptSet when the CIDR list changed and reports
// whether the chain may reference it. Caller holds g.mu.
func (g *GeoBlocker) syncExemptSet() bool {
	key := strings.Join(g.exemptCIDRs, ",")
	if key == g.exemptKey && g.exemptLoaded {
		return true
	}
	g.exemptLoaded = loadGeoExemptSet(g.exemptCIDRs)
	if g.exemptLoaded {
		g.exemptKey = key
		log.Printf("[geoblock] exempt from country blocks: %d CIDRs (CDNs, crawlers, monitors), ports %v", len(g.exemptCIDRs), g.exemptPorts)
	} else if len(g.exemptCIDRs) > 0 {
		log.Printf("[geoblock] WARNING: could not load the %d exempt CIDRs — crawlers and CDNs in blocked countries will be blocked", len(g.exemptCIDRs))
	}
	return g.exemptLoaded
}

// dropExemptSet destroys geoExemptSet once nothing references it.
func (g *GeoBlocker) dropExemptSet() {
	if g.exemptKey == "" && !g.exemptLoaded {
		return
	}
	_ = flushIpset(geoExemptSet)
	_ = destroyIpset(geoExemptSet)
	g.exemptKey = ""
	g.exemptLoaded = false
}
