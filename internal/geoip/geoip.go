package geoip

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

const defaultDBPath = "/etc/defensia/GeoLite2-Country.mmdb"

// ProvisionedDBPath is where the agent stores the country database it downloads
// from the panel. Nothing ever put a file at defaultDBPath, so until Nov 2026
// every standard install ran with geoblocking silently disabled.
const ProvisionedDBPath = "/etc/defensia/geoip-country.mmdb"

// Lookup provides country code lookups from MaxMind GeoLite2-Country database.
type Lookup struct {
	mu        sync.RWMutex
	db        *maxminddb.Reader
	path      string
	blocked   map[string]bool     // lowercase country codes that are blocked
	cidrCache map[string][]string // cached CIDRs per country code (extracted once)
	exempt    []*net.IPNet        // ranges a country block never applies to (CDNs, crawlers)
}

type countryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// New creates a Lookup. With an empty dbPath it tries a hand-installed
// MaxMind file first, then the database provisioned from the panel. If neither
// exists, lookups return "" until Reload succeeds.
func New(dbPath string) *Lookup {
	l := &Lookup{
		blocked:   make(map[string]bool),
		cidrCache: make(map[string][]string),
	}

	candidates := []string{dbPath}
	if dbPath == "" {
		candidates = []string{defaultDBPath, ProvisionedDBPath}
	}
	for _, p := range candidates {
		if err := l.Reload(p); err == nil {
			return l
		}
	}

	log.Printf("[geoip] no country database at %s — geoblocking disabled until one is provisioned", strings.Join(candidates, " or "))
	return l
}

// Reload opens the database at path and swaps it in, dropping cached CIDRs.
// On error the current database, if any, stays in use.
func (l *Lookup) Reload(path string) error {
	db, err := maxminddb.Open(path)
	if err != nil {
		return err
	}

	l.mu.Lock()
	old := l.db
	l.db = db
	l.path = path
	l.cidrCache = make(map[string][]string)
	l.mu.Unlock()

	if old != nil {
		old.Close()
	}
	log.Printf("[geoip] loaded database from %s (built %s)", path, time.Unix(int64(db.Metadata.BuildEpoch), 0).UTC().Format("2006-01-02"))
	return nil
}

// Loaded reports whether a database is open, and which file.
func (l *Lookup) Loaded() (bool, string) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.db != nil, l.path
}

// Close closes the database.
func (l *Lookup) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.db != nil {
		l.db.Close()
		l.db = nil
	}
}

// Country returns the ISO 3166-1 alpha-2 country code for an IP, or "".
func (l *Lookup) Country(ipStr string) string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.db == nil {
		return ""
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}

	var record countryRecord
	if err := l.db.Lookup(ip, &record); err != nil {
		return ""
	}

	return record.Country.ISOCode
}

// SetBlocked replaces the set of blocked country codes.
func (l *Lookup) SetBlocked(codes []string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.blocked = make(map[string]bool, len(codes))
	for _, c := range codes {
		l.blocked[c] = true
	}

	log.Printf("[geoip] blocking %d countries: %v", len(codes), codes)
}

// SetExempt replaces the ranges IsBlocked never reports as blocked: the same
// CDN, crawler and monitor ranges the kernel country chain lets through.
// Without this, the per-IP geoblock ban banned Cloudflare edges that the
// chain itself exempts, taking proxied sites down for some visitors.
func (l *Lookup) SetExempt(cidrs []string) {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(c)); err == nil {
			nets = append(nets, n)
		}
	}
	l.mu.Lock()
	l.exempt = nets
	l.mu.Unlock()
}

// IsBlocked returns true if the given IP belongs to a blocked country and is
// not in an exempt range. Returns the country code and blocked status.
func (l *Lookup) IsBlocked(ipStr string) (string, bool) {
	cc := l.Country(ipStr)
	if cc == "" {
		return "", false
	}

	return cc, l.blockedFor(cc, ipStr)
}

// blockedFor decides for an IP already resolved to country cc.
func (l *Lookup) blockedFor(cc, ipStr string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if !l.blocked[cc] {
		return false
	}
	if ip := net.ParseIP(ipStr); ip != nil {
		for _, n := range l.exempt {
			if n.Contains(ip) {
				return false
			}
		}
	}
	return true
}

// ExtractCIDRs returns all CIDRs for the given country code from the mmdb.
// Results are cached — the full mmdb iteration only happens once per country.
func (l *Lookup) ExtractCIDRs(countryCode string) ([]string, error) {
	countryCode = strings.ToUpper(strings.TrimSpace(countryCode))
	if countryCode == "" {
		return nil, fmt.Errorf("empty country code")
	}

	// Hold the read lock for the whole walk so Reload cannot close the reader
	// underneath it.
	l.mu.RLock()
	if l.db == nil {
		l.mu.RUnlock()
		return nil, fmt.Errorf("geoip database not loaded")
	}
	if cached, ok := l.cidrCache[countryCode]; ok {
		l.mu.RUnlock()
		log.Printf("[geoip] returning %d cached CIDRs for %s", len(cached), countryCode)
		return cached, nil
	}
	db := l.db

	var cidrs []string
	networks := db.Networks(maxminddb.SkipAliasedNetworks)
	for networks.Next() {
		var record countryRecord
		subnet, err := networks.Network(&record)
		if err != nil {
			continue
		}
		if record.Country.ISOCode == countryCode {
			// Only include IPv4 CIDRs (ipset hash:net doesn't support IPv6)
			if subnet.IP.To4() != nil {
				cidrs = append(cidrs, subnet.String())
			}
		}
	}
	err := networks.Err()
	l.mu.RUnlock()
	if err != nil {
		return cidrs, fmt.Errorf("network iteration error: %w", err)
	}

	// Cache the result, unless the database was swapped while we walked it
	l.mu.Lock()
	if l.db == db {
		l.cidrCache[countryCode] = cidrs
	}
	l.mu.Unlock()

	log.Printf("[geoip] extracted %d CIDRs for country %s (cached)", len(cidrs), countryCode)
	return cidrs, nil
}
