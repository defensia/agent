package geoip

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

const defaultDBPath = "/etc/defensia/GeoLite2-Country.mmdb"

// Lookup provides country code lookups from MaxMind GeoLite2-Country database.
type Lookup struct {
	mu        sync.RWMutex
	db        *maxminddb.Reader
	blocked   map[string]bool   // lowercase country codes that are blocked
	cidrCache map[string][]string // cached CIDRs per country code (extracted once)
}

type countryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// New creates a Lookup. If the database file doesn't exist, lookups return "".
func New(dbPath string) *Lookup {
	if dbPath == "" {
		dbPath = defaultDBPath
	}

	l := &Lookup{
		blocked:   make(map[string]bool),
		cidrCache: make(map[string][]string),
	}

	db, err := maxminddb.Open(dbPath)
	if err != nil {
		log.Printf("[geoip] database not found at %s — geoblocking disabled", dbPath)
		return l
	}

	l.db = db
	log.Printf("[geoip] loaded database from %s", dbPath)
	return l
}

// Close closes the database.
func (l *Lookup) Close() {
	if l.db != nil {
		l.db.Close()
	}
}

// Country returns the ISO 3166-1 alpha-2 country code for an IP, or "".
func (l *Lookup) Country(ipStr string) string {
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

// IsBlocked returns true if the given IP belongs to a blocked country.
// Returns the country code and blocked status.
func (l *Lookup) IsBlocked(ipStr string) (string, bool) {
	cc := l.Country(ipStr)
	if cc == "" {
		return "", false
	}

	l.mu.RLock()
	defer l.mu.RUnlock()

	return cc, l.blocked[cc]
}

// ExtractCIDRs returns all CIDRs for the given country code from the mmdb.
// Results are cached — the full mmdb iteration only happens once per country.
func (l *Lookup) ExtractCIDRs(countryCode string) ([]string, error) {
	if l.db == nil {
		return nil, fmt.Errorf("geoip database not loaded")
	}

	countryCode = strings.ToUpper(strings.TrimSpace(countryCode))
	if countryCode == "" {
		return nil, fmt.Errorf("empty country code")
	}

	l.mu.RLock()
	if cached, ok := l.cidrCache[countryCode]; ok {
		l.mu.RUnlock()
		log.Printf("[geoip] returning %d cached CIDRs for %s", len(cached), countryCode)
		return cached, nil
	}
	l.mu.RUnlock()

	var cidrs []string
	networks := l.db.Networks(maxminddb.SkipAliasedNetworks)
	for networks.Next() {
		var record countryRecord
		subnet, err := networks.Network(&record)
		if err != nil {
			continue
		}
		if record.Country.ISOCode == countryCode {
			cidrs = append(cidrs, subnet.String())
		}
	}
	if err := networks.Err(); err != nil {
		return cidrs, fmt.Errorf("network iteration error: %w", err)
	}

	// Cache the result
	l.mu.Lock()
	l.cidrCache[countryCode] = cidrs
	l.mu.Unlock()

	log.Printf("[geoip] extracted %d CIDRs for country %s (cached)", len(cidrs), countryCode)
	return cidrs, nil
}
