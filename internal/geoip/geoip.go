package geoip

import (
	"log"
	"net"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

const defaultDBPath = "/etc/defensia/GeoLite2-Country.mmdb"

// Lookup provides country code lookups from MaxMind GeoLite2-Country database.
type Lookup struct {
	mu      sync.RWMutex
	db      *maxminddb.Reader
	blocked map[string]bool // lowercase country codes that are blocked
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

	l := &Lookup{blocked: make(map[string]bool)}

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
