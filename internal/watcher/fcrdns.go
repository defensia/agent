package watcher

import (
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// fcrdnsResult caches the result of a Forward-Confirmed rDNS check.
type fcrdnsResult struct {
	verified bool
	hostname string
	checkedAt time.Time
}

// fcrdnsCache stores FCrDNS verification results per IP.
type fcrdnsCache struct {
	mu      sync.RWMutex
	entries map[string]fcrdnsResult
	ttl     time.Duration
}

// newFcrdnsCache creates a new FCrDNS cache with the given TTL.
func newFcrdnsCache(ttl time.Duration) *fcrdnsCache {
	return &fcrdnsCache{
		entries: make(map[string]fcrdnsResult),
		ttl:     ttl,
	}
}

// lookup checks if a cached result exists and is still valid.
func (c *fcrdnsCache) lookup(ip string) (fcrdnsResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	r, ok := c.entries[ip]
	if !ok {
		return r, false
	}
	if time.Since(r.checkedAt) > c.ttl {
		return r, false
	}
	return r, true
}

// store saves a result to the cache.
func (c *fcrdnsCache) store(ip string, verified bool, hostname string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[ip] = fcrdnsResult{
		verified:  verified,
		hostname:  hostname,
		checkedAt: time.Now(),
	}

	// Prune expired entries if cache is large
	if len(c.entries) > 5000 {
		now := time.Now()
		for k, v := range c.entries {
			if now.Sub(v.checkedAt) > c.ttl {
				delete(c.entries, k)
			}
		}
	}
}

// knownBotDomains maps bot categories to their legitimate rDNS domain suffixes.
// Only bots in this list are FCrDNS-verified — all others skip verification.
var knownBotDomains = map[string][]string{
	// Google
	"googlebot":        {".googlebot.com", ".google.com"},
	"google-adsbot":    {".googlebot.com", ".google.com"},
	"google-mediabot":  {".googlebot.com", ".google.com"},
	"google-feedfetch": {".google.com"},
	// Bing
	"bingbot":         {".search.msn.com"},
	"msnbot":          {".search.msn.com"},
	"bingpreview":     {".search.msn.com"},
	// Yahoo / Oath
	"yahoo-slurp":     {".crawl.yahoo.net"},
	// Yandex
	"yandexbot":       {".yandex.ru", ".yandex.net", ".yandex.com"},
	// Baidu
	"baiduspider":     {".baidu.com", ".baidu.jp"},
	// Apple
	"applebot":        {".applebot.apple.com"},
	// DuckDuckGo
	"duckduckbot":     {".duckduckgo.com"},
	// Facebook
	"facebookbot":     {".facebook.com", ".fbsv.net"},
	// LinkedIn
	"linkedinbot":     {".linkedin.com"},
	// Twitter
	"twitterbot":      {".twttr.com"},
	// Pinterest
	"pinterestbot":    {".pinterest.com"},
	// Ahrefs
	"ahrefsbot":       {".ahrefs.com"},
	// SEMrush
	"semrushbot":      {".semrush.com"},
}

// verifyFcrdns performs Forward-Confirmed reverse DNS verification.
//
// Steps:
//  1. PTR lookup: IP → hostname (e.g., "crawl-66-249-66-1.googlebot.com")
//  2. Check if hostname ends with an expected domain suffix
//  3. Forward lookup: hostname → IPs
//  4. Verify the original IP is in the forward results
//
// Returns (verified, hostname). verified=true means the bot is legitimate.
func verifyFcrdns(ip string, expectedSuffixes []string) (bool, string) {
	// Step 1: PTR lookup
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return false, ""
	}

	hostname := strings.TrimSuffix(names[0], ".")
	hostLower := strings.ToLower(hostname)

	// Step 2: Check domain suffix
	suffixMatch := false
	for _, suffix := range expectedSuffixes {
		if strings.HasSuffix(hostLower, suffix) {
			suffixMatch = true
			break
		}
	}
	if !suffixMatch {
		return false, hostname
	}

	// Step 3: Forward lookup
	addrs, err := net.LookupHost(hostname)
	if err != nil || len(addrs) == 0 {
		return false, hostname
	}

	// Step 4: Verify original IP is in forward results
	for _, addr := range addrs {
		if addr == ip {
			return true, hostname
		}
	}

	return false, hostname
}

// checkBotFcrdns verifies if a bot IP is legitimate using FCrDNS.
// slug is the bot fingerprint slug (e.g., "googlebot", "bingbot").
// Returns: verified (true = legitimate), hostname from rDNS.
// Only verifies bots that have known domain suffixes — returns (true, "") for unknown bots.
func (w *WebWatcher) checkBotFcrdns(ip, slug string) (bool, string) {
	// Only verify bots we have domain data for
	suffixes, known := knownBotDomains[slug]
	if !known {
		// Not a verifiable bot — skip verification (don't penalize)
		return true, ""
	}

	// Check cache first
	if result, ok := w.fcrdns.lookup(ip); ok {
		return result.verified, result.hostname
	}

	// Perform FCrDNS (async-safe: called from goroutine in processLine)
	verified, hostname := verifyFcrdns(ip, suffixes)

	// Cache the result
	w.fcrdns.store(ip, verified, hostname)

	if verified {
		log.Printf("[fcrdns] %s verified as %s (%s)", ip, hostname, slug)
	} else {
		if hostname != "" {
			log.Printf("[fcrdns] %s SPOOFED: claims %s but rDNS=%s", ip, slug, hostname)
		} else {
			log.Printf("[fcrdns] %s SPOOFED: claims %s but no valid rDNS", ip, slug)
		}
	}

	return verified, hostname
}
