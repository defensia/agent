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
	// Strip IPv4-mapped IPv6 prefix (::ffff:1.2.3.4 → 1.2.3.4)
	// PTR lookups fail on mapped addresses but work on the plain IPv4.
	ip = strings.TrimPrefix(ip, "::ffff:")

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

// metaNetworks is the address space announced by Meta's AS32934, collapsed from
// the RADb route objects (whois -h whois.radb.net -- '-i origin AS32934').
//
// rDNS alone cannot verify Facebook's fetchers: over seven days across the fleet,
// 4,540 of 15,127 facebookexternalhit requests flagged as spoofed came from
// 2a03:2880::/32 — Meta's own network, on addresses with no PTR record at all.
var metaNetworks = mustParseCIDRs(
	"31.13.24.0/21", "31.13.64.0/18", "45.64.40.0/22",
	"57.141.0.0/20", "57.141.16.0/21", "57.141.24.0/22", "57.141.28.0/23",
	"57.144.0.0/14", "66.220.144.0/20", "69.63.176.0/20", "69.171.224.0/19",
	"74.119.76.0/22", "102.132.96.0/20", "103.4.96.0/22", "129.134.0.0/16",
	"147.75.208.0/20", "157.240.0.0/16", "163.70.128.0/17", "163.77.128.0/17",
	"173.252.64.0/18", "179.60.192.0/22", "185.60.216.0/22", "185.89.216.0/22",
	"204.15.20.0/22",
	"2401:db00::/32", "2620:0:1c00::/40", "2803:6080::/29", "2a03:2880::/31",
	"2a03:2887:ff2c::/47", "2a03:83e0::/32", "2a10:f781:10:cee0::/64",
)

// knownBotNetworks maps a bot slug to the address space its operator publishes.
// A request from inside it is verified outright, before any DNS lookup.
var knownBotNetworks = map[string][]*net.IPNet{
	"facebookbot": metaNetworks,
}

// inKnownBotNetwork reports whether ip lies in the published network of the bot
// identified by slug. False for bots with no published network.
func inKnownBotNetwork(ip, slug string) bool {
	nets, ok := knownBotNetworks[slug]
	if !ok {
		return false
	}
	parsed := net.ParseIP(strings.TrimPrefix(ip, "::ffff:"))
	if parsed == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("watcher: bad CIDR " + c)
		}
		out = append(out, n)
	}
	return out
}

// unverifiedBotEvent decides what a failed verification means for a request whose
// user agent claims an allow-listed bot.
//
// For a search crawler it means impersonation: Googlebot only ever runs from
// Google's network, so a claim that does not verify is a forgery. Social preview
// user agents do not carry that premise. Phones and in-app browsers send
// facebookexternalhit, Twitterbot and the rest themselves when they build a link
// preview, so a failed check is the normal result for most of the legitimate
// traffic — a household broadband line sharing a link, not an attacker. Those are
// reported as an unverified preview, at info, and never as spoofing.
func unverifiedBotEvent(category string) (eventType, severity, action string) {
	if category == "social" {
		return "bot_monitor", "info", "unverified_preview"
	}
	return "bot_spoofed", "warning", "spoofed"
}

// matchAllowBot checks if a UA matches a known bot with action="allow".
// Returns the matched bot fingerprint or nil. Must be called with w.mu held.
func (w *WebWatcher) matchAllowBot(uaLower, uaRaw string) *compiledBot {
	for i := range w.botFingerprints {
		bot := &w.botFingerprints[i]
		if bot.Action != "allow" {
			continue
		}
		if bot.IsRegex && bot.Re != nil {
			if bot.Re.MatchString(uaRaw) {
				return bot
			}
		} else if strings.Contains(uaLower, strings.ToLower(bot.Pattern)) {
			return bot
		}
	}
	return nil
}

// checkBotFcrdns verifies if a bot IP is legitimate using FCrDNS.
// slug is the bot fingerprint slug (e.g., "googlebot", "bingbot").
// Returns: verified (true = legitimate), hostname from rDNS.
// Only verifies bots that have known domain suffixes — returns (true, "") for unknown bots.
func (w *WebWatcher) checkBotFcrdns(ip, slug string) (bool, string) {
	// A published network is a stronger answer than rDNS, and needs no lookup.
	if inKnownBotNetwork(ip, slug) {
		return true, ""
	}

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
