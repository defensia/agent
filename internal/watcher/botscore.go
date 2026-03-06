package watcher

import (
	"strconv"
	"sync"
	"time"
)

const (
	maxBotScoreEntries = 20000
	maxSignalsPerIP    = 20
	decayPointsPerMin  = 5
	cleanupMaxAge      = 30 * time.Minute
)

// Score thresholds
const (
	thresholdObserve   = 30
	thresholdThrottle  = 60
	thresholdBlock     = 80
	thresholdBlacklist = 100
)

// BotScoreTracker maintains per-IP bot scores with decay.
type BotScoreTracker struct {
	mu      sync.Mutex
	entries map[string]*ipScore
}

type ipScore struct {
	score      int
	signals    []scoreSignal
	lastUpdate time.Time
	firstSeen  time.Time
}

type scoreSignal struct {
	reason string
	points int
	at     time.Time
}

// NewBotScoreTracker creates a new scorer.
func NewBotScoreTracker() *BotScoreTracker {
	return &BotScoreTracker{
		entries: make(map[string]*ipScore),
	}
}

// AddScore adds points to an IP's bot score. Returns the new total score and category.
// Must NOT be called with WebWatcher.mu held (this has its own lock).
func (b *BotScoreTracker) AddScore(ip, reason string, points int) (int, string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	entry := b.entries[ip]
	if entry == nil {
		entry = &ipScore{
			firstSeen:  now,
			lastUpdate: now,
		}
		b.entries[ip] = entry
	}

	// Apply decay based on time since last update
	elapsed := now.Sub(entry.lastUpdate)
	if elapsed > time.Minute {
		decay := int(elapsed.Minutes()) * decayPointsPerMin
		entry.score -= decay
		if entry.score < 0 {
			entry.score = 0
		}
	}

	entry.score += points
	entry.lastUpdate = now

	// Keep last N signals
	entry.signals = append(entry.signals, scoreSignal{
		reason: reason,
		points: points,
		at:     now,
	})
	if len(entry.signals) > maxSignalsPerIP {
		entry.signals = entry.signals[len(entry.signals)-maxSignalsPerIP:]
	}

	return entry.score, b.classifyLocked(entry)
}

// GetScore returns the current score and category for an IP.
func (b *BotScoreTracker) GetScore(ip string) (int, string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	entry := b.entries[ip]
	if entry == nil {
		return 0, "unknown"
	}

	// Apply decay
	now := time.Now()
	elapsed := now.Sub(entry.lastUpdate)
	if elapsed > time.Minute {
		decay := int(elapsed.Minutes()) * decayPointsPerMin
		effective := entry.score - decay
		if effective < 0 {
			effective = 0
		}
		return effective, b.classifyLocked(entry)
	}

	return entry.score, b.classifyLocked(entry)
}

// ActionForScore returns the action string based on the score.
func ActionForScore(score int) string {
	switch {
	case score >= thresholdBlacklist:
		return "blacklist"
	case score >= thresholdBlock:
		return "block"
	case score >= thresholdThrottle:
		return "throttle"
	case score >= thresholdObserve:
		return "observe"
	default:
		return "normal"
	}
}

// SeverityForAction returns the event severity for a given action.
func SeverityForAction(action string) string {
	switch action {
	case "blacklist":
		return "critical"
	case "block":
		return "critical"
	case "throttle":
		return "warning"
	case "observe":
		return "info"
	default:
		return "info"
	}
}

// DecayAndCleanup removes expired entries and applies decay. Called from cleanupLoop.
func (b *BotScoreTracker) DecayAndCleanup() {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	for ip, entry := range b.entries {
		elapsed := now.Sub(entry.lastUpdate)

		// Remove entries older than max age
		if elapsed > cleanupMaxAge {
			delete(b.entries, ip)
			continue
		}

		// Apply decay
		if elapsed > time.Minute {
			decay := int(elapsed.Minutes()) * decayPointsPerMin
			entry.score -= decay
			if entry.score <= 0 {
				delete(b.entries, ip)
			}
		}
	}

	// Hard cap on total entries
	if len(b.entries) > maxBotScoreEntries {
		// Evict lowest-score entries
		type ipEntry struct {
			ip    string
			score int
		}
		all := make([]ipEntry, 0, len(b.entries))
		for ip, e := range b.entries {
			all = append(all, ipEntry{ip, e.score})
		}
		// Simple eviction: remove bottom half
		threshold := len(all) / 2
		for i, e := range all {
			if i < threshold {
				delete(b.entries, e.ip)
			}
		}
	}
}

// EnrichDetails adds bot score fields to an event details map.
func EnrichBotDetails(details map[string]string, score int, category, action string) map[string]string {
	details["bot_score"] = strconv.Itoa(score)
	details["bot_category"] = category
	details["bot_action"] = action
	return details
}

// classifyLocked determines the bot category from accumulated signals. Caller must hold b.mu.
func (b *BotScoreTracker) classifyLocked(entry *ipScore) string {
	has := make(map[string]bool)
	for _, s := range entry.signals {
		has[s.reason] = true
	}

	if has["honeypot_triggered"] || has["scanner_ua"] || has["scanner_detected"] {
		return "scanner"
	}
	if has["sql_injection"] || has["rce_attempt"] || has["xss_attempt"] || has["ssrf_attempt"] || has["web_shell"] || has["shellshock"] || has["web_exploit"] {
		return "exploit_bot"
	}
	if has["wp_bruteforce"] || has["xmlrpc_abuse"] {
		return "credential_stuffer"
	}
	if has["404_flood"] {
		return "scraper"
	}
	return "unknown"
}
