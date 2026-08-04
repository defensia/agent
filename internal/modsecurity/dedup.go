package modsecurity

import (
	"sync"
	"time"
)

// Dedup tracks IPs recently reported by the ModSecurity audit log parser.
// The web log WAF watcher checks this before emitting events to avoid duplicates.
type Dedup struct {
	mu      sync.RWMutex
	entries map[string]time.Time // "ip" → last reported time
	window  time.Duration
}

// NewDedup creates a dedup tracker. Events from the same IP within the window
// are considered duplicates when the ModSecurity parser already reported them.
func NewDedup(window time.Duration) *Dedup {
	return &Dedup{
		entries: make(map[string]time.Time),
		window:  window,
	}
}

// Record marks an IP as recently reported by ModSecurity.
func (d *Dedup) Record(ip string) {
	d.mu.Lock()
	d.entries[ip] = time.Now()

	// Prune if too large
	if len(d.entries) > 2000 {
		now := time.Now()
		for k, t := range d.entries {
			if now.Sub(t) > d.window {
				delete(d.entries, k)
			}
		}
	}
	d.mu.Unlock()
}

// ShouldSkip returns true if ModSecurity recently reported this IP,
// meaning the web log watcher should skip its own detection to avoid duplication.
func (d *Dedup) ShouldSkip(ip string) bool {
	d.mu.RLock()
	t, ok := d.entries[ip]
	d.mu.RUnlock()

	if !ok {
		return false
	}
	return time.Since(t) < d.window
}
