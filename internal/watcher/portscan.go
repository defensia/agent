package watcher

import (
	"log"
	"net"
	"sync"
	"time"
)

// portScanResult caches whether a client IP has open server ports.
type portScanResult struct {
	openPorts []int
	checkedAt time.Time
}

// portScanCache stores reverse port scan results per IP.
type portScanCache struct {
	mu      sync.RWMutex
	entries map[string]portScanResult
	ttl     time.Duration
}

func newPortScanCache(ttl time.Duration) *portScanCache {
	return &portScanCache{
		entries: make(map[string]portScanResult),
		ttl:     ttl,
	}
}

func (c *portScanCache) lookup(ip string) (portScanResult, bool) {
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

func (c *portScanCache) store(ip string, openPorts []int) {
	c.mu.Lock()
	c.entries[ip] = portScanResult{
		openPorts: openPorts,
		checkedAt: time.Now(),
	}

	// Prune if too large
	if len(c.entries) > 5000 {
		now := time.Now()
		for k, v := range c.entries {
			if now.Sub(v.checkedAt) > c.ttl {
				delete(c.entries, k)
			}
		}
	}
	c.mu.Unlock()
}

// reverseScanPorts are common server/proxy ports that indicate the client
// is infrastructure (server, proxy, VPN) rather than a regular browser.
var reverseScanPorts = []int{22, 80, 443, 8080, 3128, 8888}

// reverseScanTimeout is the TCP connect timeout per port.
const reverseScanTimeout = 2 * time.Second

// reversePortScan checks if a client IP has open server ports.
// Returns the list of open ports found. Uses cache to avoid repeat scans.
func (w *WebWatcher) reversePortScan(ip string) []int {
	// Don't scan private/local IPs
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() {
		return nil
	}

	// Check cache
	if result, ok := w.portScanResults.lookup(ip); ok {
		return result.openPorts
	}

	// Scan ports concurrently with early termination
	type portResult struct {
		port int
		open bool
	}

	results := make(chan portResult, len(reverseScanPorts))
	for _, port := range reverseScanPorts {
		go func(p int) {
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, itoa(p)), reverseScanTimeout)
			if err == nil {
				conn.Close()
				results <- portResult{p, true}
			} else {
				results <- portResult{p, false}
			}
		}(port)
	}

	var openPorts []int
	for i := 0; i < len(reverseScanPorts); i++ {
		r := <-results
		if r.open {
			openPorts = append(openPorts, r.port)
		}
	}

	w.portScanResults.store(ip, openPorts)

	if len(openPorts) > 0 {
		log.Printf("[portscan] %s has %d open ports: %v", ip, len(openPorts), openPorts)
	}

	return openPorts
}

// formatPorts converts a slice of port numbers to a comma-separated string.
func formatPorts(ports []int) string {
	var s string
	for i, p := range ports {
		if i > 0 {
			s += ","
		}
		s += itoa(p)
	}
	return s
}

// itoa converts int to string without importing strconv (already imported in weblog.go).
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [10]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
