package watcher

import (
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// EventFunc is called when a suspicious event is detected (may or may not result in a ban).
type EventFunc func(ip, eventType, severity string, details map[string]string)

// WebWatcher tails a web server access log and bans IPs that match attack patterns.
type WebWatcher struct {
	logPath string
	onBan   BanFunc
	onEvent EventFunc
	checkIP CheckIPFunc

	mu        sync.Mutex
	banned    map[string]bool
	whitelist map[string]bool
	wlNets    []*net.IPNet

	// Per-rule attempt tracking: ruleKey:ip → timestamps
	attempts map[string][]time.Time
}

// DetectWebLogPath returns the web server access log path, or empty string if none found.
func DetectWebLogPath() string {
	if p := os.Getenv("WEB_LOG_PATH"); p != "" {
		return p
	}
	if _, err := os.Stat("/var/log/nginx/access.log"); err == nil {
		return "/var/log/nginx/access.log"
	}
	if _, err := os.Stat("/var/log/apache2/access.log"); err == nil {
		return "/var/log/apache2/access.log"
	}
	if _, err := os.Stat("/var/log/httpd/access_log"); err == nil {
		return "/var/log/httpd/access_log"
	}
	return ""
}

// NewWebWatcher creates a watcher for the web server access log.
func NewWebWatcher(onBan BanFunc, onEvent EventFunc) *WebWatcher {
	path := DetectWebLogPath()

	return &WebWatcher{
		logPath:   path,
		onBan:     onBan,
		onEvent:   onEvent,
		attempts:  make(map[string][]time.Time),
		banned:    make(map[string]bool),
		whitelist: make(map[string]bool),
	}
}

// SetCheckIP sets a callback for immediate ban (e.g. geoblocking).
func (w *WebWatcher) SetCheckIP(fn CheckIPFunc) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.checkIP = fn
}

// UpdateWhitelist replaces the whitelist.
func (w *WebWatcher) UpdateWhitelist(ips []string, cidrs []string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.whitelist = make(map[string]bool, len(ips))
	for _, ip := range ips {
		w.whitelist[ip] = true
	}

	w.wlNets = make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			w.wlNets = append(w.wlNets, ipNet)
		}
	}
}

func (w *WebWatcher) isWhitelisted(ip string) bool {
	if w.whitelist[ip] {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range w.wlNets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// Run starts tailing the access log. Blocks indefinitely.
func (w *WebWatcher) Run() {
	if w.logPath == "" {
		log.Printf("[webwatcher] no web server log found — disabled")
		return
	}
	log.Printf("[webwatcher] watching %s", w.logPath)

	// Periodic cleanup of stale attempts
	go w.cleanupLoop()

	for {
		if err := w.tail(); err != nil {
			log.Printf("[webwatcher] error: %v — retrying in 5s", err)
			time.Sleep(5 * time.Second)
		}
	}
}

func (w *WebWatcher) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		w.mu.Lock()
		now := time.Now()
		for key, times := range w.attempts {
			var recent []time.Time
			for _, t := range times {
				if now.Sub(t) <= 5*time.Minute {
					recent = append(recent, t)
				}
			}
			if len(recent) == 0 {
				delete(w.attempts, key)
			} else {
				w.attempts[key] = recent
			}
		}
		// Cap total entries to prevent unbounded memory growth
		if len(w.attempts) > 50000 {
			w.attempts = make(map[string][]time.Time)
		}
		w.mu.Unlock()
	}
}

// tail follows the access log file, identical to authlog watcher's approach.
func (w *WebWatcher) tail() error {
	f, err := os.Open(w.logPath)
	if err != nil {
		return err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return err
	}
	offset := fi.Size()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	var partial string

	for range ticker.C {
		fi, err = os.Stat(w.logPath)
		if err != nil {
			return err
		}

		size := fi.Size()
		if size <= offset {
			if size < offset {
				offset = 0 // rotated
			}
			continue
		}

		readF, err := os.Open(w.logPath)
		if err != nil {
			return err
		}

		readF.Seek(offset, io.SeekStart)
		buf := make([]byte, size-offset)
		n, err := io.ReadFull(readF, buf)
		readF.Close()

		if n > 0 {
			partial += string(buf[:n])
			offset += int64(n)

			for {
				idx := strings.IndexByte(partial, '\n')
				if idx < 0 {
					break
				}
				w.processLine(partial[:idx])
				partial = partial[idx+1:]
			}
		}

		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}
	}

	return nil
}

// accessLogEntry holds parsed fields from an access log line.
type accessLogEntry struct {
	ip        string
	method    string
	uri       string
	status    int
	userAgent string
}

// parseAccessLog parses a combined log format line without regex.
// Format: IP - - [timestamp] "METHOD URI PROTO" STATUS SIZE "REFERER" "USER-AGENT"
func parseAccessLog(line string) (accessLogEntry, bool) {
	var e accessLogEntry

	// Extract IP (first field)
	spaceIdx := strings.IndexByte(line, ' ')
	if spaceIdx < 0 {
		return e, false
	}
	e.ip = line[:spaceIdx]

	// Validate IP has at least a dot (quick sanity check)
	if !strings.ContainsRune(e.ip, '.') && !strings.ContainsRune(e.ip, ':') {
		return e, false
	}

	// Find request line between first pair of quotes: "METHOD URI PROTO"
	q1 := strings.IndexByte(line, '"')
	if q1 < 0 {
		return e, false
	}
	q2 := strings.IndexByte(line[q1+1:], '"')
	if q2 < 0 {
		return e, false
	}
	reqLine := line[q1+1 : q1+1+q2]

	// Parse method and URI from request line
	parts := strings.SplitN(reqLine, " ", 3)
	if len(parts) < 2 {
		return e, false
	}
	e.method = parts[0]
	e.uri = parts[1]

	// Parse status code: first number after closing quote
	afterReq := line[q1+1+q2+2:] // skip past `" `
	statusStr := ""
	for i, c := range afterReq {
		if c >= '0' && c <= '9' {
			statusStr += string(c)
		} else if i > 0 {
			break
		}
	}
	if statusStr != "" {
		e.status, _ = strconv.Atoi(statusStr)
	}

	// Extract user-agent: last quoted string
	lastQ2 := strings.LastIndexByte(line, '"')
	if lastQ2 > 0 {
		sub := line[:lastQ2]
		lastQ1 := strings.LastIndexByte(sub, '"')
		if lastQ1 >= 0 {
			e.userAgent = sub[lastQ1+1:]
		}
	}

	return e, e.ip != "" && e.uri != ""
}

// ── Detection rules ─────────────────────────────────────────────────

// Instant-ban patterns: a single match = immediate ban (zero false positives)
var instantBanPatterns = []struct {
	name     string
	patterns []string
	eventType string
}{
	{"path_traversal", []string{"../", "etc/passwd", "etc/shadow", "proc/self"}, "path_traversal"},
	{"sql_injection", []string{"union+select", "union%20select", "' or 1=1", "' or '1'='1", "benchmark(", "sleep(", "waitfor+delay"}, "sql_injection"},
}

var scannerAgents = []string{
	"sqlmap", "nikto", "nmap", "masscan", "dirbuster", "wpscan",
	"gobuster", "dirb", "nuclei", "acunetix", "nessus", "openvas",
	"havij", "w3af",
}

// Threshold-based rules
type thresholdRule struct {
	key       string    // map key prefix
	eventType string
	threshold int
	window    time.Duration
}

var (
	ruleWPLogin    = thresholdRule{"wp_login", "wp_bruteforce", 10, 2 * time.Minute}
	ruleXMLRPC     = thresholdRule{"xmlrpc", "xmlrpc_abuse", 5, 1 * time.Minute}
	rulePluginScan = thresholdRule{"plugin_scan", "scanner_detected", 5, 5 * time.Minute}
	rule404Flood   = thresholdRule{"404_flood", "404_flood", 30, 5 * time.Minute}
)

func (w *WebWatcher) processLine(line string) {
	entry, ok := parseAccessLog(line)
	if !ok {
		return
	}

	ip := entry.ip
	uriLower := strings.ToLower(entry.uri)
	uaLower := strings.ToLower(entry.userAgent)

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.banned[ip] {
		return
	}
	if w.isWhitelisted(ip) {
		return
	}

	// Geoblocking callback
	if w.checkIP != nil {
		if reason := w.checkIP(ip); reason != "" {
			w.banned[ip] = true
			go w.onBan(ip, reason, 1)
			return
		}
	}

	// ── Instant-ban: path traversal & SQL injection ──
	for _, rule := range instantBanPatterns {
		for _, pat := range rule.patterns {
			if strings.Contains(uriLower, pat) {
				w.banned[ip] = true
				go w.onBan(ip, rule.eventType, 1)
				go w.onEvent(ip, rule.eventType, "critical", map[string]string{
					"uri":        entry.uri,
					"method":     entry.method,
					"user_agent": entry.userAgent,
					"pattern":    pat,
				})
				return
			}
		}
	}

	// ── Instant-ban: known scanner user-agents ──
	for _, agent := range scannerAgents {
		if strings.Contains(uaLower, agent) {
			w.banned[ip] = true
			go w.onBan(ip, "scanner_detected", 1)
			go w.onEvent(ip, "scanner_detected", "high", map[string]string{
				"uri":        entry.uri,
				"user_agent": entry.userAgent,
				"scanner":    agent,
			})
			return
		}
	}

	// ── Pre-filter: only process suspicious requests beyond this point ──
	// Skip normal 2xx/3xx responses to non-sensitive URIs
	isSuspiciousURI := strings.Contains(uriLower, "wp-login") ||
		strings.Contains(uriLower, "xmlrpc") ||
		strings.Contains(uriLower, "wp-content/plugins/") ||
		strings.Contains(uriLower, "wp-admin") ||
		strings.Contains(uriLower, "phpmyadmin") ||
		strings.Contains(uriLower, ".env") ||
		strings.Contains(uriLower, "config.") ||
		strings.Contains(uriLower, "debug") ||
		strings.Contains(uriLower, "shell") ||
		strings.Contains(uriLower, "eval(") ||
		strings.Contains(uriLower, "base64")

	is4xx := entry.status >= 400 && entry.status < 500

	if !isSuspiciousURI && !is4xx {
		return // Normal traffic — skip
	}

	now := time.Now()

	// ── Threshold: WP Login brute force ──
	if entry.method == "POST" && strings.Contains(uriLower, "wp-login.php") && entry.status != 302 {
		if w.checkThreshold(ip, ruleWPLogin, now) {
			go w.onEvent(ip, ruleWPLogin.eventType, "critical", map[string]string{
				"uri": entry.uri,
			})
		}
		return
	}

	// ── Threshold: XMLRPC abuse ──
	if entry.method == "POST" && strings.Contains(uriLower, "xmlrpc.php") {
		if w.checkThreshold(ip, ruleXMLRPC, now) {
			go w.onEvent(ip, ruleXMLRPC.eventType, "high", map[string]string{
				"uri": entry.uri,
			})
		}
		return
	}

	// ── Threshold: plugin scanner ──
	if strings.Contains(uriLower, "wp-content/plugins/") && entry.status == 404 {
		if w.checkThreshold(ip, rulePluginScan, now) {
			go w.onEvent(ip, rulePluginScan.eventType, "medium", map[string]string{
				"uri": entry.uri,
			})
		}
		return
	}

	// ── Threshold: 404 flood ──
	if entry.status == 404 {
		if w.checkThreshold(ip, rule404Flood, now) {
			go w.onEvent(ip, rule404Flood.eventType, "medium", map[string]string{
				"uri": entry.uri,
			})
		}
		return
	}
}

// checkThreshold increments the counter for a rule+IP and bans if threshold exceeded.
// Returns true if the IP was banned. Caller must hold w.mu.
func (w *WebWatcher) checkThreshold(ip string, rule thresholdRule, now time.Time) bool {
	key := rule.key + ":" + ip

	// Clean old entries
	var recent []time.Time
	for _, t := range w.attempts[key] {
		if now.Sub(t) <= rule.window {
			recent = append(recent, t)
		}
	}
	recent = append(recent, now)
	w.attempts[key] = recent

	if len(recent) >= rule.threshold {
		w.banned[ip] = true
		count := len(recent)
		go w.onBan(ip, rule.eventType, count)
		return true
	}
	return false
}
