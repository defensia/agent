package watcher

import (
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// EventFunc is called when a suspicious event is detected (may or may not result in a ban).
// Severity must be one of: "info", "warning", "critical" (matching the API validation).
type EventFunc func(ip, eventType, severity string, details map[string]string)

// WebWatcher tails web server access logs and bans IPs that match attack patterns.
type WebWatcher struct {
	logPaths []string
	onBan    BanFunc
	onEvent  EventFunc
	checkIP  CheckIPFunc

	mu        sync.Mutex
	banned    map[string]bool
	whitelist map[string]bool
	wlNets    []*net.IPNet

	// Per-rule attempt tracking: ruleKey:ip → timestamps
	attempts map[string][]time.Time
}

// DetectWebLogPaths returns all web server access log paths found.
// Detection order: env var → nginx config → apache config → well-known paths.
func DetectWebLogPaths() []string {
	seen := make(map[string]bool)
	var paths []string

	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}

	// 1. Explicit env var always wins (supports comma-separated)
	if env := os.Getenv("WEB_LOG_PATH"); env != "" {
		for _, p := range strings.Split(env, ",") {
			p = strings.TrimSpace(p)
			if _, err := os.Stat(p); err == nil {
				add(p)
			} else {
				log.Printf("[webwatcher] WEB_LOG_PATH=%s but file not found", p)
			}
		}
		if len(paths) > 0 {
			return paths
		}
	}

	// 2. Parse nginx config for ALL access_log directives
	for _, p := range detectNginxLogPaths() {
		add(p)
	}

	// 3. Parse apache config for ALL CustomLog directives
	for _, p := range detectApacheLogPaths() {
		add(p)
	}

	// 4. Well-known static paths as fallback (only if nothing found from config)
	if len(paths) == 0 {
		knownPaths := []string{
			"/var/log/nginx/access.log",
			"/var/log/apache2/access.log",
			"/var/log/apache2/other_vhosts_access.log",
			"/var/log/httpd/access_log",
			"/usr/local/apache/logs/access_log",
			"/var/log/httpd/access.log",
			"/usr/local/lsws/logs/access.log",
			"/var/log/caddy/access.log",
			"/var/log/nginx-access.log",
			"/var/log/access.log",
		}
		for _, p := range knownPaths {
			if _, err := os.Stat(p); err == nil {
				add(p)
			}
		}
	}

	return paths
}

// detectNginxLogPaths parses nginx config to find ALL access_log paths.
func detectNginxLogPaths() []string {
	out, err := exec.Command("nginx", "-T").CombinedOutput()
	if err != nil {
		return nil
	}

	seen := make(map[string]bool)
	var paths []string
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "access_log ") && !strings.HasPrefix(trimmed, "#") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				path := strings.TrimSuffix(parts[1], ";")
				if path == "off" || strings.HasPrefix(path, "syslog:") || strings.HasPrefix(path, "|") {
					continue
				}
				if !seen[path] {
					if _, err := os.Stat(path); err == nil {
						seen[path] = true
						paths = append(paths, path)
					}
				}
			}
		}
	}
	return paths
}

// detectApacheLogPaths parses apache config to find ALL CustomLog paths.
func detectApacheLogPaths() []string {
	// Check if apache is installed
	apacheInstalled := false
	for _, cmd := range []string{"apache2ctl", "apachectl", "httpd"} {
		if _, err := exec.LookPath(cmd); err == nil {
			apacheInstalled = true
			break
		}
	}
	if !apacheInstalled {
		return nil
	}

	seen := make(map[string]bool)
	var paths []string

	// Collect CustomLog paths from all config files
	configFiles := []string{
		"/etc/apache2/apache2.conf",
		"/etc/httpd/conf/httpd.conf",
		"/usr/local/apache/conf/httpd.conf",
	}

	// Add sites-enabled vhosts
	vhostFiles, _ := filepath.Glob("/etc/apache2/sites-enabled/*.conf")
	configFiles = append(configFiles, vhostFiles...)
	vhostFiles2, _ := filepath.Glob("/etc/httpd/conf.d/*.conf")
	configFiles = append(configFiles, vhostFiles2...)

	for _, cf := range configFiles {
		data, err := os.ReadFile(cf)
		if err != nil {
			continue
		}
		for _, p := range parseApacheCustomLogs(string(data)) {
			if !seen[p] {
				if _, err := os.Stat(p); err == nil {
					seen[p] = true
					paths = append(paths, p)
				}
			}
		}
	}

	return paths
}

// parseApacheCustomLogs extracts ALL CustomLog paths from apache config content.
func parseApacheCustomLogs(content string) []string {
	var paths []string
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "CustomLog ") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				path := strings.Trim(parts[1], "\"")
				if !strings.HasPrefix(path, "|") && !strings.HasPrefix(path, "syslog:") {
					paths = append(paths, path)
				}
			}
		}
	}
	return paths
}

// NewWebWatcher creates a watcher for web server access logs.
func NewWebWatcher(paths []string, onBan BanFunc, onEvent EventFunc) *WebWatcher {
	return &WebWatcher{
		logPaths:  paths,
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

// Run starts tailing all access logs. Blocks indefinitely.
func (w *WebWatcher) Run() {
	if len(w.logPaths) == 0 {
		log.Printf("[webwatcher] no web server logs found — disabled")
		return
	}

	for _, p := range w.logPaths {
		log.Printf("[webwatcher] watching %s", p)
	}

	// Periodic cleanup of stale attempts
	go w.cleanupLoop()

	// Start a goroutine per log file (all share the same mutex/state)
	var wg sync.WaitGroup
	for _, p := range w.logPaths {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			for {
				if err := w.tail(path); err != nil {
					log.Printf("[webwatcher] %s error: %v — retrying in 5s", filepath.Base(path), err)
					time.Sleep(5 * time.Second)
				}
			}
		}(p)
	}
	wg.Wait()
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

// tail follows a single access log file.
func (w *WebWatcher) tail(logPath string) error {
	f, err := os.Open(logPath)
	if err != nil {
		return err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return err
	}

	// WEBLOG_REPLAY=1 → process the entire existing file (for testing/backfill)
	var offset int64
	if os.Getenv("WEBLOG_REPLAY") == "1" {
		offset = 0
		log.Printf("[webwatcher] REPLAY mode: processing %s from beginning (%d bytes)", filepath.Base(logPath), fi.Size())
	} else {
		offset = fi.Size()
	}

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	var partial string

	for range ticker.C {
		fi, err = os.Stat(logPath)
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

		readF, err := os.Open(logPath)
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
	referer   string
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

	// Extract user-agent (last quoted string) and referer (second-to-last)
	lastQ2 := strings.LastIndexByte(line, '"')
	if lastQ2 > 0 {
		sub := line[:lastQ2]
		lastQ1 := strings.LastIndexByte(sub, '"')
		if lastQ1 >= 0 {
			e.userAgent = sub[lastQ1+1:]

			// Referer is the quoted string before user-agent
			sub2 := sub[:lastQ1]
			if refQ2 := strings.LastIndexByte(sub2, '"'); refQ2 > 0 {
				sub3 := sub2[:refQ2]
				if refQ1 := strings.LastIndexByte(sub3, '"'); refQ1 >= 0 {
					e.referer = sub3[refQ1+1:]
				}
			}
		}
	}

	return e, e.ip != "" && e.uri != ""
}

// ── Detection rules ─────────────────────────────────────────────────

// Instant-ban patterns: a single match = immediate ban (zero false positives).
// Checked against the lowercased URI.
var instantBanPatterns = []struct {
	name      string
	patterns  []string
	eventType string
}{
	// Path traversal & local file inclusion
	{"path_traversal", []string{
		"../", "..%2f", "..%252f",
		"etc/passwd", "etc/shadow", "proc/self",
	}, "path_traversal"},

	// SQL injection
	{"sql_injection", []string{
		"union+select", "union%20select", "union+all+select", "union%20all%20select",
		"' or 1=1", "' or '1'='1", "%27%20or%20", "%27+or+",
		"benchmark(", "sleep(", "waitfor+delay",
		"information_schema", "load_file(", "into+outfile", "into%20outfile",
		"group_concat(",
	}, "sql_injection"},

	// .env file probing — never served by any legitimate application
	{"env_probe", []string{"/.env"}, "env_probe"},

	// Config / secret file probing
	{"config_probe", []string{
		"wp-config.php", "wp-config.bak", "wp-config.old", "wp-config.txt",
		".git/config", ".git/head", "/.svn/", "/.hg/",
		"web.config", "/.htpasswd",
		"/server-status", "/server-info",
	}, "config_probe"},

	// Remote code execution attempts
	{"rce_attempt", []string{
		"eval(", "exec(", "system(", "passthru(", "shell_exec(",
		"phpinfo(", "php://input", "php://filter", "data://text",
		"${jndi:",
	}, "rce_attempt"},
}

var scannerAgents = []string{
	"sqlmap", "nikto", "nmap", "masscan", "dirbuster", "wpscan",
	"gobuster", "dirb", "nuclei", "acunetix", "nessus", "openvas",
	"havij", "w3af", "zgrab", "httprobe", "subfinder", "whatweb",
	"jorgee", "zmeu", "webdav", "python-requests/",
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
	refLower := strings.ToLower(entry.referer)

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
			go w.onEvent(ip, "scanner_detected", "warning", map[string]string{
				"uri":        entry.uri,
				"user_agent": entry.userAgent,
				"scanner":    agent,
			})
			return
		}
	}

	// ── Instant-ban: Shellshock (CVE-2014-6271) in Referer or User-Agent ──
	if strings.Contains(refLower, "() {") || strings.Contains(uaLower, "() {") {
		w.banned[ip] = true
		go w.onBan(ip, "shellshock", 1)
		go w.onEvent(ip, "shellshock", "critical", map[string]string{
			"uri":        entry.uri,
			"user_agent": entry.userAgent,
			"referer":    entry.referer,
		})
		return
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
			go w.onEvent(ip, ruleXMLRPC.eventType, "warning", map[string]string{
				"uri": entry.uri,
			})
		}
		return
	}

	// ── Threshold: plugin scanner ──
	if strings.Contains(uriLower, "wp-content/plugins/") && entry.status == 404 {
		if w.checkThreshold(ip, rulePluginScan, now) {
			go w.onEvent(ip, rulePluginScan.eventType, "info", map[string]string{
				"uri": entry.uri,
			})
		}
		return
	}

	// ── Threshold: 404 flood ──
	if entry.status == 404 {
		if w.checkThreshold(ip, rule404Flood, now) {
			go w.onEvent(ip, rule404Flood.eventType, "info", map[string]string{
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
