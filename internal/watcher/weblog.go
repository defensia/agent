package watcher

import (
	"context"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// EventFunc is called when a suspicious event is detected (may or may not result in a ban).
// Severity must be one of: "info", "warning", "critical" (matching the API validation).
type EventFunc func(ip, eventType, severity string, details map[string]string)

// LogPathInfo holds a log file path and its associated domain names.
type LogPathInfo struct {
	Path    string
	Domains []string
}

// parseFileStats tracks parse success/failure rates per log file.
type parseFileStats struct {
	totalLines  int
	failedLines int
	warned      bool
}

// WebWatcher tails web server access logs and bans IPs that match attack patterns.
type WebWatcher struct {
	logPaths  []string
	domainMap map[string][]string // logPath → domain names
	onBan     BanFunc
	onEvent   EventFunc
	checkIP   CheckIPFunc

	mu        sync.Mutex
	banned    map[string]bool
	whitelist map[string]bool
	wlNets    []*net.IPNet

	// Per-rule attempt tracking: ruleKey:ip → timestamps
	attempts map[string][]time.Time

	// Parse failure tracking per log file
	parseStats map[string]*parseFileStats

	// Hot-reload: active goroutines with cancel functions
	activePaths map[string]context.CancelFunc
}

// ── Log path detection ──────────────────────────────────────────────

// DetectWebLogInfo returns all web server access log paths with associated domains.
// Detection order: env var → nginx config → apache config → well-known paths.
func DetectWebLogInfo() ([]LogPathInfo, map[string][]string) {
	seen := make(map[string]bool)
	var infos []LogPathInfo
	domainMap := make(map[string][]string)

	add := func(info LogPathInfo) {
		if !seen[info.Path] {
			seen[info.Path] = true
			infos = append(infos, info)
			if len(info.Domains) > 0 {
				domainMap[info.Path] = info.Domains
			}
		}
	}

	// 1. Explicit env var always wins (supports comma-separated, no domain info)
	if env := os.Getenv("WEB_LOG_PATH"); env != "" {
		for _, p := range strings.Split(env, ",") {
			p = strings.TrimSpace(p)
			if _, err := os.Stat(p); err == nil {
				add(LogPathInfo{Path: p})
			} else {
				log.Printf("[webwatcher] WEB_LOG_PATH=%s but file not found", p)
			}
		}
		if len(infos) > 0 {
			return infos, domainMap
		}
	}

	// 2. Parse nginx config for access_log + server_name
	for _, info := range detectNginxLogInfo() {
		add(info)
	}

	// 3. Parse apache config for CustomLog + ServerName
	for _, info := range detectApacheLogInfo() {
		add(info)
	}

	// 4. Well-known static paths as fallback (only if nothing found from config)
	if len(infos) == 0 {
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
				add(LogPathInfo{Path: p})
			}
		}
	}

	return infos, domainMap
}

// DetectWebLogPaths returns just the paths (backward compat wrapper).
func DetectWebLogPaths() []string {
	infos, _ := DetectWebLogInfo()
	paths := make([]string, len(infos))
	for i, info := range infos {
		paths[i] = info.Path
	}
	return paths
}

// detectNginxLogInfo parses nginx config to find ALL access_log paths with their server_names.
func detectNginxLogInfo() []LogPathInfo {
	out, err := exec.Command("nginx", "-T").CombinedOutput()
	if err != nil {
		return nil
	}

	type serverBlock struct {
		serverNames []string
		logPaths    []string
	}

	var blocks []serverBlock
	var current *serverBlock
	inServer := false
	braceDepth := 0       // depth within the current server block
	serverStartDepth := 0 // global depth when server{ was encountered

	// Track global brace depth for http-level access_log directives
	globalDepth := 0

	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Count braces in this line
		openBraces := strings.Count(trimmed, "{")
		closeBraces := strings.Count(trimmed, "}")

		prevGlobalDepth := globalDepth
		globalDepth += openBraces - closeBraces

		// Detect server block start: "server {" or "server\n{"
		if !inServer && strings.HasPrefix(trimmed, "server") {
			rest := strings.TrimPrefix(trimmed, "server")
			rest = strings.TrimSpace(rest)
			if rest == "{" || rest == "" || strings.HasPrefix(rest, "{") {
				inServer = true
				current = &serverBlock{}
				serverStartDepth = prevGlobalDepth
				braceDepth = openBraces - closeBraces
				continue
			}
		}

		if inServer {
			braceDepth += openBraces - closeBraces

			// Server block closed when braceDepth returns to 0
			if braceDepth <= 0 {
				if current != nil {
					blocks = append(blocks, *current)
				}
				current = nil
				inServer = false
				continue
			}

			// Inside server block — capture server_name
			if strings.HasPrefix(trimmed, "server_name ") {
				names := strings.TrimSuffix(strings.TrimPrefix(trimmed, "server_name "), ";")
				for _, n := range strings.Fields(names) {
					n = strings.TrimSpace(n)
					if n != "" && n != "_" {
						current.serverNames = append(current.serverNames, n)
					}
				}
			}

			// Inside server block — capture access_log
			if strings.HasPrefix(trimmed, "access_log ") {
				parts := strings.Fields(trimmed)
				if len(parts) >= 2 {
					path := strings.TrimSuffix(parts[1], ";")
					if path != "off" && !strings.HasPrefix(path, "syslog:") && !strings.HasPrefix(path, "|") {
						current.logPaths = append(current.logPaths, path)
					}
				}
			}
		} else {
			// Outside server blocks — http-level access_log (default for all vhosts)
			if strings.HasPrefix(trimmed, "access_log ") && globalDepth >= 1 {
				parts := strings.Fields(trimmed)
				if len(parts) >= 2 {
					path := strings.TrimSuffix(parts[1], ";")
					if path != "off" && !strings.HasPrefix(path, "syslog:") && !strings.HasPrefix(path, "|") {
						blocks = append(blocks, serverBlock{
							logPaths: []string{path},
						})
					}
				}
			}
		}

		_ = serverStartDepth // used for context, depth tracking is via braceDepth
	}

	// If server block wasn't closed (malformed), still capture it
	if current != nil && len(current.logPaths) > 0 {
		blocks = append(blocks, *current)
	}

	// Build deduplicated LogPathInfo list
	pathDomains := make(map[string]map[string]bool)
	for _, block := range blocks {
		for _, lp := range block.logPaths {
			if _, err := os.Stat(lp); err != nil {
				continue
			}
			if pathDomains[lp] == nil {
				pathDomains[lp] = make(map[string]bool)
			}
			for _, name := range block.serverNames {
				pathDomains[lp][name] = true
			}
		}
	}

	var result []LogPathInfo
	for path, domainSet := range pathDomains {
		var domains []string
		for d := range domainSet {
			domains = append(domains, d)
		}
		sort.Strings(domains)
		result = append(result, LogPathInfo{Path: path, Domains: domains})
	}

	return result
}

// detectApacheLogInfo parses apache config to find ALL CustomLog paths with their ServerNames.
func detectApacheLogInfo() []LogPathInfo {
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

	configFiles := []string{
		"/etc/apache2/apache2.conf",
		"/etc/httpd/conf/httpd.conf",
		"/usr/local/apache/conf/httpd.conf",
	}
	vhostFiles, _ := filepath.Glob("/etc/apache2/sites-enabled/*.conf")
	configFiles = append(configFiles, vhostFiles...)
	vhostFiles2, _ := filepath.Glob("/etc/httpd/conf.d/*.conf")
	configFiles = append(configFiles, vhostFiles2...)

	pathDomains := make(map[string]map[string]bool)

	for _, cf := range configFiles {
		data, err := os.ReadFile(cf)
		if err != nil {
			continue
		}
		for _, vhost := range parseApacheVhosts(string(data)) {
			for _, lp := range vhost.logPaths {
				if _, err := os.Stat(lp); err != nil {
					continue
				}
				if pathDomains[lp] == nil {
					pathDomains[lp] = make(map[string]bool)
				}
				for _, d := range vhost.serverNames {
					pathDomains[lp][d] = true
				}
			}
		}
	}

	var result []LogPathInfo
	for path, domainSet := range pathDomains {
		var domains []string
		for d := range domainSet {
			domains = append(domains, d)
		}
		sort.Strings(domains)
		result = append(result, LogPathInfo{Path: path, Domains: domains})
	}
	return result
}

type apacheVhost struct {
	serverNames []string
	logPaths    []string
}

// parseApacheVhosts extracts ServerName/ServerAlias + CustomLog pairs from Apache config.
func parseApacheVhosts(content string) []apacheVhost {
	var results []apacheVhost
	var current *apacheVhost

	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		lower := strings.ToLower(trimmed)

		if strings.HasPrefix(lower, "<virtualhost") {
			current = &apacheVhost{}
			continue
		}
		if strings.HasPrefix(lower, "</virtualhost") {
			if current != nil {
				results = append(results, *current)
				current = nil
			}
			continue
		}

		if current == nil {
			// Outside VirtualHost — capture global CustomLog
			if strings.HasPrefix(trimmed, "CustomLog ") {
				parts := strings.Fields(trimmed)
				if len(parts) >= 2 {
					path := strings.Trim(parts[1], "\"")
					if !strings.HasPrefix(path, "|") && !strings.HasPrefix(path, "syslog:") {
						results = append(results, apacheVhost{logPaths: []string{path}})
					}
				}
			}
			continue
		}

		if strings.HasPrefix(lower, "servername ") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				current.serverNames = append(current.serverNames, parts[1])
			}
		}
		if strings.HasPrefix(lower, "serveralias ") {
			parts := strings.Fields(trimmed)
			for _, alias := range parts[1:] {
				current.serverNames = append(current.serverNames, alias)
			}
		}
		if strings.HasPrefix(trimmed, "CustomLog ") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				path := strings.Trim(parts[1], "\"")
				if !strings.HasPrefix(path, "|") && !strings.HasPrefix(path, "syslog:") {
					current.logPaths = append(current.logPaths, path)
				}
			}
		}
	}
	return results
}

// ── WebWatcher lifecycle ────────────────────────────────────────────

// NewWebWatcher creates a watcher for web server access logs.
func NewWebWatcher(paths []string, domainMap map[string][]string, onBan BanFunc, onEvent EventFunc) *WebWatcher {
	if domainMap == nil {
		domainMap = make(map[string][]string)
	}
	return &WebWatcher{
		logPaths:    paths,
		domainMap:   domainMap,
		onBan:       onBan,
		onEvent:     onEvent,
		attempts:    make(map[string][]time.Time),
		banned:      make(map[string]bool),
		whitelist:   make(map[string]bool),
		parseStats:  make(map[string]*parseFileStats),
		activePaths: make(map[string]context.CancelFunc),
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

	// Startup logging with domain info
	totalDomains := 0
	for _, p := range w.logPaths {
		if domains, ok := w.domainMap[p]; ok && len(domains) > 0 {
			log.Printf("[webwatcher] watching %s (%s)", p, strings.Join(domains, ", "))
			totalDomains += len(domains)
		} else {
			log.Printf("[webwatcher] watching %s", p)
		}
	}
	if totalDomains > 0 {
		log.Printf("[webwatcher] monitoring %d log file(s) covering %d domain(s)", len(w.logPaths), totalDomains)
	}

	// Periodic cleanup of stale attempts
	go w.cleanupLoop()

	// Hot-reload of new log files every 5 minutes
	go w.hotReloadLoop()

	// Start a goroutine per log file
	for _, p := range w.logPaths {
		w.startTailGoroutine(p)
	}

	// Block forever
	select {}
}

// startTailGoroutine launches a tailing goroutine for a log file if not already active.
func (w *WebWatcher) startTailGoroutine(path string) {
	w.mu.Lock()
	if _, exists := w.activePaths[path]; exists {
		w.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.activePaths[path] = cancel
	w.mu.Unlock()

	go func() {
		defer func() {
			w.mu.Lock()
			delete(w.activePaths, path)
			w.mu.Unlock()
		}()

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			if err := w.tailWithContext(ctx, path); err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("[webwatcher] %s error: %v — retrying in 5s", filepath.Base(path), err)
				time.Sleep(5 * time.Second)
			}
		}
	}()
}

// hotReloadLoop periodically re-detects log paths and starts tailing new ones.
func (w *WebWatcher) hotReloadLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		newInfos, newDomainMap := DetectWebLogInfo()

		newPathSet := make(map[string]bool)
		for _, info := range newInfos {
			newPathSet[info.Path] = true
		}

		w.mu.Lock()

		// Update domain map
		for path, domains := range newDomainMap {
			w.domainMap[path] = domains
		}

		// Find new paths not yet being watched
		var toStart []string
		for _, info := range newInfos {
			if _, exists := w.activePaths[info.Path]; !exists {
				toStart = append(toStart, info.Path)
				w.logPaths = append(w.logPaths, info.Path)
			}
		}

		// Find removed paths to stop
		var toStop []string
		for path, cancel := range w.activePaths {
			if !newPathSet[path] {
				cancel()
				toStop = append(toStop, path)
			}
		}

		w.mu.Unlock()

		for _, path := range toStart {
			domainStr := ""
			if domains, ok := newDomainMap[path]; ok && len(domains) > 0 {
				domainStr = " (" + strings.Join(domains, ", ") + ")"
			}
			log.Printf("[webwatcher] new log detected: %s%s", path, domainStr)
			w.startTailGoroutine(path)
		}

		for _, path := range toStop {
			log.Printf("[webwatcher] log removed, stopped watching: %s", filepath.Base(path))
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

// tailWithContext follows a single access log file, respecting context cancellation.
func (w *WebWatcher) tailWithContext(ctx context.Context, logPath string) error {
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

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}

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
				w.processLine(logPath, partial[:idx])
				partial = partial[idx+1:]
			}
		}

		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}
	}
}

// ── Log parsing ─────────────────────────────────────────────────────

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
	key       string // map key prefix
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

// ── Line processing ─────────────────────────────────────────────────

// enrichDetails adds domain and log_file info to event details.
func (w *WebWatcher) enrichDetails(logPath string, details map[string]string) map[string]string {
	if domains, ok := w.domainMap[logPath]; ok && len(domains) > 0 {
		details["domain"] = strings.Join(domains, ",")
	}
	details["log_file"] = filepath.Base(logPath)
	return details
}

func (w *WebWatcher) processLine(logPath, line string) {
	entry, ok := parseAccessLog(line)

	w.mu.Lock()
	defer w.mu.Unlock()

	// Track parse stats
	stats := w.parseStats[logPath]
	if stats == nil {
		stats = &parseFileStats{}
		w.parseStats[logPath] = stats
	}
	stats.totalLines++

	if !ok {
		stats.failedLines++
		if !stats.warned && stats.totalLines >= 100 {
			rate := float64(stats.failedLines) / float64(stats.totalLines)
			if rate > 0.5 {
				stats.warned = true
				log.Printf("[webwatcher] WARNING: %s — high parse failure rate (%.0f%% of %d lines). Custom log format? Use combined format or set WEB_LOG_PATH to exclude.",
					logPath, rate*100, stats.totalLines)
			}
		}
		return
	}

	ip := entry.ip
	uriLower := strings.ToLower(entry.uri)
	uaLower := strings.ToLower(entry.userAgent)
	refLower := strings.ToLower(entry.referer)

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
				go w.onEvent(ip, rule.eventType, "critical", w.enrichDetails(logPath, map[string]string{
					"uri":        entry.uri,
					"method":     entry.method,
					"user_agent": entry.userAgent,
					"pattern":    pat,
				}))
				return
			}
		}
	}

	// ── Instant-ban: known scanner user-agents ──
	for _, agent := range scannerAgents {
		if strings.Contains(uaLower, agent) {
			w.banned[ip] = true
			go w.onBan(ip, "scanner_detected", 1)
			go w.onEvent(ip, "scanner_detected", "warning", w.enrichDetails(logPath, map[string]string{
				"uri":        entry.uri,
				"user_agent": entry.userAgent,
				"scanner":    agent,
			}))
			return
		}
	}

	// ── Instant-ban: Shellshock (CVE-2014-6271) in Referer or User-Agent ──
	if strings.Contains(refLower, "() {") || strings.Contains(uaLower, "() {") {
		w.banned[ip] = true
		go w.onBan(ip, "shellshock", 1)
		go w.onEvent(ip, "shellshock", "critical", w.enrichDetails(logPath, map[string]string{
			"uri":        entry.uri,
			"user_agent": entry.userAgent,
			"referer":    entry.referer,
		}))
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
			go w.onEvent(ip, ruleWPLogin.eventType, "critical", w.enrichDetails(logPath, map[string]string{
				"uri": entry.uri,
			}))
		}
		return
	}

	// ── Threshold: XMLRPC abuse ──
	if entry.method == "POST" && strings.Contains(uriLower, "xmlrpc.php") {
		if w.checkThreshold(ip, ruleXMLRPC, now) {
			go w.onEvent(ip, ruleXMLRPC.eventType, "warning", w.enrichDetails(logPath, map[string]string{
				"uri": entry.uri,
			}))
		}
		return
	}

	// ── Threshold: plugin scanner ──
	if strings.Contains(uriLower, "wp-content/plugins/") && entry.status == 404 {
		if w.checkThreshold(ip, rulePluginScan, now) {
			go w.onEvent(ip, rulePluginScan.eventType, "info", w.enrichDetails(logPath, map[string]string{
				"uri": entry.uri,
			}))
		}
		return
	}

	// ── Threshold: 404 flood ──
	if entry.status == 404 {
		if w.checkThreshold(ip, rule404Flood, now) {
			go w.onEvent(ip, rule404Flood.eventType, "info", w.enrichDetails(logPath, map[string]string{
				"uri": entry.uri,
			}))
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
