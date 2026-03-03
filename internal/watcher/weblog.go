package watcher

import (
	"context"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"net/url"
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

	// WAF config from panel sync (nil = use defaults)
	wafEnabled    map[string]bool
	wafDetectOnly map[string]bool
	wafThresholds map[string]int

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

	// 4. Docker containers running web servers (always checked — a host may run
	//    both a native web server and additional services inside Docker).
	for _, info := range detectDockerLogInfo() {
		add(info)
	}

	// 5. Well-known static paths as fallback (only if nothing found from config)
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

// nginxBlock holds server_name and access_log directives from a single nginx server{} block.
type nginxBlock struct {
	serverNames []string
	logPaths    []string
}

// detectNginxLogInfo parses nginx config to find ALL access_log paths with their server_names.
func detectNginxLogInfo() []LogPathInfo {
	out, err := exec.Command("nginx", "-T").CombinedOutput()
	if err != nil {
		return nil
	}
	return nginxBlocksToLogPathInfos(parseNginxBlocks(string(out)), nil)
}

// parseNginxBlocks extracts server-block and http-level access_log entries from nginx -T output.
// It does NOT check whether paths exist on disk.
func parseNginxBlocks(output string) []nginxBlock {
	var blocks []nginxBlock
	var current *nginxBlock
	inServer := false
	braceDepth := 0
	serverStartDepth := 0
	globalDepth := 0

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		openBraces := strings.Count(trimmed, "{")
		closeBraces := strings.Count(trimmed, "}")

		prevGlobalDepth := globalDepth
		globalDepth += openBraces - closeBraces

		if !inServer && strings.HasPrefix(trimmed, "server") {
			rest := strings.TrimPrefix(trimmed, "server")
			rest = strings.TrimSpace(rest)
			if rest == "{" || rest == "" || strings.HasPrefix(rest, "{") {
				inServer = true
				current = &nginxBlock{}
				serverStartDepth = prevGlobalDepth
				braceDepth = openBraces - closeBraces
				continue
			}
		}

		if inServer {
			braceDepth += openBraces - closeBraces

			if braceDepth <= 0 {
				if current != nil {
					blocks = append(blocks, *current)
				}
				current = nil
				inServer = false
				continue
			}

			if strings.HasPrefix(trimmed, "server_name ") {
				names := strings.TrimSuffix(strings.TrimPrefix(trimmed, "server_name "), ";")
				for _, n := range strings.Fields(names) {
					n = strings.TrimSpace(n)
					if n != "" && n != "_" {
						current.serverNames = append(current.serverNames, n)
					}
				}
			}

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
			if strings.HasPrefix(trimmed, "access_log ") && globalDepth >= 1 {
				parts := strings.Fields(trimmed)
				if len(parts) >= 2 {
					path := strings.TrimSuffix(parts[1], ";")
					if path != "off" && !strings.HasPrefix(path, "syslog:") && !strings.HasPrefix(path, "|") {
						blocks = append(blocks, nginxBlock{logPaths: []string{path}})
					}
				}
			}
		}

		_ = serverStartDepth
	}

	if current != nil && len(current.logPaths) > 0 {
		blocks = append(blocks, *current)
	}

	return blocks
}

// nginxBlocksToLogPathInfos converts parsed nginx blocks to []LogPathInfo.
// If mountMap is non-nil, container-internal paths are first resolved to host paths via it.
// Only paths that exist on the host filesystem are included.
func nginxBlocksToLogPathInfos(blocks []nginxBlock, mountMap map[string]string) []LogPathInfo {
	pathDomains := make(map[string]map[string]bool)
	for _, block := range blocks {
		for _, lp := range block.logPaths {
			hostPath := lp
			if mountMap != nil {
				hostPath = resolveDockerMount(lp, mountMap)
				if hostPath == "" {
					continue
				}
			}
			if _, err := os.Stat(hostPath); err != nil {
				continue
			}
			if pathDomains[hostPath] == nil {
				pathDomains[hostPath] = make(map[string]bool)
			}
			for _, name := range block.serverNames {
				pathDomains[hostPath][name] = true
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

// ── Docker container log detection ──────────────────────────────────

// detectDockerLogInfo finds web server access logs inside Docker containers.
// For each running nginx/apache/caddy container it:
//  1. Runs `nginx -T` inside the container and maps the log paths to host paths
//     via bind-mount information from `docker inspect`.
//  2. Falls back to scanning all bind-mounted host directories for *access*.log files.
func detectDockerLogInfo() []LogPathInfo {
	if _, err := exec.LookPath("docker"); err != nil {
		return nil
	}

	out, err := exec.Command("docker", "ps",
		"--format", "{{.ID}}|{{.Image}}|{{.Names}}",
		"--filter", "status=running",
	).Output()
	if err != nil || len(strings.TrimSpace(string(out))) == 0 {
		return nil
	}

	webKeywords := []string{"nginx", "apache", "httpd", "caddy", "openresty", "traefik"}
	seen := make(map[string]bool)
	var result []LogPathInfo

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "|", 3)
		if len(parts) < 3 {
			continue
		}
		id, image, name := parts[0], strings.ToLower(parts[1]), parts[2]

		isWeb := false
		for _, kw := range webKeywords {
			if strings.Contains(image, kw) {
				isWeb = true
				break
			}
		}
		if !isWeb {
			continue
		}

		mounts := dockerBindMounts(id)

		// Primary: run nginx -T inside the container to get precise paths + domain names.
		if nginxOut, err := exec.Command("docker", "exec", name, "nginx", "-T").CombinedOutput(); err == nil {
			for _, info := range nginxBlocksToLogPathInfos(parseNginxBlocks(string(nginxOut)), mounts) {
				if !seen[info.Path] {
					seen[info.Path] = true
					result = append(result, info)
					log.Printf("[webwatcher] docker: watching %s from container %s", info.Path, name)
				}
			}
			continue // nginx -T worked; skip the generic fallback below
		}

		// Fallback: scan host-side bind-mount directories for *access*.log files.
		for _, hostDir := range mounts {
			entries, err := os.ReadDir(hostDir)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				lower := strings.ToLower(e.Name())
				if strings.Contains(lower, "access") && strings.HasSuffix(lower, ".log") {
					hostPath := filepath.Join(hostDir, e.Name())
					if !seen[hostPath] {
						seen[hostPath] = true
						result = append(result, LogPathInfo{Path: hostPath})
						log.Printf("[webwatcher] docker: watching %s (mount scan, container %s)", hostPath, name)
					}
				}
			}
		}
	}

	return result
}

// dockerBindMounts returns a containerPath→hostPath map for a container's bind mounts.
func dockerBindMounts(containerID string) map[string]string {
	out, err := exec.Command("docker", "inspect",
		"--format", "{{range .Mounts}}{{if eq .Type \"bind\"}}{{.Destination}}|{{.Source}}\n{{end}}{{end}}",
		containerID,
	).Output()
	if err != nil {
		return nil
	}
	m := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		p := strings.SplitN(line, "|", 2)
		if len(p) == 2 && p[0] != "" && p[1] != "" {
			m[p[0]] = p[1]
		}
	}
	return m
}

// resolveDockerMount translates a container-internal file path to its host bind-mount path.
// Uses longest-prefix matching across the mount table. Returns "" if no mount covers the path.
func resolveDockerMount(containerPath string, mounts map[string]string) string {
	type kv struct{ k, v string }
	pairs := make([]kv, 0, len(mounts))
	for k, v := range mounts {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return len(pairs[i].k) > len(pairs[j].k) // longest prefix first
	})
	for _, p := range pairs {
		if containerPath == p.k || strings.HasPrefix(containerPath, p.k+"/") {
			rel := strings.TrimPrefix(containerPath, p.k)
			return filepath.Join(p.v, rel)
		}
	}
	return ""
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

	// XSS attempts
	{"xss_attempt", []string{
		"<script", "javascript:", "onerror=", "onload=", "document.cookie",
		"<img src=x", "<svg/onload", "onfocus=", "onmouseover=",
		"%3cscript", "data:text/html", "vbscript:",
	}, "xss_attempt"},

	// SSRF attempts
	{"ssrf_attempt", []string{
		"169.254.169.254", "file://", "dict://", "gopher://",
	}, "ssrf_attempt"},

	// Web shell access attempts
	{"web_shell", []string{
		"/c99.php", "/r57.php", "/shell.php", "/webshell",
		"cmd=whoami", "cmd=id", "cmd=ls",
	}, "web_shell"},

	// Known framework/server exploits (CVEs)
	{"web_exploit", []string{
		// Spring4Shell (CVE-2022-22965) — near-zero false positives
		"class.module.classloader",
		// JBoss / WildFly management consoles — never served by a legitimate app
		"/jmx-console/", "/web-console/",
		"/invoker/jmxinvokerservlet", "/invoker/readonly",
		// Apache Tomcat manager (no legitimate public-facing app exposes this)
		"/manager/html", "/manager/text",
		// Apache Struts OGNL injection via redirect prefix
		"redirect:${", "redirect:%24%7b",
		// ThinkPHP RCE (widely exploited in Asia-Pacific traffic)
		"invokefunction&function=call_user_func_array",
		// Drupalgeddon2 (CVE-2018-7600)
		"%23markup%5d", "element_parents%5d",
	}, "web_exploit"},
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
	rule404Flood   = thresholdRule{"404_flood", "404_flood", 15, 5 * time.Minute}
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
	// Double-decode URI to catch double URL-encoded attacks (%252fetc → %2fetc → /etc)
	if decoded, err := url.QueryUnescape(uriLower); err == nil {
		uriLower = decoded
	}
	if decoded, err := url.QueryUnescape(uriLower); err == nil {
		uriLower = decoded
	}
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
		if !w.isTypeEnabled(rule.eventType) {
			continue
		}
		for _, pat := range rule.patterns {
			if strings.Contains(uriLower, pat) {
				if !w.isDetectOnly(rule.eventType) {
					w.banned[ip] = true
					go w.onBan(ip, rule.eventType, 1)
				}
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
	if w.isTypeEnabled("scanner_detected") {
		for _, agent := range scannerAgents {
			if strings.Contains(uaLower, agent) {
				if !w.isDetectOnly("scanner_detected") {
					w.banned[ip] = true
					go w.onBan(ip, "scanner_detected", 1)
				}
				go w.onEvent(ip, "scanner_detected", "warning", w.enrichDetails(logPath, map[string]string{
					"uri":        entry.uri,
					"user_agent": entry.userAgent,
					"scanner":    agent,
				}))
				return
			}
		}
	}

	// ── Instant-ban: Shellshock (CVE-2014-6271) in Referer or User-Agent ──
	if w.isTypeEnabled("shellshock") && (strings.Contains(refLower, "() {") || strings.Contains(uaLower, "() {")) {
		if !w.isDetectOnly("shellshock") {
			w.banned[ip] = true
			go w.onBan(ip, "shellshock", 1)
		}
		go w.onEvent(ip, "shellshock", "critical", w.enrichDetails(logPath, map[string]string{
			"uri":        entry.uri,
			"user_agent": entry.userAgent,
			"referer":    entry.referer,
		}))
		return
	}

	// ── Instant-ban: Header injection in User-Agent or Referer ──
	if w.isTypeEnabled("header_injection") {
		for _, pat := range []string{"\r\n", "%0d%0a", "content-type:", "set-cookie:"} {
			if strings.Contains(uaLower, pat) || strings.Contains(refLower, pat) {
				if !w.isDetectOnly("header_injection") {
					w.banned[ip] = true
					go w.onBan(ip, "header_injection", 1)
				}
				go w.onEvent(ip, "header_injection", "warning", w.enrichDetails(logPath, map[string]string{
					"uri":        entry.uri,
					"user_agent": entry.userAgent,
					"referer":    entry.referer,
					"pattern":    pat,
				}))
				return
			}
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
		if w.isTypeEnabled("wp_bruteforce") {
			rule := thresholdRule{ruleWPLogin.key, ruleWPLogin.eventType, w.wafThreshold("wp_bruteforce", ruleWPLogin.threshold), ruleWPLogin.window}
			if w.checkThreshold(ip, rule, now, w.isDetectOnly("wp_bruteforce")) {
				go w.onEvent(ip, ruleWPLogin.eventType, "critical", w.enrichDetails(logPath, map[string]string{
					"uri": entry.uri,
				}))
			}
		}
		return
	}

	// ── Threshold: XMLRPC abuse ──
	if entry.method == "POST" && strings.Contains(uriLower, "xmlrpc.php") {
		if w.isTypeEnabled("xmlrpc_abuse") {
			rule := thresholdRule{ruleXMLRPC.key, ruleXMLRPC.eventType, w.wafThreshold("xmlrpc_abuse", ruleXMLRPC.threshold), ruleXMLRPC.window}
			if w.checkThreshold(ip, rule, now, w.isDetectOnly("xmlrpc_abuse")) {
				go w.onEvent(ip, ruleXMLRPC.eventType, "warning", w.enrichDetails(logPath, map[string]string{
					"uri": entry.uri,
				}))
			}
		}
		return
	}

	// ── Threshold: plugin scanner ──
	if strings.Contains(uriLower, "wp-content/plugins/") && entry.status == 404 {
		if w.isTypeEnabled("scanner_detected") {
			rule := thresholdRule{rulePluginScan.key, rulePluginScan.eventType, w.wafThreshold("scanner_detected", rulePluginScan.threshold), rulePluginScan.window}
			if w.checkThreshold(ip, rule, now, w.isDetectOnly("scanner_detected")) {
				go w.onEvent(ip, rulePluginScan.eventType, "info", w.enrichDetails(logPath, map[string]string{
					"uri": entry.uri,
				}))
			}
		}
		return
	}

	// ── Threshold: 404 flood ──
	if entry.status == 404 {
		if w.isTypeEnabled("404_flood") {
			rule := thresholdRule{rule404Flood.key, rule404Flood.eventType, w.wafThreshold("404_flood", rule404Flood.threshold), rule404Flood.window}
			if w.checkThreshold(ip, rule, now, w.isDetectOnly("404_flood")) {
				go w.onEvent(ip, rule404Flood.eventType, "info", w.enrichDetails(logPath, map[string]string{
					"uri": entry.uri,
				}))
			}
		}
		return
	}
}

// checkThreshold increments the counter for a rule+IP and bans if threshold exceeded.
// If detectOnly is true, tracks the attempt but does not ban.
// Returns true if the threshold was crossed. Caller must hold w.mu.
func (w *WebWatcher) checkThreshold(ip string, rule thresholdRule, now time.Time, detectOnly bool) bool {
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
		if !detectOnly {
			w.banned[ip] = true
			count := len(recent)
			go w.onBan(ip, rule.eventType, count)
		}
		return true
	}
	return false
}

// ── WAF Configuration ───────────────────────────────────────────────

// WAFConfig holds the per-server WAF settings received from the panel sync.
type WAFConfig struct {
	EnabledTypes    []string       `json:"enabled_types"`
	DetectOnlyTypes []string       `json:"detect_only_types"`
	Thresholds      map[string]int `json:"thresholds"`
}

// UpdateWAFConfig applies WAF configuration from the panel.
// Pass nil to reset all settings to defaults (all types enabled, hardcoded thresholds).
func (w *WebWatcher) UpdateWAFConfig(cfg *WAFConfig) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if cfg == nil {
		w.wafEnabled = nil
		w.wafDetectOnly = nil
		w.wafThresholds = nil
		return
	}

	if len(cfg.EnabledTypes) > 0 {
		m := make(map[string]bool, len(cfg.EnabledTypes))
		for _, t := range cfg.EnabledTypes {
			m[t] = true
		}
		w.wafEnabled = m
	} else {
		w.wafEnabled = nil
	}

	if len(cfg.DetectOnlyTypes) > 0 {
		m := make(map[string]bool, len(cfg.DetectOnlyTypes))
		for _, t := range cfg.DetectOnlyTypes {
			m[t] = true
		}
		w.wafDetectOnly = m
	} else {
		w.wafDetectOnly = nil
	}

	if len(cfg.Thresholds) > 0 {
		w.wafThresholds = cfg.Thresholds
	} else {
		w.wafThresholds = nil
	}
}

// isTypeEnabled returns true if this attack type should be processed.
// Must be called with w.mu held.
func (w *WebWatcher) isTypeEnabled(eventType string) bool {
	if w.wafEnabled == nil {
		return true
	}
	return w.wafEnabled[eventType]
}

// isDetectOnly returns true if the type should only record an event, not ban.
// Must be called with w.mu held.
func (w *WebWatcher) isDetectOnly(eventType string) bool {
	if w.wafDetectOnly == nil {
		return false
	}
	return w.wafDetectOnly[eventType]
}

// wafThreshold returns the configured threshold for a rule, falling back to the default.
// Must be called with w.mu held.
func (w *WebWatcher) wafThreshold(key string, defaultVal int) int {
	if w.wafThresholds == nil {
		return defaultVal
	}
	if v, ok := w.wafThresholds[key]; ok && v > 0 {
		return v
	}
	return defaultVal
}
