package watcher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

// compiledBot holds a pre-compiled bot fingerprint for fast matching.
type compiledBot struct {
	Slug     string
	Name     string
	Category string
	Action   string // allow, log, block
	Pattern  string // original pattern (used for plain substring match)
	IsRegex  bool
	Re       *regexp.Regexp // non-nil only when IsRegex is true
}

// compiledWafRule is a dynamic WAF rule loaded from the panel (virtual patching).
type compiledWafRule struct {
	ID       int64
	Category string         // eventType to emit (sql_injection, rce_attempt, etc.)
	Target   string         // "uri" | "ua" | "referer"
	Pattern  string         // original pattern for substring match
	IsRegex  bool
	Re       *regexp.Regexp // non-nil only when IsRegex is true
}

// ScoredBanFunc is called when an IP's score crosses a ban threshold.
// duration is the ban length (1h for block, 24h for blacklist).
type ScoredBanFunc func(ip, reason string, score int, duration time.Duration)

// defaultScorePoints are the fallback score weights when the panel hasn't configured them.
var defaultScorePoints = map[string]int{
	"rce_attempt":        50,
	"web_shell":          50,
	"shellshock":         50,
	"scanner_detected":   50,
	"sql_injection":      40,
	"ssrf_attempt":       40,
	"web_exploit":        40,
	"honeypot_triggered": 40,
	"path_traversal":     30,
	"header_injection":   30,
	"wp_bruteforce":      30,
	"xss_attempt":        25,
	"env_probe":          25,
	"xmlrpc_abuse":       25,
	"config_probe":       20,
	"404_flood":          15,
}

// WebWatcher tails web server access logs and bans IPs that match attack patterns.
type WebWatcher struct {
	logPaths  []string
	domainMap map[string][]string // logPath → domain names
	onBan     BanFunc
	onEvent   EventFunc
	onScoredBan ScoredBanFunc
	checkIP   CheckIPFunc

	mu        sync.Mutex
	banned    map[string]bool
	whitelist map[string]bool
	wlNets    []*net.IPNet

	// Per-rule attempt tracking: ruleKey:ip → timestamps
	attempts map[string][]time.Time

	// Per-IP WAF score tracking (cumulative scoring engine)
	scorer *BotScoreTracker
	// Track highest ban action per IP to avoid re-banning
	scoredActions map[string]string // ip → highest action taken ("block" or "blacklist")
	// Dedup: avoid scoring the same detection twice from multiple log files
	recentScores map[string]time.Time // "ip:eventType" → last scored time

	// Parse failure tracking per log file
	parseStats map[string]*parseFileStats

	// Counter: total requests analyzed since last heartbeat read
	requestsAnalyzed uint64

	// WAF config from panel sync (nil = use defaults)
	wafEnabled    map[string]bool
	wafDetectOnly map[string]bool
	wafThresholds map[string]int
	wafScorePoints map[string]int  // per-type score weights from panel
	monitorMode   bool // when true, all event types are detect-only

	// Bot fingerprints from panel sync
	botFingerprints []compiledBot

	// WAF rules (virtual patches) from panel sync
	dynamicWafRules []compiledWafRule

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

	// 5. Well-known static paths (always checked — add() deduplicates)
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
		log.Printf("[webwatcher] nginx -T failed: %v (output: %.200s)", err, string(out))
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

var nginxPrefix string
var nginxPrefixOnce sync.Once

func getNginxPrefix() string {
	nginxPrefixOnce.Do(func() {
		out, err := exec.Command("nginx", "-V").CombinedOutput()
		if err != nil {
			return
		}
		re := regexp.MustCompile(`--prefix=(\S+)`)
		if m := re.FindSubmatch(out); len(m) > 1 {
			nginxPrefix = string(m[1])
		}
	})
	return nginxPrefix
}

func resolveNginxRelativePath(relPath string) string {
	var candidates []string
	if prefix := getNginxPrefix(); prefix != "" {
		candidates = append(candidates, filepath.Join(prefix, relPath))
	}
	candidates = append(candidates,
		filepath.Join("/etc/nginx", relPath),
		filepath.Join("/usr/local/nginx", relPath),
		filepath.Join("/opt/nginx", relPath),
		filepath.Join("/usr/share/nginx", relPath),
	)
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
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
			if !filepath.IsAbs(hostPath) {
				resolved := resolveNginxRelativePath(hostPath)
				if resolved == "" {
					continue
				}
				hostPath = resolved
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

// resolveApacheEnvVars expands ${APACHE_LOG_DIR} in a path by parsing /etc/apache2/envvars.
func resolveApacheEnvVars(path string) string {
	if !strings.Contains(path, "${") && !strings.Contains(path, "$APACHE") {
		return path
	}

	logDir := ""
	for _, envFile := range []string{"/etc/apache2/envvars", "/etc/sysconfig/httpd"} {
		data, err := os.ReadFile(envFile)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			line = strings.TrimPrefix(line, "export ")
			if strings.HasPrefix(line, "APACHE_LOG_DIR=") {
				val := strings.TrimPrefix(line, "APACHE_LOG_DIR=")
				val = strings.Trim(val, "\"'")
				// Handle ${var:-default} syntax
				if strings.Contains(val, ":-") {
					if idx := strings.Index(val, ":-"); idx >= 0 {
						end := strings.Index(val[idx:], "}")
						if end > 0 {
							val = val[idx+2 : idx+end]
						}
					}
				}
				if val != "" && !strings.Contains(val, "$") {
					logDir = val
				}
			}
		}
		if logDir != "" {
			break
		}
	}

	if logDir == "" {
		for _, candidate := range []string{"/var/log/apache2", "/var/log/httpd"} {
			if fi, err := os.Stat(candidate); err == nil && fi.IsDir() {
				logDir = candidate
				break
			}
		}
	}

	if logDir == "" {
		return path
	}

	path = strings.ReplaceAll(path, "${APACHE_LOG_DIR}", logDir)
	path = strings.ReplaceAll(path, "$APACHE_LOG_DIR", logDir)
	return path
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
	confFiles, _ := filepath.Glob("/etc/apache2/conf-enabled/*.conf")
	configFiles = append(configFiles, confFiles...)

	pathDomains := make(map[string]map[string]bool)

	for _, cf := range configFiles {
		data, err := os.ReadFile(cf)
		if err != nil {
			continue
		}
		for _, vhost := range parseApacheVhosts(string(data)) {
			for _, lp := range vhost.logPaths {
				lp = resolveApacheEnvVars(lp)
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
// Containers are selected for monitoring if they match one of:
//  1. Image name contains a web keyword (nginx, apache, httpd, caddy, openresty, traefik)
//  2. Label `defensia.monitor=true` is present (overrides image detection)
//
// Log path resolution order:
//  1. Label `defensia.log-path` — explicit host path(s), comma-separated
//  2. `docker exec nginx -T` — parses nginx config for log directives
//  3. Fallback: scan bind-mounted directories for *access*.log files
//
// Supported labels:
//
//	defensia.monitor=true     — force-monitor this container (even if not a web image)
//	defensia.monitor=false    — skip this container (even if it matches a web image)
//	defensia.log-path=/path   — explicit host log path(s), comma-separated
//	defensia.waf=true         — (informational) reported in heartbeat, WAF config comes from panel
//	defensia.domain=example   — associate domain(s) with this container's logs, comma-separated
func detectDockerLogInfo() []LogPathInfo {
	if _, err := exec.LookPath("docker"); err != nil {
		return nil
	}

	out, err := exec.Command("docker", "ps",
		"--format", "{{.ID}}|{{.Image}}|{{.Names}}|{{.Labels}}",
		"--filter", "status=running",
	).Output()
	if err != nil || len(strings.TrimSpace(string(out))) == 0 {
		return nil
	}

	webKeywords := []string{"nginx", "apache", "httpd", "caddy", "openresty", "traefik"}
	seen := make(map[string]bool)
	var result []LogPathInfo

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "|", 4)
		if len(parts) < 3 {
			continue
		}
		id, image, name := parts[0], strings.ToLower(parts[1]), parts[2]
		rawLabels := ""
		if len(parts) >= 4 {
			rawLabels = parts[3]
		}

		labels := parseDockerLabels(rawLabels)

		// Label-based override: defensia.monitor=false skips, =true forces
		if v, ok := labels["defensia.monitor"]; ok {
			if v == "false" || v == "0" || v == "no" {
				continue
			}
		}

		// Determine if this is a web container
		isWeb := false
		if v, ok := labels["defensia.monitor"]; ok && (v == "true" || v == "1" || v == "yes") {
			isWeb = true
			log.Printf("[webwatcher] docker: container %s selected via defensia.monitor label", name)
		}
		if !isWeb {
			for _, kw := range webKeywords {
				if strings.Contains(image, kw) {
					isWeb = true
					break
				}
			}
		}
		if !isWeb {
			continue
		}

		// Label: defensia.domain — explicit domain association
		var labelDomains []string
		if d, ok := labels["defensia.domain"]; ok && d != "" {
			for _, dom := range strings.Split(d, ",") {
				dom = strings.TrimSpace(dom)
				if dom != "" {
					labelDomains = append(labelDomains, dom)
				}
			}
		}

		// Label: defensia.log-path — explicit host path(s), highest priority
		if lp, ok := labels["defensia.log-path"]; ok && lp != "" {
			for _, p := range strings.Split(lp, ",") {
				p = strings.TrimSpace(p)
				if p != "" && !seen[p] {
					seen[p] = true
					result = append(result, LogPathInfo{Path: p, Domains: labelDomains})
					log.Printf("[webwatcher] docker: watching %s from container %s (defensia.log-path label)", p, name)
				}
			}
			continue // explicit path set — skip auto-detection
		}

		mounts := dockerBindMounts(id)

		// Primary: run nginx -T inside the container to get precise paths + domain names.
		if nginxOut, err := exec.Command("docker", "exec", name, "nginx", "-T").CombinedOutput(); err == nil {
			for _, info := range nginxBlocksToLogPathInfos(parseNginxBlocks(string(nginxOut)), mounts) {
				if !seen[info.Path] {
					seen[info.Path] = true
					if len(labelDomains) > 0 {
						info.Domains = append(info.Domains, labelDomains...)
					}
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
						result = append(result, LogPathInfo{Path: hostPath, Domains: labelDomains})
						log.Printf("[webwatcher] docker: watching %s (mount scan, container %s)", hostPath, name)
					}
				}
			}
		}
	}

	return result
}

// parseDockerLabels parses the comma-separated key=value label string from `docker ps --format {{.Labels}}`.
func parseDockerLabels(raw string) map[string]string {
	labels := make(map[string]string)
	if raw == "" {
		return labels
	}
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if eq := strings.IndexByte(pair, '='); eq > 0 {
			labels[pair[:eq]] = pair[eq+1:]
		}
	}
	return labels
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
		logPaths:      paths,
		domainMap:     domainMap,
		onBan:         onBan,
		onEvent:       onEvent,
		attempts:      make(map[string][]time.Time),
		banned:        make(map[string]bool),
		whitelist:     make(map[string]bool),
		scorer:        NewBotScoreTracker(),
		scoredActions: make(map[string]string),
		recentScores:  make(map[string]time.Time),
		parseStats:    make(map[string]*parseFileStats),
		activePaths:   make(map[string]context.CancelFunc),
	}
}

// SetOnScoredBan sets a callback for score-based bans (with duration).
// RequestsAnalyzed returns and resets the request counter since last call.
func (w *WebWatcher) RequestsAnalyzed() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	count := w.requestsAnalyzed
	w.requestsAnalyzed = 0
	return count
}

func (w *WebWatcher) SetOnScoredBan(fn ScoredBanFunc) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.onScoredBan = fn
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
		log.Printf("[webwatcher] no web server logs found — WAF disabled")
		log.Printf("[webwatcher] hint: if your web server runs in Docker, mount the log directory to the host:")
		log.Printf("[webwatcher]   volumes:")
		log.Printf("[webwatcher]     - /var/log/nginx:/var/log/nginx")
		log.Printf("[webwatcher] hint: or set WEB_LOG_PATH=/path/to/access.log in the systemd unit")
		// Report to the panel so users can see the issue without SSH access.
		go w.onEvent("0.0.0.0", "waf_disabled", "warning", map[string]string{
			"reason": "no_web_logs_found",
			"hint":   "Mount your container log directory to the host (e.g. /var/log/nginx:/var/log/nginx) or set WEB_LOG_PATH in the agent systemd unit",
		})
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
// Also handles containerd/CRI-O log prefix: "2026-01-01T00:00:00.000Z stdout F <actual log line>"
func parseAccessLog(line string) (accessLogEntry, bool) {
	var e accessLogEntry

	// Strip containerd/CRI-O log prefix (K8s container logs)
	// Format: "2006-01-02T15:04:05.999999999Z stdout F <line>"
	if len(line) > 36 && line[4] == '-' && line[10] == 'T' {
		if idx := strings.Index(line, " stdout F "); idx > 0 && idx < 40 {
			line = line[idx+10:]
		} else if idx := strings.Index(line, " stderr F "); idx > 0 && idx < 40 {
			line = line[idx+10:]
		}
	}

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

// enrichDetails adds domain, log_file, and raw log line to event details.
func (w *WebWatcher) enrichDetails(logPath, rawLine string, details map[string]string) map[string]string {
	if domains, ok := w.domainMap[logPath]; ok && len(domains) > 0 {
		details["domain"] = strings.Join(domains, ",")
	}
	details["log_file"] = filepath.Base(logPath)
	if len(rawLine) > 2000 {
		rawLine = rawLine[:2000]
	}
	details["raw_line"] = rawLine
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
	w.requestsAnalyzed++

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

	// Skip private/reserved IPs (Docker bridge, localhost, etc.)
	if isPrivateIP(ip) {
		return
	}

	uriRaw := strings.ToLower(entry.uri)
	// Double-decode URI to catch double URL-encoded attacks (%252fetc → %2fetc → /etc)
	uriLower := uriRaw
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

	// ── Score-based detection: path traversal, SQL injection, etc. ──
	// Each match adds points to the IP's cumulative score. Action depends on total score.
	for _, rule := range instantBanPatterns {
		if !w.isTypeEnabled(rule.eventType) {
			continue
		}
		for _, pat := range rule.patterns {
			if strings.Contains(uriLower, pat) || strings.Contains(uriRaw, pat) {
				w.addScore(ip, rule.eventType, logPath, line, map[string]string{
					"uri":        entry.uri,
					"method":     entry.method,
					"user_agent": entry.userAgent,
					"pattern":    pat,
				})
				return
			}
		}
	}

	// ── Dynamic WAF rules (virtual patches from panel) ──
	for i := range w.dynamicWafRules {
		rule := &w.dynamicWafRules[i]
		if !w.isTypeEnabled(rule.Category) {
			continue
		}
		var haystack string
		switch rule.Target {
		case "ua":
			haystack = uaLower
		case "referer":
			haystack = refLower
		default: // "uri"
			haystack = uriLower
		}
		matched := false
		if rule.IsRegex && rule.Re != nil {
			matched = rule.Re.MatchString(haystack)
		} else {
			matched = strings.Contains(haystack, rule.Pattern)
		}
		if matched {
			w.addScore(ip, rule.Category, logPath, line, map[string]string{
				"uri":        entry.uri,
				"method":     entry.method,
				"user_agent": entry.userAgent,
				"waf_rule":   fmt.Sprintf("%d", rule.ID),
				"target":     rule.Target,
				"pattern":    rule.Pattern,
			})
			return
		}
	}

	// ── Score-based: known scanner user-agents ──
	if w.isTypeEnabled("scanner_detected") {
		for _, agent := range scannerAgents {
			if strings.Contains(uaLower, agent) {
				w.addScore(ip, "scanner_detected", logPath, line, map[string]string{
					"uri":        entry.uri,
					"user_agent": entry.userAgent,
					"scanner":    agent,
				})
				return
			}
		}
	}

	// ── Bot fingerprint matching (outside scoring — has its own allow/log/block) ──
	for i := range w.botFingerprints {
		bot := &w.botFingerprints[i]
		matched := false
		if bot.IsRegex && bot.Re != nil {
			matched = bot.Re.MatchString(entry.userAgent)
		} else {
			matched = strings.Contains(uaLower, strings.ToLower(bot.Pattern))
		}
		if matched {
			details := w.enrichDetails(logPath, line, map[string]string{
				"uri":          entry.uri,
				"user_agent":   entry.userAgent,
				"bot_slug":     bot.Slug,
				"bot_name":     bot.Name,
				"bot_category": bot.Category,
				"bot_action":   bot.Action,
			})
			if bot.Action == "block" && !w.monitorMode {
				w.banned[ip] = true
				go w.onBan(ip, "bot_blocked", 1)
				go w.onEvent(ip, "bot_detected", "warning", details)
			} else if bot.Action == "log" || (bot.Action == "block" && w.monitorMode) {
				go w.onEvent(ip, "bot_detected", "info", details)
			} else {
				// allow — log as crawl (lower noise)
				go w.onEvent(ip, "bot_crawl", "info", details)
			}
			return
		}
	}

	// ── Unknown bot detection ──────────────────────────────────
	// If UA looks like a bot but matched no fingerprint, emit bot_unknown
	if w.isTypeEnabled("bot_unknown") {
		uaPatterns := []string{"bot", "crawler", "spider", "scraper", "fetch", "python-requests", "python-urllib", "go-http-client", "java/", "curl/", "wget/", "libwww", "httpx", "axios/", "ruby", "perl/", "php/"}
		for _, pat := range uaPatterns {
			if strings.Contains(uaLower, pat) {
				go w.onEvent(ip, "bot_unknown", "info", w.enrichDetails(logPath, line, map[string]string{
					"uri":        entry.uri,
					"user_agent": entry.userAgent,
				}))
				break
			}
		}
	}

	// ── Score-based: Shellshock (CVE-2014-6271) ──
	if w.isTypeEnabled("shellshock") && (strings.Contains(refLower, "() {") || strings.Contains(uaLower, "() {")) {
		w.addScore(ip, "shellshock", logPath, line, map[string]string{
			"uri":        entry.uri,
			"user_agent": entry.userAgent,
			"referer":    entry.referer,
		})
		return
	}

	// ── Score-based: Header injection ──
	if w.isTypeEnabled("header_injection") {
		for _, pat := range []string{"\r\n", "%0d%0a", "content-type:", "set-cookie:"} {
			if strings.Contains(uaLower, pat) || strings.Contains(refLower, pat) {
				w.addScore(ip, "header_injection", logPath, line, map[string]string{
					"uri":        entry.uri,
					"user_agent": entry.userAgent,
					"referer":    entry.referer,
					"pattern":    pat,
				})
				return
			}
		}
	}

	// ── Pre-filter: only process threshold-based rules for suspicious/4xx requests ──
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
		return
	}

	now := time.Now()

	// ── Threshold → score: WP Login brute force ──
	if entry.method == "POST" && strings.Contains(uriLower, "wp-login.php") && entry.status != 302 {
		if w.isTypeEnabled("wp_bruteforce") {
			rule := thresholdRule{ruleWPLogin.key, ruleWPLogin.eventType, w.wafThreshold("wp_bruteforce", ruleWPLogin.threshold), ruleWPLogin.window}
			if w.checkThresholdOnly(ip, rule, now) {
				w.addScore(ip, "wp_bruteforce", logPath, line, map[string]string{
					"uri": entry.uri,
				})
			}
		}
		return
	}

	// ── Threshold → score: XMLRPC abuse ──
	if entry.method == "POST" && strings.Contains(uriLower, "xmlrpc.php") {
		if w.isTypeEnabled("xmlrpc_abuse") {
			rule := thresholdRule{ruleXMLRPC.key, ruleXMLRPC.eventType, w.wafThreshold("xmlrpc_abuse", ruleXMLRPC.threshold), ruleXMLRPC.window}
			if w.checkThresholdOnly(ip, rule, now) {
				w.addScore(ip, "xmlrpc_abuse", logPath, line, map[string]string{
					"uri": entry.uri,
				})
			}
		}
		return
	}

	// ── Threshold → score: plugin scanner ──
	if strings.Contains(uriLower, "wp-content/plugins/") && entry.status == 404 {
		if w.isTypeEnabled("scanner_detected") {
			rule := thresholdRule{rulePluginScan.key, rulePluginScan.eventType, w.wafThreshold("scanner_detected", rulePluginScan.threshold), rulePluginScan.window}
			if w.checkThresholdOnly(ip, rule, now) {
				w.addScore(ip, "scanner_detected", logPath, line, map[string]string{
					"uri": entry.uri,
				})
			}
		}
		return
	}

	// ── Threshold → score: 404 flood ──
	if entry.status == 404 {
		if w.isTypeEnabled("404_flood") {
			rule := thresholdRule{rule404Flood.key, rule404Flood.eventType, w.wafThreshold("404_flood", rule404Flood.threshold), rule404Flood.window}
			if w.checkThresholdOnly(ip, rule, now) {
				w.addScore(ip, "404_flood", logPath, line, map[string]string{
					"uri": entry.uri,
				})
			}
		}
		return
	}
}

// checkThresholdOnly increments the counter for a rule+IP and returns true if
// the threshold was crossed. Does NOT ban — the caller should use addScore instead.
// Resets the counter after triggering so it can fire again. Caller must hold w.mu.
func (w *WebWatcher) checkThresholdOnly(ip string, rule thresholdRule, now time.Time) bool {
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
		// Reset counter so it can fire again for sustained attacks
		w.attempts[key] = nil
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
	ScorePoints     map[string]int `json:"score_points"`
}

// UpdateWAFConfig applies WAF configuration from the panel.
// Pass nil to reset all settings to defaults (all types enabled, hardcoded thresholds).
func (w *WebWatcher) UpdateWAFConfig(cfg *WAFConfig) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if cfg == nil {
		log.Println("[webwatcher] WAF config reset to defaults — all types enabled")
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
		log.Printf("[webwatcher] WAF config applied: %d enabled types, %d detect-only, %d thresholds", len(cfg.EnabledTypes), len(cfg.DetectOnlyTypes), len(cfg.Thresholds))
	} else {
		w.wafEnabled = nil
		log.Println("[webwatcher] WAF config: no types specified — all types enabled by default")
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

	if len(cfg.ScorePoints) > 0 {
		w.wafScorePoints = cfg.ScorePoints
	} else {
		w.wafScorePoints = nil
	}
}

// isTypeEnabled returns true if this attack type should be processed.
// When wafEnabled is nil (no explicit config from panel), all types are enabled by default.
// Must be called with w.mu held.
func (w *WebWatcher) isTypeEnabled(eventType string) bool {
	if w.wafEnabled == nil {
		return true
	}
	return w.wafEnabled[eventType]
}

// SetMonitorMode enables or disables monitor-only mode. When enabled, all WAF
// event types are treated as detect-only — events are recorded but no bans issued.
func (w *WebWatcher) SetMonitorMode(enabled bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.monitorMode = enabled
	log.Printf("[webwatcher] monitor mode: %v", enabled)
}

// isDetectOnly returns true if the type should only record an event, not ban.
// Must be called with w.mu held.
func (w *WebWatcher) isDetectOnly(eventType string) bool {
	if w.monitorMode {
		return true
	}
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

// ── IP Scoring Engine ───────────────────────────────────────────────

// getScorePoints returns the configured points for a detection type.
// Falls back to defaultScorePoints, then 0. Must be called with w.mu held.
func (w *WebWatcher) getScorePoints(eventType string) int {
	if w.wafScorePoints != nil {
		if v, ok := w.wafScorePoints[eventType]; ok {
			return v
		}
	}
	if v, ok := defaultScorePoints[eventType]; ok {
		return v
	}
	return 0
}

// addScore adds points to an IP's cumulative score and takes the appropriate action.
// Must be called with w.mu held. Uses BotScoreTracker (has its own mutex, so we
// release w.mu before calling it, then re-acquire).
func (w *WebWatcher) addScore(ip, eventType, logPath, line string, details map[string]string) {
	points := w.getScorePoints(eventType)
	if points == 0 {
		return
	}

	// Dedup: skip if we scored this IP+type within the last 2 seconds
	// (same request logged in multiple access log files)
	dedupKey := ip + ":" + eventType
	now := time.Now()
	if last, ok := w.recentScores[dedupKey]; ok && now.Sub(last) < 2*time.Second {
		return
	}
	w.recentScores[dedupKey] = now

	// Release w.mu before calling scorer (which has its own lock)
	w.mu.Unlock()
	score, category := w.scorer.AddScore(ip, eventType, points)
	w.mu.Lock()

	action := ActionForScore(score)
	severity := SeverityForAction(action)

	details["waf_score"] = strconv.Itoa(score)
	details["waf_action"] = action
	details["waf_category"] = category
	details = w.enrichDetails(logPath, line, details)

	// Always report the event when score reaches observe level (30+)
	if score >= thresholdObserve {
		go w.onEvent(ip, eventType, severity, details)
	}

	// Monitor mode: never ban, just observe everything
	if w.monitorMode {
		return
	}

	// Ban actions: only escalate, never downgrade
	prevAction := w.scoredActions[ip]
	if action == "block" && prevAction != "block" && prevAction != "blacklist" {
		w.scoredActions[ip] = "block"
		w.banned[ip] = true
		if w.onScoredBan != nil {
			go w.onScoredBan(ip, eventType, score, 1*time.Hour)
		}
	} else if action == "blacklist" && prevAction != "blacklist" {
		w.scoredActions[ip] = "blacklist"
		w.banned[ip] = true
		if w.onScoredBan != nil {
			go w.onScoredBan(ip, eventType, score, 24*time.Hour)
		}
	}
}

// CleanExpiredScores removes expired IP scores and resets ban state for re-evaluation.
// Should be called periodically (e.g. every 5 minutes).
func (w *WebWatcher) CleanExpiredScores() {
	w.scorer.DecayAndCleanup()

	w.mu.Lock()
	defer w.mu.Unlock()
	// Reset scored actions for IPs whose scores have been cleaned up
	for ip := range w.scoredActions {
		if s, _ := w.scorer.GetScore(ip); s == 0 {
			delete(w.scoredActions, ip)
			delete(w.banned, ip)
		}
	}
	// Clean old dedup entries
	now := time.Now()
	for k, t := range w.recentScores {
		if now.Sub(t) > 10*time.Second {
			delete(w.recentScores, k)
		}
	}
}

// ── Bot Fingerprint Configuration ───────────────────────────────────

// BotFingerprintInput matches the JSON structure from the panel sync.
type BotFingerprintInput struct {
	Slug     string `json:"slug"`
	Name     string `json:"name"`
	Pattern  string `json:"ua_pattern"`
	IsRegex  bool   `json:"is_regex"`
	Category string `json:"category"`
	Action   string `json:"action"`
}

// UpdateBotFingerprints compiles and stores bot fingerprint rules from the panel.
// Also persists the raw inputs to /etc/defensia/bot_fingerprints.json for cache reload on restart.
func (w *WebWatcher) UpdateBotFingerprints(fps []BotFingerprintInput) {
	w.mu.Lock()
	defer w.mu.Unlock()

	bots := make([]compiledBot, 0, len(fps))
	for _, fp := range fps {
		cb := compiledBot{
			Slug:     fp.Slug,
			Name:     fp.Name,
			Category: fp.Category,
			Action:   fp.Action,
			Pattern:  fp.Pattern,
			IsRegex:  fp.IsRegex,
		}
		if fp.IsRegex {
			re, err := regexp.Compile("(?i)" + fp.Pattern)
			if err != nil {
				log.Printf("[webwatcher] invalid bot regex %q (%s): %v", fp.Pattern, fp.Slug, err)
				continue
			}
			cb.Re = re
		}
		bots = append(bots, cb)
	}
	w.botFingerprints = bots
	log.Printf("[webwatcher] loaded %d bot fingerprints", len(bots))

	// Persist to cache so fingerprints survive agent restarts
	const cachePath = "/etc/defensia/bot_fingerprints.json"
	if data, err := json.Marshal(fps); err == nil {
		if err := os.MkdirAll("/etc/defensia", 0755); err == nil {
			if err := os.WriteFile(cachePath, data, 0600); err != nil {
				log.Printf("[webwatcher] failed to save bot fingerprints cache: %v", err)
			}
		}
	}
}

// LoadBotFingerprintsCache loads bot fingerprints from the on-disk cache written by
// UpdateBotFingerprints. Should be called once at startup before the first sync.
func (w *WebWatcher) LoadBotFingerprintsCache() {
	const cachePath = "/etc/defensia/bot_fingerprints.json"
	data, err := os.ReadFile(cachePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[webwatcher] failed to read bot fingerprints cache: %v", err)
		}
		return
	}
	var fps []BotFingerprintInput
	if err := json.Unmarshal(data, &fps); err != nil {
		log.Printf("[webwatcher] failed to parse bot fingerprints cache: %v", err)
		return
	}
	log.Printf("[webwatcher] loaded %d bot fingerprints from cache", len(fps))
	w.UpdateBotFingerprints(fps)
}

// ── Dynamic WAF Rules (Virtual Patching) ────────────────────────────

// WafRuleInput matches the JSON structure from the panel sync.
type WafRuleInput struct {
	ID       int64  `json:"id"`
	Category string `json:"category"`
	Pattern  string `json:"pattern"`
	Target   string `json:"target"`
	IsRegex  bool   `json:"is_regex"`
}

// UpdateWafRules compiles and stores dynamic WAF rules from the panel.
// Also persists the raw inputs to /etc/defensia/waf_rules.json for cache reload on restart.
func (w *WebWatcher) UpdateWafRules(rules []WafRuleInput) {
	w.mu.Lock()
	defer w.mu.Unlock()

	compiled := make([]compiledWafRule, 0, len(rules))
	for _, r := range rules {
		target := r.Target
		if target == "" {
			target = "uri"
		}
		cr := compiledWafRule{
			ID:       r.ID,
			Category: r.Category,
			Target:   target,
			Pattern:  strings.ToLower(r.Pattern),
			IsRegex:  r.IsRegex,
		}
		if r.IsRegex {
			re, err := regexp.Compile("(?i)" + r.Pattern)
			if err != nil {
				log.Printf("[webwatcher] invalid WAF rule regex %q (id=%d): %v", r.Pattern, r.ID, err)
				continue
			}
			cr.Re = re
		}
		compiled = append(compiled, cr)
	}
	w.dynamicWafRules = compiled
	log.Printf("[webwatcher] loaded %d dynamic WAF rules", len(compiled))

	const cachePath = "/etc/defensia/waf_rules.json"
	if data, err := json.Marshal(rules); err == nil {
		if err := os.MkdirAll("/etc/defensia", 0755); err == nil {
			if err := os.WriteFile(cachePath, data, 0600); err != nil {
				log.Printf("[webwatcher] failed to save WAF rules cache: %v", err)
			}
		}
	}
}

// LoadWafRulesCache loads dynamic WAF rules from the on-disk cache written by
// UpdateWafRules. Should be called once at startup before the first sync.
func (w *WebWatcher) LoadWafRulesCache() {
	const cachePath = "/etc/defensia/waf_rules.json"
	data, err := os.ReadFile(cachePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[webwatcher] failed to read WAF rules cache: %v", err)
		}
		return
	}
	var rules []WafRuleInput
	if err := json.Unmarshal(data, &rules); err != nil {
		log.Printf("[webwatcher] failed to parse WAF rules cache: %v", err)
		return
	}
	log.Printf("[webwatcher] loaded %d dynamic WAF rules from cache", len(rules))
	w.UpdateWafRules(rules)
}
