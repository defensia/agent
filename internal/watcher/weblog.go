package watcher

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// WafRuleEntry is the agent-side representation of a dynamic WAF rule from the panel.
type WafRuleEntry struct {
	ID       int64  `json:"id"`
	Category string `json:"category"`
	Pattern  string `json:"pattern"`
	Target   string `json:"target"` // "uri", "ua", "referer", "honeypot"
}

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
	onBanTimed BanWithDurationFunc
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
	wafThresholds   map[string]int
	wafScorePoints  map[string]int

	// Dynamic WAF rules from panel (nil = use hardcoded defaults)
	wafDynURIRules  []dynPatternGroup // replaces instantBanPatterns for URI
	wafDynUARules   []string          // replaces scannerAgents for UA
	wafDynHoneypots []string          // replaces honeypotPaths

	// Hot-reload: active goroutines with cancel functions
	activePaths map[string]context.CancelFunc

	// Docker log reader processes
	dockerCmds []*exec.Cmd

	// Bot score tracker (score-based ban decisions)
	scorer *BotScoreTracker
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

	// 5. cPanel/CloudLinux per-vhost logs in domlogs directory (always checked).
	// Files are named by domain (e.g. domain.com, domain.com-ssl_log) with no
	// standard extension. The main access_log is already covered below.
	for _, info := range detectCpanelDomlogInfo() {
		add(info)
	}

	// 6. Well-known static paths as fallback (only if nothing found from config)
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
//
// When server blocks inherit a global access_log (i.e. they have server_name but no
// access_log directive), their domains are associated with the global log path.
func nginxBlocksToLogPathInfos(blocks []nginxBlock, mountMap map[string]string) []LogPathInfo {
	pathDomains := make(map[string]map[string]bool)

	// Collect global log paths (blocks with logPaths but no serverNames)
	// and orphan domains (blocks with serverNames but no logPaths).
	var globalLogPaths []string
	var orphanDomains []string

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
			// Track global log paths (from http-level, no server_name)
			if len(block.serverNames) == 0 {
				globalLogPaths = append(globalLogPaths, hostPath)
			}
		}
		// Server blocks that inherit access_log from http level
		if len(block.logPaths) == 0 && len(block.serverNames) > 0 {
			orphanDomains = append(orphanDomains, block.serverNames...)
		}
	}

	// Associate orphan domains with global log paths.
	// This handles the common case: access_log at http{} level + server blocks with only server_name.
	if len(orphanDomains) > 0 && len(globalLogPaths) > 0 {
		// Dedup global log paths
		seen := make(map[string]bool)
		for _, gp := range globalLogPaths {
			if !seen[gp] {
				seen[gp] = true
				if pathDomains[gp] == nil {
					pathDomains[gp] = make(map[string]bool)
				}
				for _, d := range orphanDomains {
					pathDomains[gp][d] = true
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
	// cPanel installs Apache at a non-standard path not in $PATH
	if !apacheInstalled {
		if _, err := os.Stat("/usr/local/apache/bin/apachectl"); err == nil {
			apacheInstalled = true
		}
	}
	if !apacheInstalled {
		return nil
	}

	// Detect ServerRoot from main config (CentOS: /etc/httpd, Debian: /etc/apache2)
	serverRoot := ""
	mainConfigs := []string{
		"/etc/httpd/conf/httpd.conf",
		"/etc/apache2/apache2.conf",
		"/usr/local/apache/conf/httpd.conf",
	}
	for _, mc := range mainConfigs {
		if data, err := os.ReadFile(mc); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "#") {
					continue
				}
				if strings.HasPrefix(strings.ToLower(trimmed), "serverroot ") {
					parts := strings.Fields(trimmed)
					if len(parts) >= 2 {
						serverRoot = strings.Trim(parts[1], "\"")
					}
				}
			}
			if serverRoot != "" {
				break
			}
		}
	}

	configFiles := make([]string, len(mainConfigs))
	copy(configFiles, mainConfigs)

	// Debian/Ubuntu vhost patterns
	vhostGlobs := []string{
		"/etc/apache2/sites-enabled/*.conf",
		"/etc/apache2/conf-enabled/*.conf",
		// CentOS/RHEL vhost patterns
		"/etc/httpd/conf.d/*.conf",
		"/etc/httpd/conf.modules.d/*.conf",
	}
	for _, pattern := range vhostGlobs {
		if matches, _ := filepath.Glob(pattern); matches != nil {
			configFiles = append(configFiles, matches...)
		}
	}

	// Also try apachectl -S to discover included config files
	// Include cPanel's non-standard binary path
	for _, cmd := range []string{"apachectl", "apache2ctl", "httpd", "/usr/local/apache/bin/apachectl"} {
		if out, err := exec.Command(cmd, "-S").CombinedOutput(); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				// Lines like: port 80 namevhost domain.com (/etc/httpd/conf.d/vhost.conf:1)
				if idx := strings.Index(line, "("); idx != -1 {
					if end := strings.Index(line[idx:], ":"); end != -1 {
						cf := line[idx+1 : idx+end]
						if _, err := os.Stat(cf); err == nil {
							configFiles = append(configFiles, cf)
						}
					}
				}
			}
			break
		}
	}

	// Dedup config files
	cfSeen := make(map[string]bool)
	var uniqueConfigFiles []string
	for _, cf := range configFiles {
		if !cfSeen[cf] {
			cfSeen[cf] = true
			uniqueConfigFiles = append(uniqueConfigFiles, cf)
		}
	}

	pathDomains := make(map[string]map[string]bool)

	for _, cf := range uniqueConfigFiles {
		data, err := os.ReadFile(cf)
		if err != nil {
			continue
		}
		for _, vhost := range parseApacheVhosts(string(data)) {
			for _, lp := range vhost.logPaths {
				lp = resolveApacheEnvVars(lp)
				// Resolve relative paths using ServerRoot (CentOS: "logs/access_log" → "/etc/httpd/logs/access_log")
				if !filepath.IsAbs(lp) && serverRoot != "" {
					lp = filepath.Join(serverRoot, lp)
				}
				// Follow symlinks (CentOS: /etc/httpd/logs → /var/log/httpd)
				if resolved, err := filepath.EvalSymlinks(lp); err == nil {
					lp = resolved
				}
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

	// Well-known RHEL/CentOS log paths as extra fallback when Apache is installed
	// but config parsing found nothing (e.g. piped logs only, or unusual config)
	if len(pathDomains) == 0 {
		rhelPaths := []string{
			"/var/log/httpd/access_log",
			"/var/log/httpd/ssl_access_log",
			"/var/log/httpd/access.log",
			"/var/log/apache2/access.log",
			"/var/log/apache2/other_vhosts_access.log",
		}
		for _, p := range rhelPaths {
			if _, err := os.Stat(p); err == nil {
				pathDomains[p] = make(map[string]bool)
				log.Printf("[webwatcher] apache: found well-known log path %s", p)
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
			// Outside VirtualHost — capture global CustomLog (case-insensitive)
			if strings.HasPrefix(lower, "customlog ") {
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
		// CustomLog — case-insensitive match
		if strings.HasPrefix(lower, "customlog ") {
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

// detectCpanelDomlogInfo scans cPanel's per-vhost access log directory.
// cPanel stores per-domain Apache logs in /usr/local/apache/logs/domlogs/
// as plain files named by domain (e.g. "domain.com", "domain.com-ssl_log").
func detectCpanelDomlogInfo() []LogPathInfo {
	domlogDir := "/usr/local/apache/logs/domlogs"
	entries, err := os.ReadDir(domlogDir)
	if err != nil {
		return nil
	}
	var infos []LogPathInfo
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Skip byte-log variants (bandwidth tracking, not access logs)
		if strings.HasSuffix(name, "-bytes_log") {
			continue
		}
		p := domlogDir + "/" + name
		// Extract domain name: strip -ssl_log suffix if present
		domain := strings.TrimSuffix(name, "-ssl_log")
		infos = append(infos, LogPathInfo{Path: p, Domains: []string{domain}})
	}
	if len(infos) > 0 {
		log.Printf("[webwatcher] cPanel domlogs: found %d log files in %s", len(infos), domlogDir)
	}
	return infos
}

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
		"--format", "{{.ID}}|{{.Image}}|{{.Names}}|{{.Ports}}",
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
		ports := ""
		if len(parts) >= 4 {
			ports = parts[3]
		}

		isWeb := false
		for _, kw := range webKeywords {
			if strings.Contains(image, kw) {
				isWeb = true
				break
			}
		}

		// Check exposed ports as heuristic — match container port (->80/tcp) not host port
		if !isWeb && ports != "" {
			for _, webPort := range []string{"->80/", "->443/", "->8080/", "->8000/"} {
				if strings.Contains(ports, webPort) {
					isWeb = true
					break
				}
			}
		}

		// Check docker-compose service label
		if !isWeb {
			if svc := dockerComposeService(id); svc != "" {
				svcLower := strings.ToLower(svc)
				for _, kw := range append(webKeywords, "web", "proxy", "frontend") {
					if strings.Contains(svcLower, kw) {
						isWeb = true
						break
					}
				}
			}
		}

		if !isWeb {
			continue
		}

		mounts := dockerMounts(id)
		foundLogs := false

		// Primary: run nginx -T inside the container to get precise paths + domain names.
		if nginxOut, err := exec.Command("docker", "exec", name, "nginx", "-T").CombinedOutput(); err == nil {
			for _, info := range nginxBlocksToLogPathInfos(parseNginxBlocks(string(nginxOut)), mounts) {
				if !seen[info.Path] {
					seen[info.Path] = true
					result = append(result, info)
					foundLogs = true
					log.Printf("[webwatcher] docker: watching %s from container %s", info.Path, name)
				}
			}
		}

		// Fallback: scan host-side mount directories for *access*.log files.
		if !foundLogs {
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
							foundLogs = true
							log.Printf("[webwatcher] docker: watching %s (mount scan, container %s)", hostPath, name)
						}
					}
				}
			}
		}

		// Stdout fallback: container logs to stdout (e.g. default Docker nginx)
		if !foundLogs {
			if isDockerStdoutAccessLog(name) {
				dockerPath := "docker://" + name
				if !seen[dockerPath] {
					// Try to get domains from nginx config inside the container
					var domains []string
					if nginxOut, err := exec.Command("docker", "exec", name, "nginx", "-T").CombinedOutput(); err == nil {
						blocks := parseNginxBlocks(string(nginxOut))
						for _, b := range blocks {
							domains = append(domains, b.serverNames...)
						}
					}
					seen[dockerPath] = true
					result = append(result, LogPathInfo{Path: dockerPath, Domains: domains})
					log.Printf("[webwatcher] docker: watching stdout from container %s (domains: %v)", name, domains)
				}
			}
		}
	}

	return result
}

// dockerComposeService returns the docker-compose service name for a container, or "".
func dockerComposeService(containerID string) string {
	out, err := exec.Command("docker", "inspect",
		"--format", "{{index .Config.Labels \"com.docker.compose.service\"}}",
		containerID,
	).Output()
	if err != nil {
		return ""
	}
	svc := strings.TrimSpace(string(out))
	if svc == "<no value>" || svc == "" {
		return ""
	}
	return svc
}

// isDockerStdoutAccessLog checks if a container's stdout looks like an access log (combined/common format).
func isDockerStdoutAccessLog(containerName string) bool {
	out, err := exec.Command("docker", "logs", "--tail", "5", containerName).CombinedOutput()
	if err != nil || len(out) == 0 {
		return false
	}
	// Check if any line looks like combined/common log format: IP - - [date] "METHOD ..."
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if len(line) < 20 {
			continue
		}
		// Basic heuristic: starts with IP-like pattern and contains HTTP method
		if (line[0] >= '0' && line[0] <= '9') &&
			strings.Contains(line, " - ") &&
			(strings.Contains(line, "\"GET ") || strings.Contains(line, "\"POST ") ||
				strings.Contains(line, "\"HEAD ") || strings.Contains(line, "\"PUT ") ||
				strings.Contains(line, "\"OPTIONS ")) {
			return true
		}
	}
	return false
}

// dockerMounts returns a containerPath→hostPath map for a container's bind mounts AND volume mounts.
func dockerMounts(containerID string) map[string]string {
	out, err := exec.Command("docker", "inspect",
		"--format", "{{range .Mounts}}{{.Destination}}|{{.Source}}\n{{end}}",
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
		scorer:      NewBotScoreTracker(),
	}
}

// SetBanTimed sets a callback for bans with a specific duration.
func (w *WebWatcher) SetBanTimed(fn BanWithDurationFunc) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.onBanTimed = fn
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

	// Start a goroutine per log source
	for _, p := range w.logPaths {
		if strings.HasPrefix(p, "docker://") {
			containerName := strings.TrimPrefix(p, "docker://")
			w.startDockerLogReader(p, containerName)
		} else {
			w.startTailGoroutine(p)
		}
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

// startDockerLogReader launches a goroutine that reads access logs from a Docker container's stdout.
func (w *WebWatcher) startDockerLogReader(logPath, containerName string) {
	w.mu.Lock()
	if _, exists := w.activePaths[logPath]; exists {
		w.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.activePaths[logPath] = cancel
	w.mu.Unlock()

	go func() {
		defer func() {
			w.mu.Lock()
			delete(w.activePaths, logPath)
			w.mu.Unlock()
		}()

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			cmd := exec.CommandContext(ctx, "docker", "logs", "-f", "--since", time.Now().Format(time.RFC3339), "--tail", "0", containerName)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				log.Printf("[webwatcher] docker logs pipe error for %s: %v — retrying in 10s", containerName, err)
				time.Sleep(10 * time.Second)
				continue
			}

			if err := cmd.Start(); err != nil {
				log.Printf("[webwatcher] docker logs start error for %s: %v — retrying in 10s", containerName, err)
				time.Sleep(10 * time.Second)
				continue
			}

			w.mu.Lock()
			w.dockerCmds = append(w.dockerCmds, cmd)
			w.mu.Unlock()

			log.Printf("[webwatcher] docker: reading stdout from container %s", containerName)

			scanner := bufio.NewScanner(stdout)
			scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)
			for scanner.Scan() {
				line := scanner.Text()
				w.mu.Lock()
				w.processLine(logPath, line)
				w.mu.Unlock()
			}

			_ = cmd.Wait()

			if ctx.Err() != nil {
				return
			}
			log.Printf("[webwatcher] docker logs stream ended for %s — retrying in 5s", containerName)
			time.Sleep(5 * time.Second)
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
			if strings.HasPrefix(path, "docker://") {
				w.startDockerLogReader(path, strings.TrimPrefix(path, "docker://"))
			} else {
				w.startTailGoroutine(path)
			}
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

		// Decay and cleanup bot scores (no new goroutine needed)
		if w.scorer != nil {
			w.scorer.DecayAndCleanup()
		}
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

// ── Honeypot paths ──────────────────────────────────────────────────

// honeypotPaths are fake paths that no legitimate user visits. Any request to these
// is a strong scanner signal with zero false positives.
var honeypotPaths = []string{
	"/.aws/credentials",
	"/backup.sql",
	"/db_backup.sql",
	"/phpmyadmin/setup/",
	"/.docker/config.json",
	"/actuator/env",
	"/api/debug",
	"/_debug/default/view",
	"/telescope/requests",
	"/elmah.axd",
	"/server-info",
	"/cgi-bin/test",
}

// ── Score points per detection ──────────────────────────────────────

var scorePoints = map[string]int{
	"sql_injection":      40,
	"rce_attempt":        50,
	"web_shell":          50,
	"ssrf_attempt":       40,
	"path_traversal":     30,
	"xss_attempt":        25,
	"web_exploit":        40,
	"shellshock":         50,
	"header_injection":   30,
	"scanner_ua":         50,
	"env_probe":          25,
	"config_probe":       20,
	"honeypot_triggered": 40,
	"wp_bruteforce":      30,
	"xmlrpc_abuse":       25,
	"scanner_detected":   20,
	"404_flood":          15,
}

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
	whitelisted := w.isWhitelisted(ip)

	// Geoblocking callback (skip for whitelisted IPs)
	if !whitelisted && w.checkIP != nil {
		if reason := w.checkIP(ip); reason != "" {
			w.banned[ip] = true
			go w.onBan(ip, reason, 1)
			return
		}
	}

	// ── Honeypot paths (checked before instant-ban, after whitelist) ──
	if w.isTypeEnabled("honeypot_triggered") {
		for _, hp := range w.getHoneypotPatterns() {
			if strings.Contains(uriLower, hp) {
				w.handleDetection(ip, "honeypot_triggered", whitelisted, logPath, line, map[string]string{
					"uri":        entry.uri,
					"method":     entry.method,
					"user_agent": entry.userAgent,
					"pattern":    hp,
				})
				return
			}
		}
	}

	// ── Instant-detection: URI patterns ──
	for _, rule := range w.getURIPatterns() {
		if !w.isTypeEnabled(rule.EventType) {
			continue
		}
		for _, pat := range rule.Patterns {
			if strings.Contains(uriLower, pat) {
				w.handleDetection(ip, rule.EventType, whitelisted, logPath, line, map[string]string{
					"uri":        entry.uri,
					"method":     entry.method,
					"user_agent": entry.userAgent,
					"pattern":    pat,
				})
				return
			}
		}
	}

	// ── Detection: known scanner user-agents ──
	if w.isTypeEnabled("scanner_detected") {
		for _, agent := range w.getUAPatterns() {
			if strings.Contains(uaLower, agent) {
				w.handleDetection(ip, "scanner_ua", whitelisted, logPath, line, map[string]string{
					"uri":        entry.uri,
					"user_agent": entry.userAgent,
					"scanner":    agent,
				})
				return
			}
		}
	}

	// ── Detection: Shellshock (CVE-2014-6271) in Referer or User-Agent ──
	if w.isTypeEnabled("shellshock") && (strings.Contains(refLower, "() {") || strings.Contains(uaLower, "() {")) {
		w.handleDetection(ip, "shellshock", whitelisted, logPath, line, map[string]string{
			"uri":        entry.uri,
			"user_agent": entry.userAgent,
			"referer":    entry.referer,
		})
		return
	}

	// ── Detection: Header injection in User-Agent or Referer ──
	if w.isTypeEnabled("header_injection") {
		for _, pat := range []string{"\r\n", "%0d%0a", "content-type:", "set-cookie:"} {
			if strings.Contains(uaLower, pat) || strings.Contains(refLower, pat) {
				w.handleDetection(ip, "header_injection", whitelisted, logPath, line, map[string]string{
					"uri":        entry.uri,
					"user_agent": entry.userAgent,
					"referer":    entry.referer,
					"pattern":    pat,
				})
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
			if w.checkThresholdScored(ip, rule, now, whitelisted || w.isDetectOnly("wp_bruteforce"), logPath, line, map[string]string{
				"uri": entry.uri,
			}) {
				return
			}
		}
		return
	}

	// ── Threshold: XMLRPC abuse ──
	if entry.method == "POST" && strings.Contains(uriLower, "xmlrpc.php") {
		if w.isTypeEnabled("xmlrpc_abuse") {
			rule := thresholdRule{ruleXMLRPC.key, ruleXMLRPC.eventType, w.wafThreshold("xmlrpc_abuse", ruleXMLRPC.threshold), ruleXMLRPC.window}
			if w.checkThresholdScored(ip, rule, now, whitelisted || w.isDetectOnly("xmlrpc_abuse"), logPath, line, map[string]string{
				"uri": entry.uri,
			}) {
				return
			}
		}
		return
	}

	// ── Threshold: plugin scanner ──
	if strings.Contains(uriLower, "wp-content/plugins/") && entry.status == 404 {
		if w.isTypeEnabled("scanner_detected") {
			rule := thresholdRule{rulePluginScan.key, rulePluginScan.eventType, w.wafThreshold("scanner_detected", rulePluginScan.threshold), rulePluginScan.window}
			if w.checkThresholdScored(ip, rule, now, whitelisted || w.isDetectOnly("scanner_detected"), logPath, line, map[string]string{
				"uri": entry.uri,
			}) {
				return
			}
		}
		return
	}

	// ── Threshold: 404 flood ──
	if entry.status == 404 {
		if w.isTypeEnabled("404_flood") {
			rule := thresholdRule{rule404Flood.key, rule404Flood.eventType, w.wafThreshold("404_flood", rule404Flood.threshold), rule404Flood.window}
			if w.checkThresholdScored(ip, rule, now, whitelisted || w.isDetectOnly("404_flood"), logPath, line, map[string]string{
				"uri": entry.uri,
			}) {
				return
			}
		}
		return
	}
}

// handleDetection processes a single detection through the bot scoring engine.
// It adds score, determines the action, and either bans or just logs the event.
// Caller must hold w.mu. The scorer has its own lock so we release w.mu briefly.
func (w *WebWatcher) handleDetection(ip, eventType string, whitelisted bool, logPath, rawLine string, details map[string]string) {
	detectOnly := w.isDetectOnly(eventType)

	// Get score points for this detection type
	points := 0
	if w.wafScorePoints != nil {
		points = w.wafScorePoints[eventType]
	}
	if points == 0 {
		points = scorePoints[eventType]
	}
	if points == 0 {
		points = 20 // default fallback
	}

	// Release w.mu to call scorer (which has its own lock)
	w.mu.Unlock()
	score, category := w.scorer.AddScore(ip, eventType, points)
	action := ActionForScore(score)
	w.mu.Lock()

	// Re-check banned status after re-acquiring lock
	if w.banned[ip] {
		return
	}

	// Determine severity based on score action
	severity := SeverityForAction(action)

	// Enrich details with bot score info
	enriched := w.enrichDetails(logPath, rawLine, details)
	EnrichBotDetails(enriched, score, category, action)

	// Map scanner_ua event type to scanner_detected for API compatibility
	apiEventType := eventType
	if eventType == "scanner_ua" {
		apiEventType = "scanner_detected"
	}

	// Apply ban based on score (not individual detection)
	if !whitelisted && !detectOnly {
		switch action {
		case "block":
			w.banned[ip] = true
			if w.onBanTimed != nil {
				go w.onBanTimed(ip, apiEventType, 1, 1*time.Hour)
			} else {
				go w.onBan(ip, apiEventType, 1)
			}
		case "blacklist":
			w.banned[ip] = true
			if w.onBanTimed != nil {
				go w.onBanTimed(ip, apiEventType, 1, 24*time.Hour)
			} else {
				go w.onBan(ip, apiEventType, 1)
			}
		}
	}

	go w.onEvent(ip, apiEventType, severity, enriched)
}

// checkThresholdScored increments the counter for a rule+IP and, when the threshold
// is crossed, feeds the detection into the bot scoring engine for score-based banning.
// Returns true if the threshold was crossed. Caller must hold w.mu.
func (w *WebWatcher) checkThresholdScored(ip string, rule thresholdRule, now time.Time, detectOnly bool, logPath, rawLine string, details map[string]string) bool {
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
		// Threshold crossed — feed into scoring engine
		w.handleDetection(ip, rule.eventType, detectOnly, logPath, rawLine, details)
		return true
	}
	return false
}

// ── Dynamic WAF Rules ────────────────────────────────────────────────

// dynPatternGroup groups patterns by event type (mirrors instantBanPatterns structure).
type dynPatternGroup struct {
	Name      string   `json:"name"`
	Patterns  []string `json:"patterns"`
	EventType string   `json:"event_type"`
}

const wafRulesCachePath = "/etc/defensia/waf_rules.json"

// dynWafRulesCache is the on-disk format for persisting rules across restarts.
type dynWafRulesCache struct {
	URIRules  []dynPatternGroup `json:"uri_rules"`
	UARules   []string          `json:"ua_rules"`
	Honeypots []string          `json:"honeypots"`
}

// UpdateWAFRules applies dynamic WAF rules received from the panel sync.
// When rules is empty, falls back to hardcoded defaults.
// Persists the rule set to disk so it survives agent restarts without panel connectivity.
func (w *WebWatcher) UpdateWAFRules(rules []WafRuleEntry) {
	if len(rules) == 0 {
		return // keep existing dynamic rules (or hardcoded defaults if none loaded yet)
	}

	// Group rules by target
	uriMap := make(map[string]*dynPatternGroup)
	var uaPatterns []string
	var honeypots []string

	for _, r := range rules {
		switch r.Target {
		case "uri":
			if _, ok := uriMap[r.Category]; !ok {
				uriMap[r.Category] = &dynPatternGroup{
					Name:      r.Category,
					EventType: r.Category,
				}
			}
			uriMap[r.Category].Patterns = append(uriMap[r.Category].Patterns, r.Pattern)
		case "ua":
			uaPatterns = append(uaPatterns, r.Pattern)
		case "honeypot":
			honeypots = append(honeypots, r.Pattern)
		}
	}

	var uriRules []dynPatternGroup
	for _, g := range uriMap {
		uriRules = append(uriRules, *g)
	}

	w.mu.Lock()
	w.wafDynURIRules = uriRules
	w.wafDynUARules = uaPatterns
	w.wafDynHoneypots = honeypots
	w.mu.Unlock()

	// Persist to disk cache (best-effort, do not block)
	go func() {
		cache := dynWafRulesCache{
			URIRules:  uriRules,
			UARules:   uaPatterns,
			Honeypots: honeypots,
		}
		data, err := json.Marshal(cache)
		if err != nil {
			return
		}
		if err := os.MkdirAll(filepath.Dir(wafRulesCachePath), 0o750); err != nil {
			return
		}
		_ = os.WriteFile(wafRulesCachePath, data, 0o600)
	}()

	log.Printf("[webwatcher] dynamic WAF rules loaded: %d URI groups, %d UA patterns, %d honeypots",
		len(uriRules), len(uaPatterns), len(honeypots))
}

// LoadWAFRulesCache restores dynamic rules from disk (called at startup before first sync).
func (w *WebWatcher) LoadWAFRulesCache() {
	data, err := os.ReadFile(wafRulesCachePath)
	if err != nil {
		return // no cache yet, use hardcoded defaults
	}
	var cache dynWafRulesCache
	if err := json.Unmarshal(data, &cache); err != nil {
		log.Printf("[webwatcher] waf_rules cache corrupt, ignoring: %v", err)
		return
	}
	if len(cache.URIRules) == 0 && len(cache.UARules) == 0 {
		return
	}
	w.mu.Lock()
	w.wafDynURIRules = cache.URIRules
	w.wafDynUARules = cache.UARules
	w.wafDynHoneypots = cache.Honeypots
	w.mu.Unlock()
	log.Printf("[webwatcher] restored WAF rules from cache: %d URI groups, %d UA patterns, %d honeypots",
		len(cache.URIRules), len(cache.UARules), len(cache.Honeypots))
}

// getURIPatterns returns the active URI instant-ban pattern groups.
// Uses dynamic rules from panel when available, otherwise falls back to hardcoded.
// Must be called with w.mu held.
func (w *WebWatcher) getURIPatterns() []dynPatternGroup {
	if w.wafDynURIRules != nil {
		return w.wafDynURIRules
	}
	// Convert hardcoded instantBanPatterns to []dynPatternGroup
	result := make([]dynPatternGroup, len(instantBanPatterns))
	for i, p := range instantBanPatterns {
		result[i] = dynPatternGroup{Name: p.name, Patterns: p.patterns, EventType: p.eventType}
	}
	return result
}

// getUAPatterns returns the active scanner user-agent patterns.
// Must be called with w.mu held.
func (w *WebWatcher) getUAPatterns() []string {
	if w.wafDynUARules != nil {
		return w.wafDynUARules
	}
	return scannerAgents
}

// getHoneypotPatterns returns the active honeypot paths.
// Must be called with w.mu held.
func (w *WebWatcher) getHoneypotPatterns() []string {
	if w.wafDynHoneypots != nil {
		return w.wafDynHoneypots
	}
	return honeypotPaths
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
		w.wafEnabled = nil
		w.wafDetectOnly = nil
		w.wafThresholds = nil
		w.wafScorePoints = nil
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

	if len(cfg.ScorePoints) > 0 {
		w.wafScorePoints = cfg.ScorePoints
	} else {
		w.wafScorePoints = nil
	}
}

// isTypeEnabled returns true if this attack type should be processed.
// When wafEnabled is nil (no config from panel yet), WAF is disabled by default.
// Must be called with w.mu held.
func (w *WebWatcher) isTypeEnabled(eventType string) bool {
	if w.wafEnabled == nil {
		return false
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
