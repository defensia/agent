package main

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/defensia/agent/internal/api"
	"github.com/defensia/agent/internal/collector"
	"github.com/defensia/agent/internal/config"
	"github.com/defensia/agent/internal/firewall"
	"github.com/defensia/agent/internal/geoip"
	"github.com/defensia/agent/internal/monitor"
	"github.com/defensia/agent/internal/remediation"
	"github.com/defensia/agent/internal/scanner"
	"github.com/defensia/agent/internal/updater"
	"github.com/defensia/agent/internal/watcher"
	"github.com/defensia/agent/internal/ws"
)

var version = "0.9.29"

var (
	monitorConfigMu sync.RWMutex
	monitorCfg      *api.MonitorConfig
	whitelistIPs    []string
	whitelistMu     sync.RWMutex
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "register":
		if len(os.Args) < 5 {
			fmt.Fprintf(os.Stderr, "usage: defensia-agent register <server_url> <agent_name> <install_token>\n")
			os.Exit(1)
		}
		runRegister(os.Args[2], os.Args[3], os.Args[4])

	case "start":
		runAgent()

	case "check":
		// Pre-flight self-test used by the auto-updater to verify the binary
		// works before restarting the service. Exits 0 on success.
		fmt.Printf("defensia-agent v%s OK\n", version)
		os.Exit(0)

	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  defensia-agent register <server_url> <agent_name> <install_token>")
	fmt.Println("  defensia-agent start")
	fmt.Println("  defensia-agent check")
}

// runRegister performs first-boot registration and saves the config.
func runRegister(serverURL, name, installToken string) {
	hostname, _ := os.Hostname()
	osInfo := detectOS()

	client := api.New(serverURL, "")

	log.Printf("Registering agent '%s' at %s...", name, serverURL)

	resp, err := client.Register(api.RegisterRequest{
		InstallToken: installToken,
		Name:         name,
		Hostname:     hostname,
		IPAddress:    detectOutboundIP(),
		OS:           osInfo.name,
		OSVersion:    osInfo.version,
		Version:      version,
	})
	if err != nil {
		log.Fatalf("Registration failed: %v", err)
	}

	cfg := &config.Config{
		ServerURL:    serverURL,
		AgentToken:   resp.Token,
		AgentID:      resp.Agent.ID,
		ReverbURL:    resp.Reverb.URL,
		ReverbAppKey: resp.Reverb.AppKey,
		AuthEndpoint: resp.Reverb.AuthEndpoint,
	}

	if err := config.Save(cfg); err != nil {
		log.Fatalf("Failed to save config: %v", err)
	}

	log.Printf("Agent registered successfully (id=%d)", resp.Agent.ID)
	log.Printf("Config saved to %s", os.Getenv("DEFENSIA_CONFIG"))
	log.Println("Run 'defensia-agent start' to begin monitoring.")
}

// runAgent is the main loop.
func runAgent() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v\nRun 'defensia-agent register' first.", err)
	}

	apiClient := api.New(cfg.ServerURL, cfg.AgentToken)

	// Callback for the updater to report update outcomes to the server
	reportUpdateEvent := func(eventType, severity string, details map[string]string) {
		_ = apiClient.ReportEvents([]api.EventRequest{{
			Type:       eventType,
			Severity:   severity,
			Details:    details,
			OccurredAt: time.Now().UTC().Format(time.RFC3339),
		}})
	}

	log.Printf("Starting Defensia agent v%s (agent_id=%d)", version, cfg.AgentID)

	// Remove any leftover staging files from a previous interrupted update/rollback.
	updater.CleanupStagingFiles()

	// Protect the API server IP from being banned (would cut off agent comms)
	if u, err := url.Parse(cfg.ServerURL); err == nil {
		host := u.Hostname()
		if ips, err := net.LookupHost(host); err == nil {
			firewall.AddProtectedIPs(ips...)
		} else {
			log.Printf("[main] warning: could not resolve API host %s: %v", host, err)
		}
	}

	// Initialize GeoIP lookup
	geoDBPath := os.Getenv("GEOIP_DB_PATH")
	geo := geoip.New(geoDBPath)
	defer geo.Close()

	// Start auth.log watcher
	w := watcher.New(func(ip, reason string, count int) {
		log.Printf("[watcher] banning %s: %s (count=%d)", ip, reason, count)

		if err := firewall.BanIP(ip); err != nil {
			log.Printf("[firewall] error: %v", err)
		}

		if err := apiClient.ReportBan(api.BanRequest{
			IPAddress: ip,
			Reason:    reason,
			BanCount:  count,
		}); err != nil {
			log.Printf("[api] failed to report ban: %v", err)
		}
	})

	// Set geoblocking check on watcher
	w.SetCheckIP(func(ip string) string {
		cc, blocked := geo.IsBlocked(ip)
		if blocked {
			return fmt.Sprintf("geoblock_%s", strings.ToLower(cc))
		}
		return ""
	})

	// Start web log watcher (if web server access logs found)
	var webW *watcher.WebWatcher
	var monitoredDomains []string
	var monitoredLogPaths []string
	if webLogInfos, domainMap := watcher.DetectWebLogInfo(); len(webLogInfos) > 0 {
		webLogPaths := make([]string, len(webLogInfos))
		for i, info := range webLogInfos {
			webLogPaths[i] = info.Path
		}
		monitoredLogPaths = webLogPaths
		domainSet := make(map[string]bool)
		for _, domains := range domainMap {
			for _, d := range domains {
				domainSet[d] = true
			}
		}
		for d := range domainSet {
			monitoredDomains = append(monitoredDomains, d)
		}
		sort.Strings(monitoredDomains)
		log.Printf("[webwatcher] detected %d access log(s), %d domain(s)", len(webLogPaths), len(monitoredDomains))
		webW = watcher.NewWebWatcher(
			webLogPaths,
			domainMap,
			func(ip, reason string, count int) {
				log.Printf("[webwatcher] banning %s: %s (count=%d)", ip, reason, count)
				if err := firewall.BanIP(ip); err != nil {
					log.Printf("[firewall] error: %v", err)
				}
				if err := apiClient.ReportBan(api.BanRequest{
					IPAddress: ip,
					Reason:    reason,
					BanCount:  count,
				}); err != nil {
					log.Printf("[api] failed to report ban: %v", err)
				}
			},
			func(ip, eventType, severity string, details map[string]string) {
				apiClient.ReportEvents([]api.EventRequest{{
					Type:       eventType,
					Severity:   severity,
					SourceIP:   ip,
					Details:    details,
					OccurredAt: time.Now().UTC().Format(time.RFC3339),
				}})
			},
		)
		webW.SetCheckIP(func(ip string) string {
			cc, blocked := geo.IsBlocked(ip)
			if blocked {
				return fmt.Sprintf("geoblock_%s", strings.ToLower(cc))
			}
			return ""
		})
		webW.SetBanTimed(func(ip, reason string, count int, duration time.Duration) {
			log.Printf("[webwatcher] banning %s: %s (count=%d, duration=%s)", ip, reason, count, duration)
			if err := firewall.BanIP(ip); err != nil {
				log.Printf("[firewall] error: %v", err)
			}
			expiresAt := time.Now().UTC().Add(duration).Format(time.RFC3339)
			if err := apiClient.ReportBan(api.BanRequest{
				IPAddress: ip,
				Reason:    reason,
				BanCount:  count,
				ExpiresAt: &expiresAt,
			}); err != nil {
				log.Printf("[api] failed to report ban: %v", err)
			}
		})
	} else {
		log.Printf("[webwatcher] no access logs found — web attack detection disabled (set WEB_LOG_PATH to override)")
	}

	// Initial sync (applies config, whitelists, rules, bans)
	if err := syncAndApply(apiClient, w, webW, geo, reportUpdateEvent); err != nil {
		log.Printf("[sync] initial sync failed: %v", err)
	}

	// Import existing iptables rules on first startup
	go importExistingRules(apiClient)

	go w.Run()
	if webW != nil {
		go webW.Run()
	}

	// Start Reverb WebSocket listener
	wsClient := ws.New(
		cfg.ReverbURL,
		cfg.ReverbAppKey,
		cfg.AuthEndpoint,
		cfg.AgentToken,
		cfg.AgentID,
		ws.Handlers{
			OnBanCreated: func(p ws.BanCreatedPayload) {
				log.Printf("[reverb] ban.created: %s", p.IPAddress)
				if err := firewall.BanIP(p.IPAddress); err != nil {
					log.Printf("[firewall] error: %v", err)
				}
			},
			OnBanRemoved: func(p ws.BanRemovedPayload) {
				log.Printf("[reverb] ban.removed: %s", p.IPAddress)
				if err := firewall.UnbanIP(p.IPAddress); err != nil {
					log.Printf("[firewall] error: %v", err)
				}
			},
			OnRuleCreated: func(p ws.RuleCreatedPayload) {
				log.Printf("[reverb] rule.created: id=%d type=%s", p.ID, p.Type)
				applyAndAckRule(apiClient, api.Rule{
					ID:        p.ID,
					Type:      p.Type,
					Protocol:  p.Protocol,
					IPAddress: p.IPAddress,
					IPRange:   p.IPRange,
					Port:      p.Port,
					Status:    p.Status,
				})
			},
			OnRuleRemoved: func(p ws.RuleRemovedPayload) {
				log.Printf("[reverb] rule.removed: id=%d", p.ID)
			},
			OnScanRequested: func(p ws.ScanRequestedPayload) {
				log.Printf("[reverb] scan.requested: scan_id=%d", p.ScanID)
				go runScan(apiClient, p.ScanID)
			},
			OnImportRequested: func(p ws.ImportRequestedPayload) {
				log.Printf("[reverb] import.requested: agent_id=%d", p.AgentID)
				go importExistingRules(apiClient)
			},
			OnSyncRequested: func(p ws.SyncRequestedPayload) {
				log.Printf("[reverb] sync.requested: agent_id=%d", p.AgentID)
				go func() {
					if err := syncAndApply(apiClient, w, webW, geo, reportUpdateEvent); err != nil {
						log.Printf("[sync] sync.requested failed: %v", err)
					}
				}()
			},
			OnAuditRequested: func(p ws.AuditRequestedPayload) {
				log.Printf("[reverb] audit.requested: audit_id=%d", p.AuditID)
				go runSoftwareAudit(apiClient, p.AuditID)
			},
			OnUpdateRequested: func(p ws.UpdateRequestedPayload) {
				log.Printf("[reverb] update.requested: checking for updates...")
				resp, err := apiClient.Heartbeat(api.HeartbeatRequest{
					Status:    "online",
					Version:   version,
					Timestamp: time.Now().UTC().Format(time.RFC3339),
					IPAddress: detectOutboundIP(),
				})
				if err != nil {
					log.Printf("[updater] heartbeat failed: %v", err)
					return
				}
				if resp.LatestAgentVersion != nil && resp.AgentDownloadBaseURL != nil {
					updater.CheckAndUpdate(version, *resp.LatestAgentVersion, *resp.AgentDownloadBaseURL, reportUpdateEvent)
				}
			},
			OnRemediationRequested: func(p ws.RemediationRequestedPayload) {
				log.Printf("[reverb] remediation.requested: job_id=%d check_id=%s", p.JobID, p.CheckID)
				go runRemediation(apiClient, p.JobID, p.CheckID)
			},
		},
	)
	go wsClient.Run()

	// Detect web server once at startup (lightweight — runs nginx -v or apache2 -v once)
	wsName, wsVersion := detectWebServerInfo()
	if wsName != "" {
		log.Printf("[webserver] detected %s %s", wsName, wsVersion)
	}

	// Detect Docker info at startup
	dockerVersion, dockerContainers := collectDockerInfo()
	if dockerVersion != "" {
		log.Printf("[docker] detected Docker %s with %d container(s)", dockerVersion, len(dockerContainers))
	}

	// Metrics collector
	metricsCollector := monitor.NewMetricsCollector()

	// Heartbeat ticker (includes zombie count + web server info + system metrics)
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			zReport := monitor.ScanZombies()
			sysMetrics := metricsCollector.Collect()

			// Refresh Docker info (containers can start/stop)
			dockerVersion, dockerContainers = collectDockerInfo()

			hbReq := api.HeartbeatRequest{
				Status:           "online",
				Version:          version,
				Timestamp:        time.Now().UTC().Format(time.RFC3339),
				IPAddress:        detectOutboundIP(),
				ZombieCount:      zReport.Count,
				WebServer:        wsName,
				WebServerVersion: wsVersion,
				Metrics: &api.SystemMetrics{
					CPUPercent:    sysMetrics.CPUPercent,
					MemoryTotal:   sysMetrics.MemoryTotal,
					MemoryUsed:    sysMetrics.MemoryUsed,
					MemoryPercent: sysMetrics.MemoryPercent,
					DiskTotal:     sysMetrics.DiskTotal,
					DiskUsed:      sysMetrics.DiskUsed,
					DiskPercent:   sysMetrics.DiskPercent,
					LoadAvg1:      sysMetrics.LoadAvg1,
					LoadAvg5:      sysMetrics.LoadAvg5,
					LoadAvg15:     sysMetrics.LoadAvg15,
					NetBytesIn:    sysMetrics.NetBytesIn,
					NetBytesOut:   sysMetrics.NetBytesOut,
				},
				MonitoredDomains:  monitoredDomains,
				MonitoredLogPaths: monitoredLogPaths,
				DockerVersion:     dockerVersion,
				DockerContainers:  dockerContainers,
				AuthWatcherMethod: w.Method,
			}

			resp, err := apiClient.Heartbeat(hbReq)
			if err != nil {
				log.Printf("[heartbeat] error: %v", err)
				continue
			}

			// Check for agent update
			if resp.LatestAgentVersion != nil && resp.AgentDownloadBaseURL != nil {
				go updater.CheckAndUpdate(version, *resp.LatestAgentVersion, *resp.AgentDownloadBaseURL, reportUpdateEvent)
			}
		}
	}()

	// Zombie process monitor (check every 60s, report events when threshold exceeded)
	go runZombieMonitor(apiClient)

	// Security monitors (configurable per-server via panel)
	go runPortScanMonitor(apiClient)
	go runFloodMonitor(apiClient)
	go runIntegrityMonitor(apiClient)

	// Fallback sync ticker (every 5min, in case WS misses something)
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			if err := syncAndApply(apiClient, w, webW, geo, reportUpdateEvent); err != nil {
				log.Printf("[sync] error: %v", err)
			}
		}
	}()

	log.Println("Agent running. Press Ctrl+C to stop.")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down...")
}

func syncAndApply(client *api.Client, w *watcher.Watcher, webW *watcher.WebWatcher, geo *geoip.Lookup, reportUpdateEvent updater.EventReporter) error {
	sync, err := client.Sync()
	if err != nil {
		return err
	}

	// Apply brute force config to watcher
	w.UpdateConfig(watcher.Config{
		Threshold: sync.Config.BFThreshold,
		Window:    time.Duration(sync.Config.BFWindow) * time.Second,
	})

	// Apply whitelists
	var wlIPs, wlCIDRs []string
	for _, wl := range sync.Whitelists {
		if wl.IPAddress != nil && *wl.IPAddress != "" {
			wlIPs = append(wlIPs, *wl.IPAddress)
		}
		if wl.IPRange != nil && *wl.IPRange != "" {
			wlCIDRs = append(wlCIDRs, *wl.IPRange)
		}
	}
	w.UpdateWhitelist(wlIPs, wlCIDRs)

	// Store whitelist IPs for monitor exclusions
	whitelistMu.Lock()
	whitelistIPs = wlIPs
	whitelistMu.Unlock()

	// Store monitor config for detector goroutines
	if sync.Config.MonitorConfig != nil {
		monitorConfigMu.Lock()
		monitorCfg = sync.Config.MonitorConfig
		monitorConfigMu.Unlock()
	}

	if webW != nil {
		webW.UpdateWhitelist(wlIPs, wlCIDRs)
		// Apply WAF config from panel
		if sync.Config.WAFConfig != nil {
			webW.UpdateWAFConfig(&watcher.WAFConfig{
				EnabledTypes:    sync.Config.WAFConfig.EnabledTypes,
				DetectOnlyTypes: sync.Config.WAFConfig.DetectOnlyTypes,
				Thresholds:      sync.Config.WAFConfig.Thresholds,
			})
		} else {
			webW.UpdateWAFConfig(nil)
		}
	}

	// Extract blocked countries from rules and update GeoIP
	var blockedCountries []string
	for _, r := range sync.Rules {
		if r.CountryCode != nil && *r.CountryCode != "" && r.Type == "block" {
			blockedCountries = append(blockedCountries, *r.CountryCode)
		}
	}
	geo.SetBlocked(blockedCountries)

	// Apply bans
	activeBanIPs := make(map[string]bool, len(sync.Bans))
	banIPs := make([]string, 0, len(sync.Bans))
	for _, b := range sync.Bans {
		activeBanIPs[b.IPAddress] = true
		banIPs = append(banIPs, b.IPAddress)
	}
	firewall.ApplyBans(banIPs)

	// Build set of IPs managed by user firewall rules (so cleanup doesn't remove them)
	activeRuleIPs := make(map[string]bool)
	for _, r := range sync.Rules {
		if r.IPAddress != nil && *r.IPAddress != "" && r.Type == "block" {
			activeRuleIPs[*r.IPAddress] = true
		}
	}

	// Remove iptables DROP rules for bans that expired or were removed server-side
	cleaned := firewall.CleanupStaleBans(activeBanIPs, activeRuleIPs)

	// Apply firewall rules that are pending or synced (skip country-only rules)
	rulesApplied := 0
	for _, r := range sync.Rules {
		// Country rules are handled by the geoip check, not iptables
		if r.CountryCode != nil && *r.CountryCode != "" {
			continue
		}
		if r.Status == "pending" || r.Status == "synced" {
			applyAndAckRule(client, r)
			rulesApplied++
		}
	}

	log.Printf("[sync] applied %d bans, cleaned %d expired, %d/%d rules, %d whitelists, %d geoblock countries",
		len(sync.Bans), cleaned, rulesApplied, len(sync.Rules), len(sync.Whitelists), len(blockedCountries))

	// Check for agent update from sync response
	if sync.AgentUpdate != nil && sync.AgentUpdate.LatestVersion != "" {
		go updater.CheckAndUpdate(version, sync.AgentUpdate.LatestVersion, sync.AgentUpdate.DownloadBaseURL, reportUpdateEvent)
	}

	return nil
}

// importExistingRules reads current iptables INPUT rules and sends them to the server.
func importExistingRules(client *api.Client) {
	rules, err := firewall.ListRules()
	if err != nil {
		log.Printf("[import] failed to list iptables rules: %v", err)
		return
	}

	if len(rules) == 0 {
		log.Printf("[import] no manageable iptables rules found")
		return
	}

	imported := make([]api.ImportedRule, len(rules))
	for i, r := range rules {
		imported[i] = api.ImportedRule{
			RawRule:   r.RawRule,
			Type:      r.Type,
			Protocol:  r.Protocol,
			Source:    r.Source,
			Port:      r.Port,
		}
	}

	resp, err := client.ImportRules(api.ImportRulesRequest{Rules: imported})
	if err != nil {
		log.Printf("[import] failed to send rules to server: %v", err)
		return
	}

	log.Printf("[import] complete — imported=%d, skipped=%d, total=%d", resp.Imported, resp.Skipped, resp.Total)
}

// runScan executes a vulnerability scan and submits results to the server.
func runScan(client *api.Client, scanID int64) {
	log.Printf("[scanner] starting scan %d", scanID)

	results := scanner.Run()

	findings := make([]api.ScanFinding, len(results))
	for i, r := range results {
		findings[i] = api.ScanFinding{
			Category:       r.Category,
			Severity:       r.Severity,
			CheckID:        r.CheckID,
			Title:          r.Title,
			Description:    r.Description,
			Recommendation: r.Recommendation,
			Details:        r.Details,
			Passed:         r.Passed,
		}
	}

	if err := client.SubmitScanResults(api.ScanResultRequest{
		ScanID:   scanID,
		Findings: findings,
	}); err != nil {
		log.Printf("[scanner] failed to submit results: %v", err)
		return
	}

	log.Printf("[scanner] scan %d complete — %d findings submitted", scanID, len(findings))
}

// runSoftwareAudit collects the full software inventory and submits it to the server.
func runSoftwareAudit(client *api.Client, auditID int64) {
	log.Printf("[collector] starting software audit %d", auditID)

	result := collector.Collect()

	if err := client.SubmitSoftwareAudit(api.SoftwareAuditRequest{
		AuditID:     auditID,
		Summary:     result.Summary,
		KeySoftware: result.KeySoftware,
		Packages:    result.Packages,
	}); err != nil {
		log.Printf("[collector] failed to submit audit %d: %v", auditID, err)
		return
	}

	log.Printf("[collector] audit %d complete — %d packages, %d key software items",
		auditID, result.Summary.TotalPackages, len(result.KeySoftware))
}

// runRemediation executes an automatic fix for the given check_id and reports the result.
func runRemediation(client *api.Client, jobID int64, checkID string) {
	fixer, ok := remediation.Fixers[checkID]
	if !ok {
		log.Printf("[remediation] no fixer for check_id=%s", checkID)
		_ = client.ReportRemediationResult(jobID, "failed", "no fixer available for "+checkID)
		return
	}

	log.Printf("[remediation] running fixer for job_id=%d check_id=%s", jobID, checkID)
	output, err := fixer()

	status := "completed"
	if err != nil {
		status = "failed"
		output = err.Error() + "\n" + output
	}

	log.Printf("[remediation] job_id=%d status=%s", jobID, status)

	if err := client.ReportRemediationResult(jobID, status, output); err != nil {
		log.Printf("[remediation] failed to report result for job_id=%d: %v", jobID, err)
	}
}

// applyAndAckRule applies a single firewall rule and sends the ack back to the server.
func applyAndAckRule(client *api.Client, r api.Rule) {
	spec := firewall.RuleSpec{
		Type:      r.Type,
		Protocol:  r.Protocol,
		IPAddress: r.IPAddress,
		IPRange:   r.IPRange,
		Port:      r.Port,
	}

	if err := firewall.ApplyRule(spec); err != nil {
		log.Printf("[firewall] failed to apply rule %d: %v", r.ID, err)
		errMsg := err.Error()
		_ = client.AckRule(r.ID, api.RuleAckRequest{
			Status:       "failed",
			ErrorMessage: &errMsg,
		})
		return
	}

	if err := client.AckRule(r.ID, api.RuleAckRequest{Status: "applied"}); err != nil {
		log.Printf("[api] failed to ack rule %d: %v", r.ID, err)
	}
}

// osInfo holds OS detection result.
type osInfo struct {
	name    string
	version string
}

func detectOS() osInfo {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return osInfo{name: "linux", version: "unknown"}
	}

	info := osInfo{}
	for _, line := range splitLines(string(data)) {
		if len(line) < 3 {
			continue
		}
		parts := splitKeyValue(line)
		if len(parts) != 2 {
			continue
		}
		val := trimQuotes(parts[1])
		switch parts[0] {
		case "ID":
			info.name = val
		case "VERSION_ID":
			info.version = val
		}
	}

	if info.name == "" {
		info.name = "linux"
	}

	return info
}

func detectOutboundIP() string {
	if ip := os.Getenv("AGENT_IP"); ip != "" {
		return ip
	}

	// Try UDP dial to detect the preferred outbound IP (no actual traffic sent)
	conn, err := net.DialTimeout("udp", "1.1.1.1:80", 2*time.Second)
	if err == nil {
		defer conn.Close()
		if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && !addr.IP.IsUnspecified() {
			return addr.IP.String()
		}
	}

	// Fallback: iterate network interfaces
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil && !ipNet.IP.IsLoopback() {
					return ipNet.IP.String()
				}
			}
		}
	}

	return "0.0.0.0"
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i, c := range s {
		if c == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func splitKeyValue(s string) []string {
	for i, c := range s {
		if c == '=' {
			return []string{s[:i], s[i+1:]}
		}
	}
	return []string{s}
}

func trimQuotes(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// detectWebServerInfo detects the installed web server and its version.
// Runs once at startup — executes "nginx -v" or "apache2 -v" a single time.
func detectWebServerInfo() (name, version string) {
	// Try Nginx first
	if path, err := exec.LookPath("nginx"); err == nil && path != "" {
		out, err := exec.Command("nginx", "-v").CombinedOutput()
		if err == nil {
			// nginx -v outputs to stderr: "nginx version: nginx/1.24.0"
			s := strings.TrimSpace(string(out))
			if idx := strings.Index(s, "nginx/"); idx >= 0 {
				version = strings.Fields(s[idx+6:])[0]
			}
			return "nginx", version
		}
	}

	// Try Apache (Debian/Ubuntu)
	if path, err := exec.LookPath("apache2"); err == nil && path != "" {
		out, err := exec.Command("apache2", "-v").CombinedOutput()
		if err == nil {
			return "apache", parseApacheVersion(string(out))
		}
	}

	// Try Apache (RHEL/CentOS)
	if path, err := exec.LookPath("httpd"); err == nil && path != "" {
		out, err := exec.Command("httpd", "-v").CombinedOutput()
		if err == nil {
			return "apache", parseApacheVersion(string(out))
		}
	}

	return "", ""
}

// parseApacheVersion extracts version from "Server version: Apache/2.4.57 (Debian)"
func parseApacheVersion(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if idx := strings.Index(line, "Apache/"); idx >= 0 {
			rest := line[idx+7:]
			fields := strings.Fields(rest)
			if len(fields) > 0 {
				return strings.TrimRight(fields[0], " ")
			}
		}
	}
	return ""
}

// collectDockerInfo returns the Docker version and a list of running containers.
func collectDockerInfo() (string, []api.DockerContainer) {
	if _, err := exec.LookPath("docker"); err != nil {
		return "", nil
	}

	// Docker version
	var dockerVersion string
	if out, err := exec.Command("docker", "--version").Output(); err == nil {
		raw := string(out)
		if idx := strings.Index(raw, "version "); idx != -1 {
			rest := raw[idx+8:]
			if comma := strings.Index(rest, ","); comma != -1 {
				dockerVersion = strings.TrimSpace(rest[:comma])
			}
		}
	}

	// Running containers
	out, err := exec.Command("docker", "ps",
		"--format", "{{.ID}}|{{.Image}}|{{.Names}}|{{.Status}}|{{.Ports}}",
		"--filter", "status=running",
	).Output()
	if err != nil || len(strings.TrimSpace(string(out))) == 0 {
		return dockerVersion, nil
	}

	webKeywords := []string{"nginx", "apache", "httpd", "caddy", "openresty", "traefik"}
	var containers []api.DockerContainer

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "|", 5)
		if len(parts) < 4 {
			continue
		}
		id, image, name, status := parts[0], parts[1], parts[2], parts[3]
		ports := ""
		if len(parts) >= 5 {
			ports = parts[4]
		}

		isWeb := false
		imageLower := strings.ToLower(image)
		for _, kw := range webKeywords {
			if strings.Contains(imageLower, kw) {
				isWeb = true
				break
			}
		}
		if !isWeb && ports != "" {
			// Match container port (e.g. "->80/tcp") not host port (":80->")
			for _, wp := range []string{"->80/", "->443/", "->8080/", "->8000/"} {
				if strings.Contains(ports, wp) {
					isWeb = true
					break
				}
			}
		}

		containers = append(containers, api.DockerContainer{
			ID:     id,
			Name:   name,
			Image:  image,
			Status: status,
			Ports:  ports,
			IsWeb:  isWeb,
		})
	}

	return dockerVersion, containers
}

// runZombieMonitor periodically scans for zombie processes and reports events when threshold is exceeded.
func runZombieMonitor(client *api.Client) {
	const threshold = 5 // report event when zombies exceed this
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	lastReported := 0

	for range ticker.C {
		report := monitor.ScanZombies()

		if report.Count <= threshold {
			lastReported = 0
			continue
		}

		// Avoid spamming: only report again if count changed significantly (>= 5 more)
		if lastReported > 0 && report.Count-lastReported < 5 {
			continue
		}

		severity := report.Severity()
		parents := strings.Join(report.TopParents(3), "; ")

		log.Printf("[monitor] zombie processes detected: %d (severity=%s, parents: %s)", report.Count, severity, parents)

		events := []api.EventRequest{{
			Type:       "zombie_processes",
			Severity:   severity,
			Details:    map[string]string{"count": fmt.Sprintf("%d", report.Count), "parents": parents},
			OccurredAt: time.Now().UTC().Format(time.RFC3339),
		}}

		if err := client.ReportEvents(events); err != nil {
			log.Printf("[monitor] failed to report zombie event: %v", err)
		}

		lastReported = report.Count
	}
}

func getMonitorSetting(name string) (enabled bool, interval time.Duration) {
	defaults := map[string]time.Duration{
		"port_scan":        5 * time.Second,
		"flood":            10 * time.Second,
		"integrity_change": 5 * time.Minute,
	}

	monitorConfigMu.RLock()
	cfg := monitorCfg
	monitorConfigMu.RUnlock()

	defaultInterval := defaults[name]

	if cfg == nil {
		return true, defaultInterval
	}

	var setting *api.MonitorSetting
	switch name {
	case "port_scan":
		setting = cfg.PortScan
	case "flood":
		setting = cfg.Flood
	case "integrity_change":
		setting = cfg.IntegrityChange
	}

	if setting == nil {
		return true, defaultInterval
	}

	iv := defaultInterval
	if setting.Interval > 0 {
		iv = time.Duration(setting.Interval) * time.Second
	}
	return setting.Enabled, iv
}

func getWhitelistIPs() []string {
	whitelistMu.RLock()
	defer whitelistMu.RUnlock()
	cp := make([]string, len(whitelistIPs))
	copy(cp, whitelistIPs)
	return cp
}

func reportScanResult(client *api.Client, monitorName string, result monitor.ScanResult) {
	now := time.Now().UTC().Format(time.RFC3339)

	if len(result.Events) > 0 {
		log.Printf("[%s] detected %d event(s)", monitorName, len(result.Events))
		if err := client.ReportEvents(result.Events); err != nil {
			log.Printf("[%s] failed to report events: %v", monitorName, err)
		}
	}

	run := api.MonitorRunRequest{
		Monitor:    monitorName,
		Detections: len(result.Events),
		Summary:    result.Summary,
		RanAt:      now,
	}
	if err := client.ReportMonitorRun(run); err != nil {
		log.Printf("[%s] failed to report run: %v", monitorName, err)
	}
}

func runPortScanMonitor(client *api.Client) {
	detector := monitor.NewPortScanDetector()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		enabled, interval := getMonitorSetting("port_scan")
		if !enabled {
			continue
		}
		ticker.Reset(interval)

		detector.SetWhitelists(getWhitelistIPs())
		result := detector.Scan()
		reportScanResult(client, "port_scan", result)
	}
}

func runFloodMonitor(client *api.Client) {
	detector := monitor.NewFloodDetector()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		enabled, interval := getMonitorSetting("flood")
		if !enabled {
			continue
		}
		ticker.Reset(interval)

		detector.SetWhitelists(getWhitelistIPs())
		result := detector.Scan()
		reportScanResult(client, "flood", result)
	}
}

func runIntegrityMonitor(client *api.Client) {
	detector := monitor.NewIntegrityDetector()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		enabled, interval := getMonitorSetting("integrity_change")
		if !enabled {
			continue
		}
		ticker.Reset(interval)

		result := detector.Scan()
		reportScanResult(client, "integrity_change", result)
	}
}

