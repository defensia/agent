package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/defensia/agent/internal/api"
	"github.com/defensia/agent/internal/collector"
	"github.com/defensia/agent/internal/config"
	"github.com/defensia/agent/internal/firewall"
	"github.com/defensia/agent/internal/geoip"
	"github.com/defensia/agent/internal/kubernetes"
	"github.com/defensia/agent/internal/malware"
	"github.com/defensia/agent/internal/monitor"
	"github.com/defensia/agent/internal/scanner"
	"github.com/defensia/agent/internal/updater"
	"github.com/defensia/agent/internal/watcher"
	"github.com/defensia/agent/internal/webserver"
	"github.com/defensia/agent/internal/ws"
)

var version = "0.9.92"

// Global malware scanner state (initialized in runAgent, used in syncAndApply + runMalwareScan)
var malwareScheduler *malware.Scheduler
var malwareAllowList *malware.AllowList
var malwareScanner   *malware.Scanner

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
	apiClient.SetVersion(version)

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

	// Deploy recovery script for systemd ExecStartPre (self-heals corrupted binaries)
	updater.DeployRecoveryScript()

	// Check if the recovery script restored the binary before we started
	updater.CheckRecoveryMarker(version, reportUpdateEvent)

	// Self-recovery: detect crash loops after a bad update and auto-rollback
	updater.CheckStartupHealth(version, reportUpdateEvent)

	// Protect the API server IP from being banned (would cut off agent comms)
	if u, err := url.Parse(cfg.ServerURL); err == nil {
		host := u.Hostname()
		if ips, err := net.LookupHost(host); err == nil {
			firewall.AddProtectedIPs(ips...)
		} else {
			log.Printf("[main] warning: could not resolve API host %s: %v", host, err)
		}
	}

	// Initialize firewall backend (detects ipset, falls back to iptables)
	firewall.Init()

	// Initialize GeoIP lookup
	geoDBPath := os.Getenv("GEOIP_DB_PATH")
	geo := geoip.New(geoDBPath)
	defer geo.Close()

	// Initialize Kubernetes client (nil if not running in K8s)
	k8sClient := kubernetes.NewClient()
	if k8sClient != nil {
		log.Printf("[main] Kubernetes mode enabled, node: %s", k8sClient.NodeName())

		// Register K8s ingress-level firewall (ConfigMap with nginx deny rules)
		if k8sFw := kubernetes.NewK8sFirewall(k8sClient); k8sFw != nil {
			firewall.SetK8sHook(k8sFw)
		}

		go k8sClient.WatchEvents(func(event kubernetes.K8sEvent) {
			log.Printf("[kubernetes] event: %s (%s)", event.Type, event.Severity)
			_ = apiClient.ReportEvents([]api.EventRequest{{
				Type:       event.Type,
				Severity:   event.Severity,
				Details:    event.Details,
				OccurredAt: time.Now().UTC().Format(time.RFC3339),
			}})
		})
	}

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

	// Set event callback for monitor mode (report detections without banning)
	w.SetOnEvent(func(ip, eventType, severity string, details map[string]string) {
		log.Printf("[watcher] detected %s from %s (monitor mode)", eventType, ip)
		apiClient.ReportEvents([]api.EventRequest{{
			Type:       eventType,
			Severity:   severity,
			SourceIP:   ip,
			Details:    details,
			OccurredAt: time.Now().UTC().Format(time.RFC3339),
		}})
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

	// In K8s: auto-discover ingress controller log paths
	if k8sClient != nil {
		if ingressPaths := k8sClient.FindIngressLogPaths(); len(ingressPaths) > 0 {
			log.Printf("[main] K8s ingress logs discovered: %v", ingressPaths)
			// Set WEB_LOG_PATH so the web watcher picks them up
			existing := os.Getenv("WEB_LOG_PATH")
			combined := strings.Join(ingressPaths, ",")
			if existing != "" {
				combined = existing + "," + combined
			}
			os.Setenv("WEB_LOG_PATH", combined)
		}
	}

	if webLogInfos, domainMap := watcher.DetectWebLogInfo(); len(webLogInfos) > 0 {
		webLogPaths := make([]string, len(webLogInfos))
		for i, info := range webLogInfos {
			webLogPaths[i] = info.Path
		}
		monitoredLogPaths = webLogPaths
		// Collect unique domains from all log files
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
		log.Printf("[webwatcher] detected %d access log(s)", len(webLogPaths))
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
		webW.SetOnScoredBan(func(ip, reason string, score int, duration time.Duration) {
			log.Printf("[webwatcher] scored ban %s: %s (score=%d, duration=%s)", ip, reason, score, duration)
			if err := firewall.BanIP(ip); err != nil {
				log.Printf("[firewall] error: %v", err)
			}
			// Don't send ExpiresAt — let the backend apply escalation logic
			// (1st=24h, 2nd=7d, 3rd=30d, 4th+=permanent)
			if err := apiClient.ReportBan(api.BanRequest{
				IPAddress: ip,
				Reason:    reason,
				BanCount:  1,
			}); err != nil {
				log.Printf("[api] failed to report scored ban: %v", err)
			}
		})
		// Periodically clean up expired IP scores (every 5 minutes)
		go func() {
			ticker := time.NewTicker(5 * time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				webW.CleanExpiredScores()
			}
		}()
		webW.LoadBotFingerprintsCache()
		webW.LoadWafRulesCache()
		loadThreatFeedCache()
	} else {
		log.Printf("[webwatcher] no access logs found — web attack detection disabled (set WEB_LOG_PATH to override)")
	}

	// Detect web server once at startup (lightweight — runs nginx -v or apache2 -v once)
	wsName, wsVersion := detectWebServerInfo()
	if wsName != "" {
		log.Printf("[webserver] detected %s %s", wsName, wsVersion)
	}

	// Setup UA blocking at web server level (runs once; no-op if sentinel exists)
	uaReport := func(eventType, severity string, details map[string]string) {
		_ = apiClient.ReportEvents([]api.EventRequest{{
			Type:       eventType,
			Severity:   severity,
			Details:    details,
			OccurredAt: time.Now().UTC().Format(time.RFC3339),
		}})
	}
	if wsName == "nginx" {
		go func() {
			if err := webserver.SetupNginxUABlock(uaReport); err != nil {
				log.Printf("[ua-block] nginx setup error: %v", err)
			}
		}()
	} else if wsName == "apache" {
		go func() {
			if err := webserver.SetupApacheUABlock(uaReport); err != nil {
				log.Printf("[ua-block] apache setup error: %v", err)
			}
		}()
	}

	// Start mail log watcher (if Postfix/Dovecot detected)
	var mailW *watcher.MailWatcher
	if watcher.HasMailService() {
		mailW = watcher.NewMailWatcher(func(ip, reason string, count int) {
			log.Printf("[mailwatcher] banning %s: %s (count=%d)", ip, reason, count)
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
		if mailW != nil {
			mailW.SetOnEvent(func(ip, eventType, severity string, details map[string]string) {
				apiClient.ReportEvents([]api.EventRequest{{
					Type:       eventType,
					Severity:   severity,
					SourceIP:   ip,
					Details:    details,
					OccurredAt: time.Now().UTC().Format(time.RFC3339),
				}})
			})
			mailW.SetCheckIP(func(ip string) string {
				cc, blocked := geo.IsBlocked(ip)
				if blocked {
					return fmt.Sprintf("geoblock_%s", strings.ToLower(cc))
				}
				return ""
			})
			log.Printf("[mailwatcher] mail service detected")
		}
	} else {
		log.Printf("[mailwatcher] no mail service found — mail attack detection disabled")
	}

	// Start database log watcher (if MySQL/PostgreSQL/MongoDB detected)
	var dbW *watcher.DBWatcher
	if watcher.HasDBService() {
		dbW = watcher.NewDBWatcher(func(ip, reason string, count int) {
			log.Printf("[dbwatcher] banning %s: %s (count=%d)", ip, reason, count)
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
		if dbW != nil {
			dbW.SetOnEvent(func(ip, eventType, severity string, details map[string]string) {
				apiClient.ReportEvents([]api.EventRequest{{
					Type:       eventType,
					Severity:   severity,
					SourceIP:   ip,
					Details:    details,
					OccurredAt: time.Now().UTC().Format(time.RFC3339),
				}})
			})
			dbW.SetCheckIP(func(ip string) string {
				cc, blocked := geo.IsBlocked(ip)
				if blocked {
					return fmt.Sprintf("geoblock_%s", strings.ToLower(cc))
				}
				return ""
			})
			log.Printf("[dbwatcher] database service detected")
		}
	} else {
		log.Printf("[dbwatcher] no database service found — DB auth detection disabled")
	}

	// Start FTP log watcher (if vsftpd/ProFTPD/Pure-FTPd detected)
	var ftpW *watcher.FTPWatcher
	if watcher.HasFTPService() {
		ftpW = watcher.NewFTPWatcher(func(ip, reason string, count int) {
			log.Printf("[ftpwatcher] banning %s: %s (count=%d)", ip, reason, count)
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
		if ftpW != nil {
			ftpW.SetOnEvent(func(ip, eventType, severity string, details map[string]string) {
				apiClient.ReportEvents([]api.EventRequest{{
					Type:       eventType,
					Severity:   severity,
					SourceIP:   ip,
					Details:    details,
					OccurredAt: time.Now().UTC().Format(time.RFC3339),
				}})
			})
			ftpW.SetCheckIP(func(ip string) string {
				cc, blocked := geo.IsBlocked(ip)
				if blocked {
					return fmt.Sprintf("geoblock_%s", strings.ToLower(cc))
				}
				return ""
			})
			log.Printf("[ftpwatcher] FTP service detected")
		}
	} else {
		log.Printf("[ftpwatcher] no FTP service found — FTP brute force detection disabled")
	}

	// Check for exposed database ports (runs once at startup)
	go func() {
		warnings := watcher.ExposedDBPorts()
		for _, warn := range warnings {
			log.Printf("[dbwatcher] WARNING: %s", warn)
			apiClient.ReportEvents([]api.EventRequest{{
				Type:       "db_exposed",
				Severity:   "critical",
				Details:    map[string]string{"warning": warn},
				OccurredAt: time.Now().UTC().Format(time.RFC3339),
			}})
		}
	}()

	// Initialize malware scanner globals
	malwareScanner = malware.New()
	malwareScanner.HashLookup = func(hashes []string) map[string]string {
		resp, err := apiClient.LookupMalwareHashes(hashes)
		if err != nil {
			log.Printf("[malware] hash lookup failed: %v", err)
			return nil
		}
		result := make(map[string]string, resp.Found)
		for sha, match := range resp.Matches {
			name := match.Name
			if name == "" {
				name = match.Type
			}
			result[sha] = name
		}
		if resp.Found > 0 {
			log.Printf("[malware] hash lookup: %d/%d matches found", resp.Found, resp.Checked)
		}
		return result
	}
	malwareAllowList = malware.NewAllowList()
	malwareScheduler = malware.NewScheduler(func(intensity string) {
		go runMalwareScan(apiClient, intensity)
	})

	// Initial sync (applies config, whitelists, rules, bans)
	if err := syncAndApply(apiClient, w, webW, mailW, dbW, ftpW, geo, reportUpdateEvent, wsName); err != nil {
		log.Printf("[sync] initial sync failed: %v", err)
	}

	// Import existing iptables rules on first startup
	go importExistingRules(apiClient)

	go w.Run()
	if webW != nil {
		go webW.Run()
	}
	if mailW != nil {
		go mailW.Run()
	}
	if dbW != nil {
		go dbW.Run()
	}
	if ftpW != nil {
		go ftpW.Run()
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
					if err := syncAndApply(apiClient, w, webW, mailW, dbW, ftpW, geo, reportUpdateEvent, wsName); err != nil {
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
			OnMalwareScanRequested: func(p ws.MalwareScanRequestedPayload) {
				log.Printf("[reverb] malware_scan.requested: intensity=%s", p.Intensity)
				go runMalwareScan(apiClient, p.Intensity)
			},
		},
	)
	go wsClient.Run()

	// Metrics collector
	metricsCollector := monitor.NewMetricsCollector()

	// Heartbeat ticker (includes zombie count + web server info + system metrics)
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			zReport := monitor.ScanZombies()
			sysMetrics := metricsCollector.Collect()

			var reqAnalyzed uint64
			if webW != nil {
				reqAnalyzed = webW.RequestsAnalyzed()
			}

			fwStatus := firewall.FirewallStatus()
			hbReq := api.HeartbeatRequest{
				Status:            "online",
				Version:           version,
				Timestamp:         time.Now().UTC().Format(time.RFC3339),
				IPAddress:         detectOutboundIP(),
				ZombieCount:       zReport.Count,
				WebServer:         wsName,
				WebServerVersion:  wsVersion,
				MonitoredDomains:  monitoredDomains,
				MonitoredLogPaths: monitoredLogPaths,
				FirewallMode:      fwStatus.Mode,
				BanCapacity:       fwStatus.Capacity,
				ActiveBans:        fwStatus.ActiveBans,
				KubernetesInfo:    collectK8sInfo(k8sClient),
				RequestsAnalyzed: reqAnalyzed,
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

	// Fallback sync ticker (every 5min, in case WS misses something)
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			if err := syncAndApply(apiClient, w, webW, mailW, dbW, ftpW, geo, reportUpdateEvent, wsName); err != nil {
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

func syncAndApply(client *api.Client, w *watcher.Watcher, webW *watcher.WebWatcher, mailW *watcher.MailWatcher, dbW *watcher.DBWatcher, ftpW *watcher.FTPWatcher, geo *geoip.Lookup, reportUpdateEvent updater.EventReporter, wsType string) error {
	sync, err := client.Sync()
	if err != nil {
		return err
	}

	// Apply brute force config to watcher
	w.UpdateConfig(watcher.Config{
		Threshold: sync.Config.BFThreshold,
		Window:    time.Duration(sync.Config.BFWindow) * time.Second,
	})

	// Apply monitor mode
	w.SetMonitorMode(sync.Config.MonitorMode)
	if mailW != nil {
		mailW.SetMonitorMode(sync.Config.MonitorMode)
	}
	if dbW != nil {
		dbW.SetMonitorMode(sync.Config.MonitorMode)
	}
	if ftpW != nil {
		ftpW.SetMonitorMode(sync.Config.MonitorMode)
	}
	if webW != nil {
		webW.SetMonitorMode(sync.Config.MonitorMode)

		// Apply WAF config from panel
		if sync.Config.WAFConfig != nil {
			log.Printf("[sync] applying WAF config: %d enabled types, %d score weights", len(sync.Config.WAFConfig.EnabledTypes), len(sync.Config.WAFConfig.ScorePoints))
			webW.UpdateWAFConfig(&watcher.WAFConfig{
				EnabledTypes:    sync.Config.WAFConfig.EnabledTypes,
				DetectOnlyTypes: sync.Config.WAFConfig.DetectOnlyTypes,
				Thresholds:      sync.Config.WAFConfig.Thresholds,
				ScorePoints:     sync.Config.WAFConfig.ScorePoints,
			})
		} else {
			log.Println("[sync] no WAF config — all types enabled by default")
			webW.UpdateWAFConfig(nil)
		}
	}

	// Apply detection rules from panel (SSH patterns)
	if len(sync.DetectionRules) > 0 {
		var patterns []watcher.SSHPattern
		for _, dr := range sync.DetectionRules {
			if dr.Service != "ssh" {
				continue
			}
			p := watcher.ParsePattern(dr.Pattern, dr.Reason)
			if p != nil {
				patterns = append(patterns, *p)
			}
		}
		w.UpdatePatterns(patterns)
	}

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
	if mailW != nil {
		mailW.UpdateWhitelist(wlIPs, wlCIDRs)
	}
	if dbW != nil {
		dbW.UpdateWhitelist(wlIPs, wlCIDRs)
	}
	if ftpW != nil {
		ftpW.UpdateWhitelist(wlIPs, wlCIDRs)
	}
	if webW != nil {
		webW.UpdateWhitelist(wlIPs, wlCIDRs)
	}

	// Apply geoblocking from config (blocked_countries field)
	blockedCountries := sync.Config.BlockedCountries
	// Fallback: also check rules with country_code for backward compatibility
	for _, r := range sync.Rules {
		if r.CountryCode != nil && *r.CountryCode != "" && r.Type == "block" {
			blockedCountries = append(blockedCountries, *r.CountryCode)
		}
	}
	geo.SetBlocked(blockedCountries)

	// Apply bans (skipped in monitor mode)
	activeBanIPs := make(map[string]bool, len(sync.Bans))
	banIPs := make([]string, 0, len(sync.Bans))
	for _, b := range sync.Bans {
		activeBanIPs[b.IPAddress] = true
		banIPs = append(banIPs, b.IPAddress)
	}
	if !sync.Config.MonitorMode {
		firewall.ApplyBans(banIPs)
	}

	// Apply threat feed blocks (IPs + CIDRs from Spamhaus, Feodo, etc.)
	if !sync.Config.MonitorMode && len(sync.ThreatFeed) > 0 {
		go applyThreatFeed(sync.ThreatFeed)
		saveThreatFeedCache(sync.ThreatFeed)
	}

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

	// Apply bot fingerprints to web watcher
	if webW != nil && len(sync.BotFingerprints) > 0 {
		fps := make([]watcher.BotFingerprintInput, len(sync.BotFingerprints))
		for i, fp := range sync.BotFingerprints {
			fps[i] = watcher.BotFingerprintInput{
				Slug:     fp.Slug,
				Name:     fp.Name,
				Pattern:  fp.Pattern,
				IsRegex:  fp.IsRegex,
				Category: fp.Category,
				Action:   fp.Action,
			}
		}
		webW.UpdateBotFingerprints(fps)
	}

	// Apply dynamic WAF rules (virtual patches from panel)
	if webW != nil {
		rules := make([]watcher.WafRuleInput, len(sync.WafRules))
		for i, r := range sync.WafRules {
			rules[i] = watcher.WafRuleInput{
				ID:       r.ID,
				Category: r.Category,
				Pattern:  r.Pattern,
				Target:   r.Target,
				IsRegex:  r.IsRegex,
			}
		}
		webW.UpdateWafRules(rules)
	}

	// Update web server UA blocklist (fingerprints with action=block)
	if wsType != "" && len(sync.BotFingerprints) > 0 {
		var uaFps []webserver.UAFingerprint
		for _, fp := range sync.BotFingerprints {
			if fp.Action == "block" {
				uaFps = append(uaFps, webserver.UAFingerprint{
					Pattern: fp.Pattern,
					IsRegex: fp.IsRegex,
				})
			}
		}
		uaReport := func(eventType, severity string, details map[string]string) {
			_ = client.ReportEvents([]api.EventRequest{{
				Type:       eventType,
				Severity:   severity,
				Details:    details,
				OccurredAt: time.Now().UTC().Format(time.RFC3339),
			}})
		}
		if wsType == "nginx" {
			go func(fps []webserver.UAFingerprint) {
				if err := webserver.UpdateNginxUABlocklist(fps, uaReport); err != nil {
					log.Printf("[ua-block] nginx update error: %v", err)
				}
			}(uaFps)
		} else if wsType == "apache" {
			go func(fps []webserver.UAFingerprint) {
				if err := webserver.UpdateApacheUABlock(fps, uaReport); err != nil {
					log.Printf("[ua-block] apache update error: %v", err)
				}
			}(uaFps)
		}
	}

	// Apply dynamic malware signatures from backend
	if len(sync.MalwareSignatures) > 0 && malwareScanner != nil {
		dynSigs := make([]malware.Signature, len(sync.MalwareSignatures))
		for i, s := range sync.MalwareSignatures {
			dynSigs[i] = malware.Signature{
				ID:       s.SignatureID,
				Name:     s.Name,
				Pattern:  s.Pattern,
				Severity: s.Severity,
				Type:     s.Type,
				IsRegex:  s.IsRegex,
				PHPOnly:  s.PHPOnly,
			}
		}
		malwareScanner.LoadDynamicSignatures(dynSigs)
	}

	// Apply malware scan schedule config
	if sync.Config.MalwareScanConfig != nil {
		cfg := sync.Config.MalwareScanConfig
		malwareScheduler.UpdateConfig(cfg.Enabled, cfg.Frequency, cfg.Time, cfg.Intensity)
	}

	// Apply malware allowlist (user-ignored findings)
	if len(sync.MalwareAllowlist) > 0 {
		entries := make([]malware.IgnoreEntry, len(sync.MalwareAllowlist))
		for i, e := range sync.MalwareAllowlist {
			entries[i] = malware.IgnoreEntry{
				FilePath:    e.FilePath,
				SignatureID: e.SignatureID,
			}
		}
		malwareAllowList.SetUserIgnored(entries)
	}

	log.Printf("[sync] applied %d bans, cleaned %d expired, %d/%d rules, %d whitelists, %d geoblock countries, %d bot fingerprints",
		len(sync.Bans), cleaned, rulesApplied, len(sync.Rules), len(sync.Whitelists), len(blockedCountries), len(sync.BotFingerprints))

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

func collectK8sInfo(c *kubernetes.Client) interface{} {
	if c == nil {
		return nil
	}
	return c.CollectInfo()
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

// ── Threat Feed ──────────────────────────────────────────────────────────────

const threatFeedCache = "/etc/defensia/threat_feed.json"

func applyThreatFeed(entries []api.ThreatEntry) {
	for _, e := range entries {
		if e.IP != nil && *e.IP != "" {
			if err := firewall.BanIP(*e.IP); err != nil {
				log.Printf("[threat-feed] ban %s (%s): %v", *e.IP, e.Source, err)
			}
		} else if e.CIDR != nil && *e.CIDR != "" {
			cidr := *e.CIDR
			if err := firewall.ApplyRule(firewall.RuleSpec{Type: "block", IPRange: &cidr}); err != nil {
				log.Printf("[threat-feed] block cidr %s (%s): %v", cidr, e.Source, err)
			}
		}
	}
	log.Printf("[threat-feed] applied %d entries", len(entries))
}

func saveThreatFeedCache(entries []api.ThreatEntry) {
	data, err := json.Marshal(entries)
	if err != nil {
		return
	}
	if err := os.MkdirAll("/etc/defensia", 0755); err != nil {
		return
	}
	if err := os.WriteFile(threatFeedCache, data, 0600); err != nil {
		log.Printf("[threat-feed] failed to save cache: %v", err)
	}
}

func loadThreatFeedCache() {
	data, err := os.ReadFile(threatFeedCache)
	if err != nil {
		return
	}
	var entries []api.ThreatEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		log.Printf("[threat-feed] failed to parse cache: %v", err)
		return
	}
	log.Printf("[threat-feed] applying %d cached entries at startup", len(entries))
	applyThreatFeed(entries)
}

// runMalwareScan detects web roots, runs malware signature scanning and framework checks.
func runMalwareScan(client *api.Client, intensityStr string) {
	log.Printf("[malware] starting scan (intensity=%s)", intensityStr)

	_ = client.ReportEvents([]api.EventRequest{{
		Type:       "malware_scan_started",
		Severity:   "info",
		Details:    map[string]string{"intensity": intensityStr},
		OccurredAt: time.Now().UTC().Format(time.RFC3339),
	}})

	intensity := malware.IntensityMedium
	switch intensityStr {
	case "low":
		intensity = malware.IntensityLow
	case "high":
		intensity = malware.IntensityHigh
	}

	webRoots := malware.DetectWebRoots()
	if len(webRoots) == 0 {
		log.Printf("[malware] no web roots found — skipping scan")
		_ = client.ReportEvents([]api.EventRequest{{
			Type:       "malware_scan_completed",
			Severity:   "info",
			Details:    map[string]string{"result": "no_web_roots"},
			OccurredAt: time.Now().UTC().Format(time.RFC3339),
		}})
		return
	}

	apiWebRoots := make([]api.MalwareScanWebRoot, len(webRoots))
	for i, root := range webRoots {
		apiWebRoots[i] = api.MalwareScanWebRoot{
			Path:             root.Path,
			Domain:           root.Domain,
			FrameworkName:    root.Framework.Name,
			FrameworkVersion: root.Framework.Version,
		}
	}

	scanner := malwareScanner
	if scanner == nil {
		scanner = malware.New()
	}
	if malwareAllowList != nil {
		scanner.AllowList = malwareAllowList
	}
	result, err := scanner.ScanWebRoots(webRoots, intensity)
	if err != nil {
		log.Printf("[malware] scan error: %v", err)
		return
	}

	var frameworkFindings []api.MalwareFrameworkIssue
	for _, root := range webRoots {
		for _, ff := range malware.CheckFramework(root) {
			frameworkFindings = append(frameworkFindings, api.MalwareFrameworkIssue{
				CheckID:     ff.CheckID,
				Title:       ff.Title,
				Severity:    ff.Severity,
				Description: ff.Description,
				FilePath:    ff.FilePath,
				Domain:      ff.Domain,
				Framework:   ff.Framework,
			})
		}
	}

	apiFindings := make([]api.MalwareScanFinding, len(result.Findings))
	for i, f := range result.Findings {
		apiFindings[i] = api.MalwareScanFinding{
			FilePath:    f.FilePath,
			SignatureID: f.SignatureID,
			Name:        f.Name,
			Severity:    f.Severity,
			Type:        f.Type,
			MatchLine:   f.MatchLine,
			MatchText:   f.MatchText,
			Domain:      f.Domain,
			Framework:   f.Framework,
		}
	}

	if err := client.SubmitMalwareScanResults(api.MalwareScanResultRequest{
		WebRoots:          apiWebRoots,
		Findings:          apiFindings,
		FrameworkFindings: frameworkFindings,
		FilesScanned:      result.FilesScanned,
		FilesSkipped:      result.FilesSkipped,
		DurationSeconds:   result.Duration.Seconds(),
	}); err != nil {
		log.Printf("[malware] failed to submit results: %v", err)
		return
	}

	log.Printf("[malware] scan complete — %d files scanned, %d malware findings, %d framework issues in %s",
		result.FilesScanned, len(result.Findings), len(frameworkFindings), result.Duration.Round(time.Second))

	_ = client.ReportEvents([]api.EventRequest{{
		Type:     "malware_scan_completed",
		Severity: "info",
		Details: map[string]string{
			"files_scanned":      fmt.Sprintf("%d", result.FilesScanned),
			"malware_findings":   fmt.Sprintf("%d", len(result.Findings)),
			"framework_findings": fmt.Sprintf("%d", len(frameworkFindings)),
			"web_roots":          fmt.Sprintf("%d", len(webRoots)),
			"duration_seconds":   fmt.Sprintf("%.1f", result.Duration.Seconds()),
		},
		OccurredAt: time.Now().UTC().Format(time.RFC3339),
	}})
}
