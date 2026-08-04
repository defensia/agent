package scanner

import (
	"os"
	"strings"
)

// checkWebServer detects the web server and checks its configuration.
// Only reads config files — no process execution, no network calls.
func checkWebServer() []Finding {
	ws := detectWebServerType()
	if ws == "" {
		return []Finding{{
			Category:    "webserver_config",
			Severity:    "info",
			CheckID:     "WS_NOT_DETECTED",
			Title:       "No web server detected",
			Description: "Neither Nginx nor Apache configuration was found",
			Passed:      true,
		}}
	}

	var findings []Finding

	if ws == "nginx" {
		findings = append(findings, checkNginx()...)
	} else {
		findings = append(findings, checkApache()...)
	}

	return findings
}

// detectWebServerType checks for Nginx or Apache config files.
func detectWebServerType() string {
	if fileExists("/etc/nginx/nginx.conf") {
		return "nginx"
	}
	if fileExists("/etc/apache2/apache2.conf") || fileExists("/etc/httpd/conf/httpd.conf") {
		return "apache"
	}
	return ""
}

// ─── Nginx Checks ───

func checkNginx() []Finding {
	var findings []Finding

	content, err := os.ReadFile("/etc/nginx/nginx.conf")
	if err != nil {
		return findings
	}
	conf := string(content)

	// Also read sites-enabled configs for header/SSL checks
	sitesConf := readDirConfigs("/etc/nginx/sites-enabled")
	allConf := conf + "\n" + sitesConf

	// WS_SERVER_TOKENS — hide Nginx version
	hasServerTokensOff := containsDirective(conf, "server_tokens", "off")
	findings = append(findings, Finding{
		Category:       "webserver_security",
		Severity:       "medium",
		CheckID:        "WS_SERVER_TOKENS",
		Title:          "Nginx server_tokens",
		Description:    boolDesc(hasServerTokensOff, "server_tokens is off", "server_tokens is not set to off (version exposed)"),
		Recommendation: "Add 'server_tokens off;' in the http block of nginx.conf",
		Passed:         hasServerTokensOff,
	})

	// WS_GZIP — compression enabled
	hasGzip := containsDirective(conf, "gzip", "on")
	findings = append(findings, Finding{
		Category:       "webserver_performance",
		Severity:       "low",
		CheckID:        "WS_GZIP",
		Title:          "Nginx gzip compression",
		Description:    boolDesc(hasGzip, "gzip is enabled", "gzip is not enabled"),
		Recommendation: "Add 'gzip on;' in the http block for better performance",
		Passed:         hasGzip,
	})

	// WS_KEEPALIVE — keepalive configured
	hasKeepalive := strings.Contains(conf, "keepalive_timeout")
	findings = append(findings, Finding{
		Category:       "webserver_performance",
		Severity:       "low",
		CheckID:        "WS_KEEPALIVE",
		Title:          "Nginx keepalive_timeout",
		Description:    boolDesc(hasKeepalive, "keepalive_timeout is configured", "keepalive_timeout is not explicitly set"),
		Recommendation: "Set 'keepalive_timeout 65;' for optimal connection reuse",
		Passed:         hasKeepalive,
	})

	// WS_WORKER_PROCESSES — should be auto
	hasWorkerAuto := containsDirective(conf, "worker_processes", "auto")
	findings = append(findings, Finding{
		Category:       "webserver_performance",
		Severity:       "low",
		CheckID:        "WS_WORKER_PROCESSES",
		Title:          "Nginx worker_processes",
		Description:    boolDesc(hasWorkerAuto, "worker_processes is set to auto", "worker_processes is not set to auto"),
		Recommendation: "Set 'worker_processes auto;' to match available CPU cores",
		Passed:         hasWorkerAuto,
	})

	// WS_CLIENT_MAX_BODY — limit request body size
	hasBodyLimit := strings.Contains(allConf, "client_max_body_size")
	findings = append(findings, Finding{
		Category:       "webserver_security",
		Severity:       "low",
		CheckID:        "WS_CLIENT_MAX_BODY",
		Title:          "Nginx client_max_body_size",
		Description:    boolDesc(hasBodyLimit, "client_max_body_size is configured", "client_max_body_size is not set (default 1M)"),
		Recommendation: "Set 'client_max_body_size' to limit upload sizes",
		Passed:         hasBodyLimit,
	})

	// WS_RATE_LIMIT — rate limiting configured
	hasRateLimit := strings.Contains(allConf, "limit_req_zone")
	findings = append(findings, Finding{
		Category:       "webserver_security",
		Severity:       "medium",
		CheckID:        "WS_RATE_LIMIT",
		Title:          "Nginx rate limiting",
		Description:    boolDesc(hasRateLimit, "limit_req_zone is configured", "No rate limiting configured"),
		Recommendation: "Add 'limit_req_zone' to protect against request floods",
		Passed:         hasRateLimit,
	})

	// WS_SEC_HEADERS — individual security header checks
	findings = append(findings, checkSecurityHeaders(allConf, "nginx")...)

	// WS_SSL_PROTOCOLS — no old TLS
	findings = append(findings, checkSSLProtocols(allConf, "ssl_protocols", "nginx")...)

	return findings
}

// ─── Apache Checks ───

func checkApache() []Finding {
	var findings []Finding

	// Try both Debian and RHEL paths
	confPath := "/etc/apache2/apache2.conf"
	if !fileExists(confPath) {
		confPath = "/etc/httpd/conf/httpd.conf"
	}

	content, err := os.ReadFile(confPath)
	if err != nil {
		return findings
	}
	conf := string(content)

	// Also read sites-enabled or conf.d
	sitesConf := readDirConfigs("/etc/apache2/sites-enabled")
	if sitesConf == "" {
		sitesConf = readDirConfigs("/etc/httpd/conf.d")
	}
	allConf := conf + "\n" + sitesConf

	// WS_SERVER_SIGNATURE — hide Apache info in error pages
	hasSignatureOff := containsDirective(allConf, "ServerSignature", "Off")
	findings = append(findings, Finding{
		Category:       "webserver_security",
		Severity:       "medium",
		CheckID:        "WS_SERVER_SIGNATURE",
		Title:          "Apache ServerSignature",
		Description:    boolDesc(hasSignatureOff, "ServerSignature is Off", "ServerSignature is not set to Off (info exposed in error pages)"),
		Recommendation: "Add 'ServerSignature Off' to your Apache config",
		Passed:         hasSignatureOff,
	})

	// WS_SERVER_TOKENS_APACHE — minimize version info
	hasTokensProd := containsDirective(allConf, "ServerTokens", "Prod")
	findings = append(findings, Finding{
		Category:       "webserver_security",
		Severity:       "medium",
		CheckID:        "WS_SERVER_TOKENS_APACHE",
		Title:          "Apache ServerTokens",
		Description:    boolDesc(hasTokensProd, "ServerTokens is set to Prod", "ServerTokens is not set to Prod (version info exposed)"),
		Recommendation: "Set 'ServerTokens Prod' to minimize server information",
		Passed:         hasTokensProd,
	})

	// WS_DIRECTORY_LISTING — disable directory browsing
	hasNoIndexes := strings.Contains(allConf, "-Indexes")
	findings = append(findings, Finding{
		Category:       "webserver_security",
		Severity:       "medium",
		CheckID:        "WS_DIRECTORY_LISTING",
		Title:          "Apache directory listing",
		Description:    boolDesc(hasNoIndexes, "Directory listing is disabled (-Indexes)", "Options -Indexes not found (directory listing may be enabled)"),
		Recommendation: "Add 'Options -Indexes' to disable directory browsing",
		Passed:         hasNoIndexes,
	})

	// WS_TRACE_METHOD — disable TRACE
	hasTraceOff := containsDirective(allConf, "TraceEnable", "Off") || containsDirective(allConf, "TraceEnable", "off")
	findings = append(findings, Finding{
		Category:       "webserver_security",
		Severity:       "medium",
		CheckID:        "WS_TRACE_METHOD",
		Title:          "Apache TRACE method",
		Description:    boolDesc(hasTraceOff, "TraceEnable is Off", "TRACE method may be enabled"),
		Recommendation: "Add 'TraceEnable Off' to disable the TRACE HTTP method",
		Passed:         hasTraceOff,
	})

	// WS_SEC_HEADERS — individual security header checks
	findings = append(findings, checkSecurityHeaders(allConf, "apache")...)

	// WS_SSL_PROTOCOLS_APACHE — no old TLS
	findings = append(findings, checkSSLProtocols(allConf, "SSLProtocol", "apache")...)

	return findings
}

// ─── Security Header Checks ───

// checkSecurityHeaders checks for individual HTTP security headers in config files.
func checkSecurityHeaders(conf, server string) []Finding {
	type headerCheck struct {
		checkID        string
		header         string
		severity       string
		title          string
		recommendation string
	}

	// Nginx uses add_header, Apache uses Header set/append
	checks := []headerCheck{
		{
			checkID:        "WS_HSTS",
			header:         "Strict-Transport-Security",
			severity:       "medium",
			title:          "HTTP Strict Transport Security (HSTS)",
			recommendation: headerRec(server, "Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
		},
		{
			checkID:        "WS_XCTO",
			header:         "X-Content-Type-Options",
			severity:       "low",
			title:          "X-Content-Type-Options header",
			recommendation: headerRec(server, "X-Content-Type-Options", "nosniff"),
		},
		{
			checkID:        "WS_XFO",
			header:         "X-Frame-Options",
			severity:       "medium",
			title:          "X-Frame-Options header",
			recommendation: headerRec(server, "X-Frame-Options", "SAMEORIGIN"),
		},
		{
			checkID:        "WS_CSP",
			header:         "Content-Security-Policy",
			severity:       "medium",
			title:          "Content Security Policy (CSP)",
			recommendation: headerRec(server, "Content-Security-Policy", "default-src 'self'"),
		},
		{
			checkID:        "WS_PERMISSIONS",
			header:         "Permissions-Policy",
			severity:       "low",
			title:          "Permissions-Policy header",
			recommendation: headerRec(server, "Permissions-Policy", "geolocation=(), camera=(), microphone=()"),
		},
		{
			checkID:        "WS_REFERRER",
			header:         "Referrer-Policy",
			severity:       "low",
			title:          "Referrer-Policy header",
			recommendation: headerRec(server, "Referrer-Policy", "strict-origin-when-cross-origin"),
		},
	}

	var findings []Finding
	for _, c := range checks {
		present := strings.Contains(conf, c.header)
		findings = append(findings, Finding{
			Category:       "webserver_security",
			Severity:       c.severity,
			CheckID:        c.checkID,
			Title:          c.title,
			Description:    boolDesc(present, c.header+" is configured", c.header+" header is missing"),
			Recommendation: c.recommendation,
			Passed:         present,
		})
	}

	return findings
}

// headerRec returns the appropriate config directive for a header.
func headerRec(server, header, value string) string {
	if server == "nginx" {
		return "add_header " + header + " \"" + value + "\" always;"
	}
	return "Header always set " + header + " \"" + value + "\""
}

// ─── Shared Helpers ───

func checkSSLProtocols(conf, directive, server string) []Finding {
	var findings []Finding

	// Find the directive line
	hasSSL := false
	insecure := false

	for _, line := range strings.Split(conf, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(strings.ToLower(trimmed), strings.ToLower(directive)) {
			hasSSL = true
			lower := strings.ToLower(trimmed)
			if strings.Contains(lower, "tlsv1 ") || strings.Contains(lower, "tlsv1;") ||
				strings.Contains(lower, "tlsv1.0") || strings.Contains(lower, "tlsv1.1") ||
				strings.Contains(lower, "+tlsv1 ") || strings.Contains(lower, "+tlsv1.1") {
				insecure = true
			}
			break
		}
	}

	if !hasSSL {
		// No SSL config found — not necessarily a problem if server doesn't handle SSL
		return findings
	}

	passed := !insecure
	findings = append(findings, Finding{
		Category:       "webserver_security",
		Severity:       "high",
		CheckID:        "WS_SSL_PROTOCOLS",
		Title:          "SSL/TLS protocol versions",
		Description:    boolDesc(passed, "Only secure TLS versions configured", "Insecure TLS versions (TLSv1.0/1.1) are enabled"),
		Recommendation: "Only allow TLSv1.2 and TLSv1.3. Remove TLSv1 and TLSv1.1",
		Passed:         passed,
	})

	return findings
}

func containsDirective(conf, key, value string) bool {
	for _, line := range strings.Split(conf, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 && strings.EqualFold(fields[0], key) && strings.EqualFold(strings.TrimRight(fields[1], ";"), value) {
			return true
		}
	}
	return false
}

func readDirConfigs(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}

	var sb strings.Builder
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".conf") {
			continue
		}
		data, err := os.ReadFile(dir + "/" + name)
		if err != nil {
			continue
		}
		sb.Write(data)
		sb.WriteByte('\n')
	}
	return sb.String()
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func boolDesc(passed bool, passMsg, failMsg string) string {
	if passed {
		return passMsg
	}
	return failMsg
}
