package webserver

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
)

const (
	nginxIPSentinel  = "/etc/defensia/.nginx-ip-ready"
	apacheIPSentinel = "/etc/defensia/.apache-ip-ready"

	// Nginx: conf.d file that includes the blocklist
	nginxIPConf      = "/etc/nginx/conf.d/defensia-ip-block.conf"
	nginxIPBlocklist  = "/etc/defensia/ip-blocklist.conf"

	// Apache blocklist (included by the conf file)
	apacheIPBlocklist = "/etc/defensia/ip-blocklist-apache.conf"

	// OLS/CyberPanel: Apache Require syntax works via .htaccess
	olsIPBlocklist = "/etc/defensia/ip-blocklist-ols.conf"
)

// ── Nginx IP Blocking ────────────────────────────────────────────────────────

// SetupNginxIPBlock performs one-time nginx IP blocking setup:
//   - Writes /etc/nginx/conf.d/defensia-ip-block.conf (include directive)
//   - Creates /etc/defensia/ip-blocklist.conf (empty)
//   - Runs nginx -t + nginx -s reload; rolls back on failure
//   - Writes sentinel so this runs only once
func SetupNginxIPBlock(report EventReporter) error {
	if _, err := os.Stat(nginxIPSentinel); err == nil {
		return nil // already done
	}

	if err := os.MkdirAll(defensiaDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", defensiaDir, err)
	}

	// Create empty blocklist first so the include never references a missing file
	if _, err := os.Stat(nginxIPBlocklist); os.IsNotExist(err) {
		if err := os.WriteFile(nginxIPBlocklist, []byte(""), 0644); err != nil {
			return fmt.Errorf("write %s: %w", nginxIPBlocklist, err)
		}
	}

	// Write the conf.d file that includes the blocklist into every server context.
	// This is included at the http level, so we need to use a geo block to set a variable,
	// then check it in server blocks. However, the simplest approach for deny rules is
	// to inject include directly into server blocks (like UA blocking does).
	// Actually, the simplest and most reliable approach: write deny directives in a file
	// and include it from each server block.

	// Find all nginx config files that contain server blocks
	serverFiles, err := findNginxServerBlockFiles()
	if err != nil {
		log.Printf("[ip-block] nginx -T failed, scanning config dirs: %v", err)
		serverFiles = scanNginxConfigDirs()
	}

	// Backup originals, then inject the include directive
	var backups []fileBackup
	for _, path := range serverFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("[ip-block] cannot read %s, skipping: %v", path, err)
			continue
		}
		backups = append(backups, fileBackup{path: path, content: data})
		newContent := injectIPBlockInclude(string(data))
		if newContent == string(data) {
			continue // already injected or no server blocks found
		}
		if err := os.WriteFile(path, []byte(newContent), 0644); err != nil {
			restoreFiles(backups)
			return fmt.Errorf("write %s: %w", path, err)
		}
	}

	// Validate
	if err := nginxTest(); err != nil {
		restoreFiles(backups)
		if report != nil {
			report("webserver_config_error", "warning", map[string]string{
				"error":     err.Error(),
				"webserver": "nginx",
				"action":    "ip_block_setup_failed",
			})
		}
		return fmt.Errorf("nginx -t after setup: %w", err)
	}

	// Reload
	if err := nginxReload(); err != nil {
		restoreFiles(backups)
		if report != nil {
			report("webserver_config_error", "warning", map[string]string{
				"error":     err.Error(),
				"webserver": "nginx",
				"action":    "ip_block_reload_failed",
			})
		}
		return fmt.Errorf("nginx reload after setup: %w", err)
	}

	// Mark done
	if err := os.WriteFile(nginxIPSentinel, []byte("1"), 0644); err != nil {
		log.Printf("[ip-block] warning: could not write sentinel %s: %v", nginxIPSentinel, err)
	}
	log.Printf("[ip-block] nginx IP blocking setup complete (%d server block files)", len(backups))
	return nil
}

// UpdateNginxIPBlocklist regenerates /etc/defensia/ip-blocklist.conf and does nginx -s reload.
// If setup has not completed yet (sentinel absent), writes the file only.
// Skips reload if the generated config is identical to the current file.
func UpdateNginxIPBlocklist(ips []string, report EventReporter) error {
	if err := os.MkdirAll(defensiaDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", defensiaDir, err)
	}

	content := generateNginxIPBlocklist(ips)

	// If setup hasn't run yet, just write the file — it'll be used when setup runs
	if _, err := os.Stat(nginxIPSentinel); os.IsNotExist(err) {
		return os.WriteFile(nginxIPBlocklist, []byte(content), 0644)
	}

	// Skip reload if content hasn't changed
	if existing, err := os.ReadFile(nginxIPBlocklist); err == nil && string(existing) == content {
		return nil
	}

	// Backup current blocklist
	var backup []byte
	if data, err := os.ReadFile(nginxIPBlocklist); err == nil {
		backup = data
	}

	if err := os.WriteFile(nginxIPBlocklist, []byte(content), 0644); err != nil {
		return fmt.Errorf("write %s: %w", nginxIPBlocklist, err)
	}

	if err := nginxTest(); err != nil {
		if backup != nil {
			os.WriteFile(nginxIPBlocklist, backup, 0644) //nolint:errcheck
		}
		if report != nil {
			report("webserver_config_error", "warning", map[string]string{
				"error":     err.Error(),
				"webserver": "nginx",
				"action":    "ip_block_update_failed",
			})
		}
		return fmt.Errorf("nginx -t after blocklist update: %w", err)
	}

	if err := nginxReload(); err != nil {
		if backup != nil {
			os.WriteFile(nginxIPBlocklist, backup, 0644) //nolint:errcheck
			nginxReload()                                //nolint:errcheck
		}
		if report != nil {
			report("webserver_config_error", "warning", map[string]string{
				"error":     err.Error(),
				"webserver": "nginx",
				"action":    "ip_block_reload_failed",
			})
		}
		return fmt.Errorf("nginx reload: %w", err)
	}

	log.Printf("[ip-block] nginx blocklist updated (%d blocked IPs)", len(ips))
	return nil
}

// ── Apache IP Blocking ───────────────────────────────────────────────────────

// SetupApacheIPBlock performs one-time Apache IP blocking setup.
// Writes a conf file that includes the blocklist, enables it, and reloads.
func SetupApacheIPBlock(report EventReporter) error {
	if _, err := os.Stat(apacheIPSentinel); err == nil {
		return nil // already done
	}

	if err := os.MkdirAll(defensiaDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", defensiaDir, err)
	}

	// Create empty blocklist
	if _, err := os.Stat(apacheIPBlocklist); os.IsNotExist(err) {
		if err := os.WriteFile(apacheIPBlocklist, []byte(generateApacheIPBlocklist(nil)), 0644); err != nil {
			return fmt.Errorf("write %s: %w", apacheIPBlocklist, err)
		}
	}

	confPath, useA2enconf := apacheIPConfPath()
	content := generateApacheIPConf()

	if err := os.WriteFile(confPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("write %s: %w", confPath, err)
	}

	if useA2enconf {
		if out, err := exec.Command("a2enconf", "defensia-ip-block").CombinedOutput(); err != nil {
			os.Remove(confPath)
			return fmt.Errorf("a2enconf: %s: %w", strings.TrimSpace(string(out)), err)
		}
	}

	if out, err := exec.Command("apachectl", "-t").CombinedOutput(); err != nil {
		if useA2enconf {
			exec.Command("a2disconf", "defensia-ip-block").Run() //nolint:errcheck
		}
		os.Remove(confPath)
		if report != nil {
			report("webserver_config_error", "warning", map[string]string{
				"error":     strings.TrimSpace(string(out)),
				"webserver": "apache",
				"action":    "ip_block_setup_failed",
			})
		}
		return fmt.Errorf("apachectl -t: %s: %w", strings.TrimSpace(string(out)), err)
	}

	if err := apacheGraceful(); err != nil {
		if useA2enconf {
			exec.Command("a2disconf", "defensia-ip-block").Run() //nolint:errcheck
		}
		os.Remove(confPath)
		if report != nil {
			report("webserver_config_error", "warning", map[string]string{
				"error":     err.Error(),
				"webserver": "apache",
				"action":    "ip_block_reload_failed",
			})
		}
		return err
	}

	if err := os.WriteFile(apacheIPSentinel, []byte("1"), 0644); err != nil {
		log.Printf("[ip-block] warning: could not write sentinel %s: %v", apacheIPSentinel, err)
	}
	log.Println("[ip-block] apache IP blocking setup complete")
	return nil
}

// UpdateApacheIPBlocklist regenerates the Apache IP blocklist and does apachectl graceful.
// Skips reload if the generated config is identical to the current file.
func UpdateApacheIPBlocklist(ips []string, report EventReporter) error {
	content := generateApacheIPBlocklist(ips)

	// If setup hasn't run yet, just write the file
	if _, err := os.Stat(apacheIPSentinel); os.IsNotExist(err) {
		return os.WriteFile(apacheIPBlocklist, []byte(content), 0644)
	}

	// Skip reload if content hasn't changed
	if existing, err := os.ReadFile(apacheIPBlocklist); err == nil && string(existing) == content {
		return nil
	}

	var backup []byte
	if data, err := os.ReadFile(apacheIPBlocklist); err == nil {
		backup = data
	}

	if err := os.WriteFile(apacheIPBlocklist, []byte(content), 0644); err != nil {
		return fmt.Errorf("write %s: %w", apacheIPBlocklist, err)
	}

	if out, err := exec.Command("apachectl", "-t").CombinedOutput(); err != nil {
		if backup != nil {
			os.WriteFile(apacheIPBlocklist, backup, 0644) //nolint:errcheck
		}
		if report != nil {
			report("webserver_config_error", "warning", map[string]string{
				"error":     strings.TrimSpace(string(out)),
				"webserver": "apache",
				"action":    "ip_block_update_failed",
			})
		}
		return fmt.Errorf("apachectl -t: %s: %w", strings.TrimSpace(string(out)), err)
	}

	if err := apacheGraceful(); err != nil {
		if backup != nil {
			os.WriteFile(apacheIPBlocklist, backup, 0644) //nolint:errcheck
			apacheGraceful()                              //nolint:errcheck
		}
		if report != nil {
			report("webserver_config_error", "warning", map[string]string{
				"error":     err.Error(),
				"webserver": "apache",
				"action":    "ip_block_reload_failed",
			})
		}
		return err
	}

	log.Printf("[ip-block] apache blocklist updated (%d blocked IPs)", len(ips))
	return nil
}

// ── OLS IP Blocking ──────────────────────────────────────────────────────────
// OpenLiteSpeed with CyberPanel supports Apache .htaccess syntax including
// "Require not ip". We write a standalone blocklist file that can be included
// from .htaccess or vhost config.

// UpdateOLSIPBlocklist writes the OLS IP blocklist file.
// OLS does not need a setup step — it reads .htaccess natively.
// No reload needed: OLS picks up .htaccess changes automatically.
func UpdateOLSIPBlocklist(ips []string, report EventReporter) error {
	if err := os.MkdirAll(defensiaDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", defensiaDir, err)
	}

	content := generateApacheIPBlocklist(ips)

	// Skip write if content hasn't changed
	if existing, err := os.ReadFile(olsIPBlocklist); err == nil && string(existing) == content {
		return nil
	}

	if err := os.WriteFile(olsIPBlocklist, []byte(content), 0644); err != nil {
		return fmt.Errorf("write %s: %w", olsIPBlocklist, err)
	}

	log.Printf("[ip-block] OLS blocklist updated (%d blocked IPs)", len(ips))
	return nil
}

// ── UpdateIPBlocklist is the unified entry point ─────────────────────────────

// UpdateIPBlocklist writes web server IP deny rules for the given IPs.
// wsType should be "nginx", "apache", or "litespeed".
// Safe to call frequently — only reloads when content changes.
func UpdateIPBlocklist(ips []string, wsType string, report EventReporter) error {
	switch wsType {
	case "nginx":
		return UpdateNginxIPBlocklist(ips, report)
	case "apache":
		return UpdateApacheIPBlocklist(ips, report)
	case "litespeed":
		return UpdateOLSIPBlocklist(ips, report)
	default:
		return fmt.Errorf("[ip-block] unsupported web server type: %s", wsType)
	}
}

// ── Content generators ───────────────────────────────────────────────────────

// generateNginxIPBlocklist produces nginx deny directives, one per IP.
// Output is sorted for stable diffs.
func generateNginxIPBlocklist(ips []string) string {
	if len(ips) == 0 {
		return ""
	}
	sorted := dedupAndSort(ips)
	var sb strings.Builder
	sb.WriteString("# Defensia IP blocklist — managed automatically, do not edit\n")
	for _, ip := range sorted {
		if isValidIP(ip) {
			fmt.Fprintf(&sb, "deny %s;\n", ip)
		}
	}
	return sb.String()
}

// generateApacheIPBlocklist produces Apache/OLS Require directives.
// Used for both Apache and OpenLiteSpeed (which supports the same syntax).
func generateApacheIPBlocklist(ips []string) string {
	var sb strings.Builder
	sb.WriteString("# Defensia IP blocklist — managed automatically, do not edit\n")
	if len(ips) == 0 {
		return sb.String()
	}
	sorted := dedupAndSort(ips)
	for _, ip := range sorted {
		if isValidIP(ip) {
			fmt.Fprintf(&sb, "Require not ip %s\n", ip)
		}
	}
	return sb.String()
}

// generateApacheIPConf produces the Apache conf file that includes the blocklist.
func generateApacheIPConf() string {
	return "# Defensia IP blocking — managed automatically, do not edit\n" +
		"<Directory />\n" +
		"    <RequireAll>\n" +
		"        Require all granted\n" +
		"        Include " + apacheIPBlocklist + "\n" +
		"    </RequireAll>\n" +
		"</Directory>\n"
}

// ── Nginx IP block injection ─────────────────────────────────────────────────

// injectIPBlockInclude inserts "include /etc/defensia/ip-blocklist.conf;" inside each server block.
// Idempotent: if ip-blocklist.conf already appears in the file, returns unchanged.
func injectIPBlockInclude(content string) string {
	if strings.Contains(content, "ip-blocklist.conf") {
		return content
	}
	return serverBlockRe.ReplaceAllStringFunc(content, func(match string) string {
		trimmed := strings.TrimLeft(match, " \t")
		indent := match[:len(match)-len(trimmed)]
		return match + "\n" + indent + "    include /etc/defensia/ip-blocklist.conf; # defensia ip-block"
	})
}

// ── Apache IP block helpers ──────────────────────────────────────────────────

// apacheIPConfPath returns the appropriate conf file path for IP blocking.
func apacheIPConfPath() (path string, useA2enconf bool) {
	if _, err := exec.LookPath("a2enconf"); err == nil {
		return "/etc/apache2/conf-available/defensia-ip-block.conf", true
	}
	return "/etc/httpd/conf.d/defensia-ip-block.conf", false
}

// ── Utilities ────────────────────────────────────────────────────────────────

// isValidIP returns true if s is a valid IPv4 or IPv6 address.
func isValidIP(s string) bool {
	return net.ParseIP(s) != nil
}

// dedupAndSort removes duplicates and sorts IPs for stable output.
func dedupAndSort(ips []string) []string {
	seen := make(map[string]bool, len(ips))
	var result []string
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip != "" && !seen[ip] {
			seen[ip] = true
			result = append(result, ip)
		}
	}
	sort.Strings(result)
	return result
}
