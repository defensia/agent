package webserver

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	nginxSentinel  = "/etc/defensia/.nginx-ua-ready"
	apacheSentinel = "/etc/defensia/.apache-ua-ready"
	nginxMapConf   = "/etc/nginx/conf.d/defensia-ua-block.conf"
	nginxBlocklist = "/etc/defensia/ua-blocklist.conf"
	apacheUAConf   = "/etc/apache2/conf-available/defensia-ua-block.conf"
	defensiaDir    = "/etc/defensia"
)

// EventReporter is called when a config error must be reported to the panel.
type EventReporter func(eventType, severity string, details map[string]string)

// UAFingerprint holds a user-agent pattern to block at the web server level.
type UAFingerprint struct {
	Pattern string
	IsRegex bool
}

// SetupNginxUABlock performs one-time nginx UA blocking setup:
//   - Writes /etc/nginx/conf.d/defensia-ua-block.conf (map + include)
//   - Creates /etc/defensia/ua-blocklist.conf (empty)
//   - Injects "if ($defensia_blocked_ua) { return 444; }" into every server block
//   - Runs nginx -t + nginx -s reload; rolls back on failure
//   - Writes sentinel /etc/defensia/.nginx-ua-ready so this runs only once
func SetupNginxUABlock(report EventReporter) error {
	if _, err := os.Stat(nginxSentinel); err == nil {
		return nil // already done
	}

	if err := os.MkdirAll(defensiaDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", defensiaDir, err)
	}

	// Create empty blocklist first so the map include never references a missing file
	if _, err := os.Stat(nginxBlocklist); os.IsNotExist(err) {
		if err := os.WriteFile(nginxBlocklist, []byte(""), 0644); err != nil {
			return fmt.Errorf("write %s: %w", nginxBlocklist, err)
		}
	}

	// Write the map+include conf (goes into http context via conf.d)
	mapConf := "map $http_user_agent $defensia_blocked_ua {\n" +
		"    default 0;\n" +
		"    include /etc/defensia/ua-blocklist.conf;\n" +
		"}\n"
	if err := os.WriteFile(nginxMapConf, []byte(mapConf), 0644); err != nil {
		return fmt.Errorf("write %s: %w", nginxMapConf, err)
	}

	// Find all nginx config files that contain server blocks
	serverFiles, err := findNginxServerBlockFiles()
	if err != nil {
		log.Printf("[ua-block] nginx -T failed, scanning config dirs: %v", err)
		serverFiles = scanNginxConfigDirs()
	}

	// Backup originals, then inject the if directive
	var backups []fileBackup
	for _, path := range serverFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("[ua-block] cannot read %s, skipping: %v", path, err)
			continue
		}
		backups = append(backups, fileBackup{path: path, content: data})
		newContent := injectIfIntoServerBlock(string(data))
		if newContent == string(data) {
			continue // already injected or no server blocks found
		}
		if err := os.WriteFile(path, []byte(newContent), 0644); err != nil {
			restoreFiles(backups)
			os.Remove(nginxMapConf)
			return fmt.Errorf("write %s: %w", path, err)
		}
	}

	// Validate
	if err := nginxTest(); err != nil {
		restoreFiles(backups)
		os.Remove(nginxMapConf)
		if report != nil {
			report("webserver_config_error", "warning", map[string]string{
				"error":     err.Error(),
				"webserver": "nginx",
				"action":    "ua_block_setup_failed",
			})
		}
		return fmt.Errorf("nginx -t after setup: %w", err)
	}

	// Reload
	if err := nginxReload(); err != nil {
		restoreFiles(backups)
		os.Remove(nginxMapConf)
		if report != nil {
			report("webserver_config_error", "warning", map[string]string{
				"error":     err.Error(),
				"webserver": "nginx",
				"action":    "ua_block_reload_failed",
			})
		}
		return fmt.Errorf("nginx reload after setup: %w", err)
	}

	// Mark done
	if err := os.WriteFile(nginxSentinel, []byte("1"), 0644); err != nil {
		log.Printf("[ua-block] warning: could not write sentinel %s: %v", nginxSentinel, err)
	}
	log.Printf("[ua-block] nginx UA blocking setup complete (%d server block files)", len(backups))
	return nil
}

// UpdateNginxUABlocklist regenerates /etc/defensia/ua-blocklist.conf and does nginx -s reload.
// If setup has not completed yet (sentinel absent), writes the file only — reload happens at setup time.
// Skips reload if the generated config is identical to the current file.
func UpdateNginxUABlocklist(fps []UAFingerprint, report EventReporter) error {
	if err := os.MkdirAll(defensiaDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", defensiaDir, err)
	}

	content := generateNginxBlocklist(fps)

	// If setup hasn't run yet, just write the file — it'll be used when setup runs
	if _, err := os.Stat(nginxSentinel); os.IsNotExist(err) {
		return os.WriteFile(nginxBlocklist, []byte(content), 0644)
	}

	// Skip reload if content hasn't changed
	if existing, err := os.ReadFile(nginxBlocklist); err == nil && string(existing) == content {
		return nil
	}

	// Backup current blocklist
	var backup []byte
	if data, err := os.ReadFile(nginxBlocklist); err == nil {
		backup = data
	}

	if err := os.WriteFile(nginxBlocklist, []byte(content), 0644); err != nil {
		return fmt.Errorf("write %s: %w", nginxBlocklist, err)
	}

	if err := nginxTest(); err != nil {
		if backup != nil {
			os.WriteFile(nginxBlocklist, backup, 0644) //nolint:errcheck
		}
		if report != nil {
			report("webserver_config_error", "warning", map[string]string{
				"error":     err.Error(),
				"webserver": "nginx",
				"action":    "ua_block_update_failed",
			})
		}
		return fmt.Errorf("nginx -t after blocklist update: %w", err)
	}

	if err := nginxReload(); err != nil {
		if backup != nil {
			os.WriteFile(nginxBlocklist, backup, 0644) //nolint:errcheck
			nginxReload()                              //nolint:errcheck
		}
		if report != nil {
			report("webserver_config_error", "warning", map[string]string{
				"error":     err.Error(),
				"webserver": "nginx",
				"action":    "ua_block_reload_failed",
			})
		}
		return fmt.Errorf("nginx reload: %w", err)
	}

	log.Printf("[ua-block] nginx blocklist updated (%d blocked UAs)", len(fps))
	return nil
}

// SetupApacheUABlock performs one-time Apache UA blocking setup.
// Supports both Debian (a2enconf) and RHEL (conf.d direct) layouts.
func SetupApacheUABlock(report EventReporter) error {
	if _, err := os.Stat(apacheSentinel); err == nil {
		return nil // already done
	}

	if err := os.MkdirAll(defensiaDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", defensiaDir, err)
	}

	confPath, useA2enconf := apacheConfPath()
	content := generateApacheConf(nil)

	if err := os.WriteFile(confPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("write %s: %w", confPath, err)
	}

	if useA2enconf {
		if out, err := exec.Command("a2enconf", "defensia-ua-block").CombinedOutput(); err != nil {
			os.Remove(confPath)
			return fmt.Errorf("a2enconf: %s: %w", strings.TrimSpace(string(out)), err)
		}
	}

	if out, err := exec.Command("apachectl", "-t").CombinedOutput(); err != nil {
		if useA2enconf {
			exec.Command("a2disconf", "defensia-ua-block").Run() //nolint:errcheck
		}
		os.Remove(confPath)
		if report != nil {
			report("webserver_config_error", "warning", map[string]string{
				"error":     strings.TrimSpace(string(out)),
				"webserver": "apache",
				"action":    "ua_block_setup_failed",
			})
		}
		return fmt.Errorf("apachectl -t: %s: %w", strings.TrimSpace(string(out)), err)
	}

	if err := apacheGraceful(); err != nil {
		if useA2enconf {
			exec.Command("a2disconf", "defensia-ua-block").Run() //nolint:errcheck
		}
		os.Remove(confPath)
		if report != nil {
			report("webserver_config_error", "warning", map[string]string{
				"error":     err.Error(),
				"webserver": "apache",
				"action":    "ua_block_reload_failed",
			})
		}
		return err
	}

	if err := os.WriteFile(apacheSentinel, []byte("1"), 0644); err != nil {
		log.Printf("[ua-block] warning: could not write sentinel %s: %v", apacheSentinel, err)
	}
	log.Println("[ua-block] apache UA blocking setup complete")
	return nil
}

// UpdateApacheUABlock regenerates the Apache UA block config and does apachectl graceful.
// Skips reload if the generated config is identical to the current file.
func UpdateApacheUABlock(fps []UAFingerprint, report EventReporter) error {
	confPath, _ := apacheConfPath()
	content := generateApacheConf(fps)

	// If setup hasn't run yet, just write the file
	if _, err := os.Stat(apacheSentinel); os.IsNotExist(err) {
		return os.WriteFile(confPath, []byte(content), 0644)
	}

	// Skip reload if content hasn't changed
	if existing, err := os.ReadFile(confPath); err == nil && string(existing) == content {
		return nil
	}

	var backup []byte
	if data, err := os.ReadFile(confPath); err == nil {
		backup = data
	}

	if err := os.WriteFile(confPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("write %s: %w", confPath, err)
	}

	if out, err := exec.Command("apachectl", "-t").CombinedOutput(); err != nil {
		if backup != nil {
			os.WriteFile(confPath, backup, 0644) //nolint:errcheck
		}
		if report != nil {
			report("webserver_config_error", "warning", map[string]string{
				"error":     strings.TrimSpace(string(out)),
				"webserver": "apache",
				"action":    "ua_block_update_failed",
			})
		}
		return fmt.Errorf("apachectl -t: %s: %w", strings.TrimSpace(string(out)), err)
	}

	if err := apacheGraceful(); err != nil {
		if backup != nil {
			os.WriteFile(confPath, backup, 0644) //nolint:errcheck
			apacheGraceful()                     //nolint:errcheck
		}
		if report != nil {
			report("webserver_config_error", "warning", map[string]string{
				"error":     err.Error(),
				"webserver": "apache",
				"action":    "ua_block_reload_failed",
			})
		}
		return err
	}

	log.Printf("[ua-block] apache config updated (%d blocked UAs)", len(fps))
	return nil
}

// ─── Content generators ─────────────────────────────────────────────────────

func generateNginxBlocklist(fps []UAFingerprint) string {
	if len(fps) == 0 {
		return ""
	}
	var sb strings.Builder
	for _, fp := range fps {
		var pat string
		if fp.IsRegex {
			pat = fp.Pattern
		} else {
			pat = regexp.QuoteMeta(fp.Pattern)
		}
		// ~* = case-insensitive PCRE match in nginx map
		fmt.Fprintf(&sb, "~*%s    1;\n", pat)
	}
	return sb.String()
}

func generateApacheConf(fps []UAFingerprint) string {
	var sb strings.Builder
	sb.WriteString("# Defensia UA blocking — managed automatically, do not edit\n")
	for _, fp := range fps {
		var pat string
		if fp.IsRegex {
			pat = fp.Pattern
		} else {
			// Escape double-quotes; Apache SetEnvIfNoCase interprets as regex
			pat = strings.ReplaceAll(regexp.QuoteMeta(fp.Pattern), `"`, `\"`)
		}
		// SetEnvIfNoCase does case-insensitive matching
		fmt.Fprintf(&sb, "SetEnvIfNoCase User-Agent \"%s\" defensia_blocked_ua=1\n", pat)
	}
	if len(fps) > 0 {
		sb.WriteString("<If \"reqenv('defensia_blocked_ua') == '1'\">\n    Require all denied\n</If>\n")
	}
	return sb.String()
}

// ─── Nginx config helpers ────────────────────────────────────────────────────

var serverBlockRe = regexp.MustCompile(`(?m)^\s*server\s*\{`)

// injectIfIntoServerBlock inserts the UA check inside each server block.
// Idempotent: if defensia_blocked_ua already appears in the file, returns unchanged.
func injectIfIntoServerBlock(content string) string {
	if strings.Contains(content, "defensia_blocked_ua") {
		return content
	}
	return serverBlockRe.ReplaceAllStringFunc(content, func(match string) string {
		// Preserve original indentation level
		trimmed := strings.TrimLeft(match, " \t")
		indent := match[:len(match)-len(trimmed)]
		return match + "\n" + indent + "    if ($defensia_blocked_ua) { return 444; } # defensia"
	})
}

// findNginxServerBlockFiles uses nginx -T to list config files containing server blocks.
func findNginxServerBlockFiles() ([]string, error) {
	out, err := exec.Command("nginx", "-T").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("nginx -T: %s: %w", strings.TrimSpace(string(out)), err)
	}
	var files []string
	seen := make(map[string]bool)
	var currentFile string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "# configuration file ") {
			currentFile = strings.TrimSpace(
				strings.TrimSuffix(
					strings.TrimPrefix(line, "# configuration file "), ":"))
		} else if currentFile != "" && serverBlockRe.MatchString(line) && !seen[currentFile] {
			files = append(files, currentFile)
			seen[currentFile] = true
		}
	}
	return files, nil
}

// scanNginxConfigDirs is the fallback when nginx -T is unavailable.
func scanNginxConfigDirs() []string {
	var files []string
	dirs := []string{"/etc/nginx/sites-enabled", "/etc/nginx/conf.d"}
	for _, dir := range dirs {
		entries, _ := filepath.Glob(filepath.Join(dir, "*"))
		for _, path := range entries {
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			if serverBlockRe.Match(data) {
				files = append(files, path)
			}
		}
	}
	return files
}

// ─── Apache helpers ──────────────────────────────────────────────────────────

// apacheConfPath returns the appropriate conf file path and whether a2enconf is needed.
func apacheConfPath() (path string, useA2enconf bool) {
	if _, err := exec.LookPath("a2enconf"); err == nil {
		return apacheUAConf, true
	}
	// RHEL/CentOS: files in conf.d are auto-included
	return "/etc/httpd/conf.d/defensia-ua-block.conf", false
}

// ─── Command wrappers ────────────────────────────────────────────────────────

type fileBackup struct {
	path    string
	content []byte
}

func restoreFiles(backups []fileBackup) {
	for _, b := range backups {
		if err := os.WriteFile(b.path, b.content, 0644); err != nil {
			log.Printf("[ua-block] restore failed for %s: %v", b.path, err)
		}
	}
}

func nginxTest() error {
	out, err := exec.Command("nginx", "-t").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

func nginxReload() error {
	out, err := exec.Command("nginx", "-s", "reload").CombinedOutput()
	if err != nil {
		return fmt.Errorf("nginx -s reload: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func apacheGraceful() error {
	out, err := exec.Command("apachectl", "graceful").CombinedOutput()
	if err != nil {
		return fmt.Errorf("apachectl graceful: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}
