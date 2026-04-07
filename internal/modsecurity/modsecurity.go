package modsecurity

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	rulesDir      = "/etc/modsecurity/defensia"
	staticRules   = "defensia-static.conf"
	dynamicRules  = "defensia-dynamic.conf"
	ipBanRules    = "defensia-ipbans.conf"
	includeMarker = "# Defensia ModSecurity rules"
)

// Engine manages ModSecurity rule generation and Apache integration.
type Engine struct {
	mu            sync.Mutex
	available     bool
	apachectl     string
	modsecDir     string
	lastReload    time.Time
	reloadPending bool
}

// New detects if ModSecurity is installed and returns an engine.
func New() *Engine {
	e := &Engine{modsecDir: rulesDir}

	if !e.detectModSecurity() {
		return e
	}

	e.available = true
	os.MkdirAll(rulesDir, 0755)
	log.Printf("[modsec] ModSecurity detected, rules dir: %s", rulesDir)
	return e
}

// IsAvailable returns true if ModSecurity is installed.
func (e *Engine) IsAvailable() bool {
	return e.available
}

// Setup writes static rules and configures Apache to include them.
func (e *Engine) Setup() error {
	if !e.available {
		return nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.writeStaticRules(); err != nil {
		return fmt.Errorf("write static rules: %w", err)
	}

	for _, f := range []string{dynamicRules, ipBanRules} {
		path := filepath.Join(rulesDir, f)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			os.WriteFile(path, []byte("# Defensia dynamic rules\n"), 0644)
		}
	}

	if err := e.ensureInclude(); err != nil {
		return fmt.Errorf("ensure include: %w", err)
	}

	if err := e.reloadApache(); err != nil {
		return fmt.Errorf("reload apache: %w", err)
	}

	log.Printf("[modsec] setup complete — static rules active")
	return nil
}

// UpdateBannedIPs writes IP ban rules synced from the dashboard.
func (e *Engine) UpdateBannedIPs(ips []string) error {
	if !e.available || len(ips) == 0 {
		return nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	var rules strings.Builder
	rules.WriteString("# Defensia banned IPs (synced from dashboard)\n")

	for i, ip := range ips {
		if i >= 500 {
			break // cap to prevent huge configs
		}
		id := 9900000 + i + 1
		rules.WriteString(fmt.Sprintf(
			"SecRule REMOTE_ADDR \"@ipMatch %s\" \"id:%d,phase:1,deny,status:403,nolog,msg:'Defensia: Banned IP'\"\n",
			ip, id,
		))
	}

	path := filepath.Join(rulesDir, ipBanRules)
	if err := os.WriteFile(path, []byte(rules.String()), 0644); err != nil {
		return err
	}

	return e.scheduleReload()
}

func (e *Engine) detectModSecurity() bool {
	for _, cmd := range []string{"apachectl", "apache2ctl", "/usr/sbin/apachectl", "/usr/sbin/apache2ctl"} {
		if path, err := exec.LookPath(cmd); err == nil {
			e.apachectl = path
			break
		}
	}

	if e.apachectl == "" {
		return false
	}

	out, err := exec.Command(e.apachectl, "-M").CombinedOutput()
	if err != nil {
		return false
	}

	output := string(out)
	if strings.Contains(output, "security2_module") || strings.Contains(output, "security_module") {
		return true
	}

	modsecConfs := []string{
		"/etc/modsecurity/modsecurity.conf",
		"/etc/httpd/conf.d/mod_security.conf",
		"/etc/apache2/mods-enabled/security2.conf",
		"/usr/local/apache/conf/modsec2.conf",
	}
	for _, conf := range modsecConfs {
		if _, err := os.Stat(conf); err == nil {
			return true
		}
	}

	return false
}

func (e *Engine) writeStaticRules() error {
	rules := `# Defensia ModSecurity Static Rules
# Auto-generated — do not edit manually

# ─── SQL Injection ───
SecRule ARGS|ARGS_NAMES|REQUEST_URI "@rx (?i)(union\s+(all\s+)?select|select\s+.*from\s+information_schema|or\s+1\s*=\s*1|'\s*or\s*'|benchmark\s*\(|sleep\s*\(\d)" \
    "id:9910001,phase:2,deny,status:403,log,msg:'Defensia: SQL Injection',severity:'CRITICAL'"

# ─── XSS ───
SecRule ARGS|REQUEST_URI "@rx (?i)(<script[^>]*>|javascript\s*:|onerror\s*=|onload\s*=|document\.cookie|\.fromCharCode)" \
    "id:9910002,phase:2,deny,status:403,log,msg:'Defensia: XSS',severity:'CRITICAL'"

# ─── RCE ───
SecRule ARGS|REQUEST_URI "@rx (?i)(eval\s*\(|exec\s*\(|system\s*\(|passthru\s*\(|shell_exec\s*\(|proc_open\s*\(|popen\s*\(|\$\{jndi:|php://filter|php://input)" \
    "id:9910003,phase:2,deny,status:403,log,msg:'Defensia: RCE',severity:'CRITICAL'"

# ─── Path Traversal ───
SecRule REQUEST_URI "@rx (?:\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|%252e%252e)" \
    "id:9910004,phase:1,deny,status:403,log,msg:'Defensia: Path Traversal',severity:'HIGH'"

# ─── SSRF ───
SecRule ARGS|REQUEST_URI "@rx (?i)(169\.254\.169\.254|metadata\.google|file:\/\/|gopher:\/\/|dict:\/\/)" \
    "id:9910005,phase:2,deny,status:403,log,msg:'Defensia: SSRF',severity:'CRITICAL'"

# ─── Shellshock ───
SecRule REQUEST_HEADERS "@rx \(\)\s*\{" \
    "id:9910006,phase:1,deny,status:403,log,msg:'Defensia: Shellshock',severity:'CRITICAL'"

# ─── Web Shell Access ───
SecRule REQUEST_URI "@rx (?i)(c99\.php|r57\.php|shell\.php|cmd\.php|wso\.php|b374k|alfa\.php)" \
    "id:9910007,phase:1,deny,status:403,log,msg:'Defensia: Web Shell Access',severity:'CRITICAL'"

# ─── Env File Probe ───
SecRule REQUEST_URI "@rx (?i)(\.env$|\.env\.local|\.env\.production|\.env\.backup)" \
    "id:9910008,phase:1,deny,status:403,log,msg:'Defensia: Env Probe',severity:'HIGH'"

# ─── Config Probe ───
SecRule REQUEST_URI "@rx (?i)(wp-config\.php\.bak|\.git/config|web\.config|\.htpasswd|server-status|server-info)" \
    "id:9910009,phase:1,deny,status:403,log,msg:'Defensia: Config Probe',severity:'HIGH'"

# ─── Header Injection ───
SecRule REQUEST_HEADERS "@rx (\r\n|\n|\r|%0d%0a|%0a|%0d)" \
    "id:9910010,phase:1,deny,status:403,log,msg:'Defensia: Header Injection',severity:'HIGH'"

# ─── Log4Shell ───
SecRule ARGS|REQUEST_HEADERS "@rx \$\{jndi:" \
    "id:9910012,phase:1,deny,status:403,log,msg:'Defensia: Log4Shell',severity:'CRITICAL'"

# ─── Spring4Shell ───
SecRule ARGS_NAMES "@rx class\.module\.classLoader" \
    "id:9910013,phase:2,deny,status:403,log,msg:'Defensia: Spring4Shell',severity:'CRITICAL'"

# ─── Scanner Blocking ───
SecRule REQUEST_HEADERS:User-Agent "@rx (?i)(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|nuclei|acunetix|nessus)" \
    "id:9910014,phase:1,deny,status:403,nolog,msg:'Defensia: Scanner',severity:'MEDIUM'"
`

	path := filepath.Join(rulesDir, staticRules)
	return os.WriteFile(path, []byte(rules), 0644)
}

func (e *Engine) ensureInclude() error {
	includeTargets := []string{
		"/etc/modsecurity/modsecurity.conf",
		"/etc/apache2/mods-enabled/security2.conf",
		"/etc/httpd/conf.d/mod_security.conf",
		"/usr/local/apache/conf/modsec2.conf",
	}

	for _, target := range includeTargets {
		content, err := os.ReadFile(target)
		if err != nil {
			continue
		}

		if strings.Contains(string(content), includeMarker) {
			return nil
		}

		include := fmt.Sprintf("\n%s\nIncludeOptional %s/*.conf\n", includeMarker, rulesDir)
		f, err := os.OpenFile(target, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			continue
		}
		_, err = f.WriteString(include)
		f.Close()
		if err != nil {
			continue
		}

		log.Printf("[modsec] added Include directive to %s", target)
		return nil
	}

	confDirs := []string{"/etc/apache2/conf-enabled", "/etc/httpd/conf.d", "/usr/local/apache/conf/includes"}
	for _, dir := range confDirs {
		if _, err := os.Stat(dir); err == nil {
			confPath := filepath.Join(dir, "defensia-modsec.conf")
			content := fmt.Sprintf("%s\n<IfModule security2_module>\n    IncludeOptional %s/*.conf\n</IfModule>\n", includeMarker, rulesDir)
			if err := os.WriteFile(confPath, []byte(content), 0644); err == nil {
				log.Printf("[modsec] created include conf at %s", confPath)
				return nil
			}
		}
	}

	return fmt.Errorf("could not find suitable Apache config for Include")
}

func (e *Engine) scheduleReload() error {
	if time.Since(e.lastReload) < 5*time.Minute {
		if !e.reloadPending {
			e.reloadPending = true
			go func() {
				time.Sleep(5*time.Minute - time.Since(e.lastReload))
				e.mu.Lock()
				defer e.mu.Unlock()
				if e.reloadPending {
					e.reloadApache()
					e.reloadPending = false
				}
			}()
		}
		return nil
	}
	return e.reloadApache()
}

func (e *Engine) reloadApache() error {
	if e.apachectl == "" {
		return fmt.Errorf("apachectl not found")
	}

	if out, err := exec.Command(e.apachectl, "configtest").CombinedOutput(); err != nil {
		log.Printf("[modsec] config test failed: %s", string(out))
		return fmt.Errorf("config test failed: %w", err)
	}

	if err := exec.Command(e.apachectl, "graceful").Run(); err != nil {
		return fmt.Errorf("graceful reload failed: %w", err)
	}

	e.lastReload = time.Now()
	log.Printf("[modsec] Apache reloaded gracefully")
	return nil
}
