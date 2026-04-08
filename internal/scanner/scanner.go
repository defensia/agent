package scanner

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// Finding represents a single security check result.
type Finding struct {
	Category       string            `json:"category"`
	Severity       string            `json:"severity"`
	CheckID        string            `json:"check_id"`
	Title          string            `json:"title"`
	Description    string            `json:"description"`
	Recommendation string            `json:"recommendation,omitempty"`
	Details        map[string]string `json:"details,omitempty"`
	Passed         bool              `json:"passed"`
}

// Run performs all security checks and returns findings.
func Run() []Finding {
	var findings []Finding

	findings = append(findings, checkSSHConfig()...)
	findings = append(findings, checkFilePermissions()...)
	findings = append(findings, checkOpenPorts()...)
	findings = append(findings, checkUsers()...)
	findings = append(findings, checkFirewall()...)
	findings = append(findings, checkProcesses()...)
	findings = append(findings, checkWebServer()...)
	findings = append(findings, checkCredentialExposure()...)

	// Software version checks
	findings = append(findings, checkOSVersion()...)
	findings = append(findings, checkKernelVersion()...)
	findings = append(findings, checkSecurityUpdates()...)
	findings = append(findings, checkPHPVersion()...)
	findings = append(findings, checkMySQLVersion()...)
	findings = append(findings, checkOpenSSHVersion()...)
	findings = append(findings, checkWebServerVersion()...)

	return findings
}

// ─── SSH Config Checks ───

func checkSSHConfig() []Finding {
	var findings []Finding

	data, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		findings = append(findings, Finding{
			Category:    "ssh_config",
			Severity:    "info",
			CheckID:     "SSH_CONFIG_READ",
			Title:       "SSH config not readable",
			Description: "Could not read /etc/ssh/sshd_config",
			Passed:      true, // not a failure, might not have permissions
		})
		return findings
	}

	content := string(data)

	// Check root login
	rootLogin := sshConfigValue(content, "PermitRootLogin")
	passed := rootLogin == "no" || rootLogin == "prohibit-password"
	findings = append(findings, Finding{
		Category:       "ssh_config",
		Severity:       "critical",
		CheckID:        "SSH_ROOT_LOGIN",
		Title:          "SSH root login",
		Description:    fmt.Sprintf("PermitRootLogin is set to '%s'", rootLogin),
		Recommendation: "Set PermitRootLogin to 'no' in /etc/ssh/sshd_config",
		Details:        map[string]string{"value": rootLogin},
		Passed:         passed,
	})

	// Check password auth
	passAuth := sshConfigValue(content, "PasswordAuthentication")
	passed = passAuth == "no"
	findings = append(findings, Finding{
		Category:       "ssh_config",
		Severity:       "high",
		CheckID:        "SSH_PASSWORD_AUTH",
		Title:          "SSH password authentication",
		Description:    fmt.Sprintf("PasswordAuthentication is '%s'", passAuth),
		Recommendation: "Disable password authentication and use SSH keys only",
		Details:        map[string]string{"value": passAuth},
		Passed:         passed,
	})

	// Check SSH port
	port := sshConfigValue(content, "Port")
	if port == "" {
		port = "22"
	}
	passed = port != "22"
	findings = append(findings, Finding{
		Category:       "ssh_config",
		Severity:       "low",
		CheckID:        "SSH_DEFAULT_PORT",
		Title:          "SSH on default port",
		Description:    fmt.Sprintf("SSH is running on port %s", port),
		Recommendation: "Consider changing the SSH port from the default 22",
		Details:        map[string]string{"port": port},
		Passed:         passed,
	})

	// Check X11 forwarding
	x11 := sshConfigValue(content, "X11Forwarding")
	passed = x11 == "no" || x11 == ""
	findings = append(findings, Finding{
		Category:       "ssh_config",
		Severity:       "low",
		CheckID:        "SSH_X11_FORWARDING",
		Title:          "SSH X11 forwarding",
		Description:    fmt.Sprintf("X11Forwarding is '%s'", x11),
		Recommendation: "Disable X11Forwarding unless required",
		Passed:         passed,
	})

	// Check MaxAuthTries
	maxAuth := sshConfigValue(content, "MaxAuthTries")
	if maxAuth == "" {
		maxAuth = "6" // default
	}
	passed = maxAuth != "" && maxAuth <= "4"
	findings = append(findings, Finding{
		Category:       "ssh_config",
		Severity:       "medium",
		CheckID:        "SSH_MAX_AUTH_TRIES",
		Title:          "SSH max auth tries",
		Description:    fmt.Sprintf("MaxAuthTries is %s", maxAuth),
		Recommendation: "Set MaxAuthTries to 3 or lower",
		Details:        map[string]string{"value": maxAuth},
		Passed:         passed,
	})

	return findings
}

// ─── File Permission Checks ───

func checkFilePermissions() []Finding {
	var findings []Finding

	checks := []struct {
		path     string
		maxPerm  os.FileMode
		checkID  string
		severity string
		title    string
	}{
		{"/etc/shadow", 0o640, "PERM_SHADOW", "critical", "/etc/shadow permissions"},
		{"/etc/passwd", 0o644, "PERM_PASSWD", "high", "/etc/passwd permissions"},
		{"/etc/ssh/sshd_config", 0o600, "PERM_SSHD_CONFIG", "high", "sshd_config permissions"},
		{"/root/.ssh/authorized_keys", 0o600, "PERM_AUTH_KEYS", "high", "authorized_keys permissions"},
	}

	for _, c := range checks {
		info, err := os.Stat(c.path)
		if err != nil {
			findings = append(findings, Finding{
				Category:    "file_permissions",
				Severity:    "info",
				CheckID:     c.checkID,
				Title:       c.title,
				Description: fmt.Sprintf("%s not found", c.path),
				Passed:      true,
			})
			continue
		}

		perm := info.Mode().Perm()
		passed := perm <= c.maxPerm
		findings = append(findings, Finding{
			Category:       "file_permissions",
			Severity:       c.severity,
			CheckID:        c.checkID,
			Title:          c.title,
			Description:    fmt.Sprintf("%s has permissions %04o (max allowed: %04o)", c.path, perm, c.maxPerm),
			Recommendation: fmt.Sprintf("Run: chmod %04o %s", c.maxPerm, c.path),
			Details:        map[string]string{"current": fmt.Sprintf("%04o", perm), "max": fmt.Sprintf("%04o", c.maxPerm)},
			Passed:         passed,
		})
	}

	return findings
}

// ─── Open Port Checks ───

func checkOpenPorts() []Finding {
	var findings []Finding

	dangerousPorts := map[int]struct {
		service  string
		severity string
	}{
		21:   {"FTP", "high"},
		23:   {"Telnet", "critical"},
		25:   {"SMTP", "medium"},
		3306: {"MySQL", "high"},
		5432: {"PostgreSQL", "high"},
		6379: {"Redis", "critical"},
		11211: {"Memcached", "high"},
		27017: {"MongoDB", "critical"},
	}

	for port, info := range dangerousPorts {
		open := isPortOpen("127.0.0.1", port)
		if open {
			findings = append(findings, Finding{
				Category:       "open_ports",
				Severity:       info.severity,
				CheckID:        fmt.Sprintf("PORT_%d", port),
				Title:          fmt.Sprintf("%s port %d is open", info.service, port),
				Description:    fmt.Sprintf("%s is listening on port %d", info.service, port),
				Recommendation: fmt.Sprintf("Ensure %s is not exposed publicly or bind to 127.0.0.1", info.service),
				Details:        map[string]string{"port": fmt.Sprintf("%d", port), "service": info.service},
				Passed:         false,
			})
		}
	}

	// If no dangerous ports found, add a pass
	if len(findings) == 0 {
		findings = append(findings, Finding{
			Category:    "open_ports",
			Severity:    "info",
			CheckID:     "PORTS_CLEAN",
			Title:       "No dangerous ports exposed",
			Description: "None of the commonly exploited ports are open locally",
			Passed:      true,
		})
	}

	return findings
}

// ─── User Checks ───

func checkUsers() []Finding {
	var findings []Finding

	// Check for users with UID 0 (besides root)
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return findings
	}

	uid0Users := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) >= 4 && parts[2] == "0" && parts[0] != "root" {
			uid0Users = append(uid0Users, parts[0])
		}
	}

	findings = append(findings, Finding{
		Category:       "users",
		Severity:       "critical",
		CheckID:        "USERS_UID0",
		Title:          "Non-root users with UID 0",
		Description:    fmt.Sprintf("Found %d non-root user(s) with UID 0", len(uid0Users)),
		Recommendation: "Remove or fix users with UID 0 besides root",
		Passed:         len(uid0Users) == 0,
	})

	// Check for users with empty passwords in /etc/shadow
	shadow, err := os.ReadFile("/etc/shadow")
	if err == nil {
		emptyPw := 0
		for _, line := range strings.Split(string(shadow), "\n") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 && parts[1] == "" {
				emptyPw++
			}
		}

		findings = append(findings, Finding{
			Category:       "users",
			Severity:       "critical",
			CheckID:        "USERS_EMPTY_PW",
			Title:          "Users with empty passwords",
			Description:    fmt.Sprintf("Found %d user(s) with empty password hashes", emptyPw),
			Recommendation: "Set passwords or lock accounts without passwords",
			Passed:         emptyPw == 0,
		})
	}

	return findings
}

// ─── Firewall Checks ───

func checkFirewall() []Finding {
	var findings []Finding

	// Check if iptables DEFENSIA chain exists (our chain)
	_, err := os.Stat("/proc/net/ip_tables_names")
	hasIptables := err == nil

	findings = append(findings, Finding{
		Category:       "firewall",
		Severity:       "medium",
		CheckID:        "FW_IPTABLES",
		Title:          "iptables available",
		Description:    fmt.Sprintf("iptables kernel module loaded: %v", hasIptables),
		Recommendation: "Ensure iptables is available for firewall rules",
		Passed:         hasIptables,
	})

	return findings
}

// ─── Helpers ───

func sshConfigValue(content, key string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 && strings.EqualFold(parts[0], key) {
			return parts[1]
		}
	}
	return ""
}

func isPortOpen(host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// ─── Process Checks ───

func checkProcesses() []Finding {
	var findings []Finding

	// Count zombie processes by reading /proc/*/status
	zombieCount := 0
	parentCmds := map[string]int{}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		findings = append(findings, Finding{
			Category:    "processes",
			Severity:    "info",
			CheckID:     "PROC_READ",
			Title:       "Cannot read /proc",
			Description: "Could not read /proc filesystem",
			Passed:      true,
		})
		return findings
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// Only PID directories (all digits)
		isDigit := true
		for _, c := range entry.Name() {
			if c < '0' || c > '9' {
				isDigit = false
				break
			}
		}
		if !isDigit {
			continue
		}

		data, err := os.ReadFile("/proc/" + entry.Name() + "/status")
		if err != nil {
			continue
		}

		state := ""
		ppid := ""
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "State:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					state = fields[1]
				}
			} else if strings.HasPrefix(line, "PPid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					ppid = fields[1]
				}
			}
		}

		if state == "Z" {
			zombieCount++
			// Read parent command
			commData, err := os.ReadFile("/proc/" + ppid + "/comm")
			if err == nil {
				cmd := strings.TrimSpace(string(commData))
				parentCmds[cmd]++
			}
		}
	}

	// Determine severity based on count
	severity := "info"
	if zombieCount >= 20 {
		severity = "critical"
	} else if zombieCount >= 6 {
		severity = "medium"
	}

	passed := zombieCount < 6

	// Build parent summary
	parentSummary := ""
	for cmd, count := range parentCmds {
		if parentSummary != "" {
			parentSummary += ", "
		}
		parentSummary += fmt.Sprintf("%s(%d)", cmd, count)
	}
	if parentSummary == "" {
		parentSummary = "none"
	}

	details := map[string]string{
		"count":   fmt.Sprintf("%d", zombieCount),
		"parents": parentSummary,
	}

	findings = append(findings, Finding{
		Category:       "processes",
		Severity:       severity,
		CheckID:        "PROC_ZOMBIES",
		Title:          "Zombie processes",
		Description:    fmt.Sprintf("Found %d zombie process(es) on the system", zombieCount),
		Recommendation: "Investigate parent processes that are not reaping child processes",
		Details:        details,
		Passed:         passed,
	})

	return findings
}
