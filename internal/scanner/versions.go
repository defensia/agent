package scanner

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// ─── OS Version Check ───

func checkOSVersion() []Finding {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return []Finding{{
			Category:    "software_versions",
			Severity:    "info",
			CheckID:     "VER_OS_EOL",
			Title:       "OS version check",
			Description: "Could not read /etc/os-release",
			Passed:      true,
		}}
	}

	content := string(data)
	id := osReleaseValue(content, "ID")
	version := osReleaseValue(content, "VERSION_ID")
	prettyName := osReleaseValue(content, "PRETTY_NAME")
	if prettyName == "" {
		prettyName = id + " " + version
	}

	// EOL versions map
	eolVersions := map[string][]string{
		"ubuntu": {"14.04", "16.04", "18.04", "19.04", "19.10", "20.10", "21.04", "21.10", "22.10", "23.04", "23.10"},
		"debian": {"7", "8", "9", "10"},
		"centos": {"5", "6", "7", "8"},
		"rhel":   {"6", "7"},
		"amzn":   {"1"},
	}

	eol := false
	if versions, ok := eolVersions[id]; ok {
		for _, v := range versions {
			if version == v {
				eol = true
				break
			}
		}
	}

	severity := "info"
	if eol {
		severity = "critical"
	}

	return []Finding{{
		Category:       "software_versions",
		Severity:       severity,
		CheckID:        "VER_OS_EOL",
		Title:          "Operating system version",
		Description:    fmt.Sprintf("%s — %s", prettyName, boolDesc(!eol, "supported", "end of life")),
		Recommendation: conditionalStr(eol, "Upgrade to a supported OS version to receive security patches", ""),
		Details:        map[string]string{"os": id, "version": version, "eol": fmt.Sprintf("%v", eol)},
		Passed:         !eol,
	}}
}

// ─── Kernel Version Check ───

func checkKernelVersion() []Finding {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return []Finding{{
			Category:    "software_versions",
			Severity:    "info",
			CheckID:     "VER_KERNEL",
			Title:       "Kernel version",
			Description: "Could not determine kernel version",
			Passed:      true,
		}}
	}

	version := strings.TrimSpace(string(out))
	major, minor := parseKernelVersion(version)

	severity := "info"
	passed := true
	desc := fmt.Sprintf("Kernel %s", version)

	if major < 4 || (major == 4 && minor < 15) {
		severity = "high"
		passed = false
		desc += " — very old kernel, known vulnerabilities"
	} else if major < 5 || (major == 5 && minor < 4) {
		severity = "medium"
		passed = false
		desc += " — outdated kernel"
	} else {
		desc += " — up to date"
	}

	return []Finding{{
		Category:       "software_versions",
		Severity:       severity,
		CheckID:        "VER_KERNEL",
		Title:          "Kernel version",
		Description:    desc,
		Recommendation: conditionalStr(!passed, "Update the kernel to receive security patches: apt update && apt upgrade", ""),
		Details:        map[string]string{"version": version, "major": fmt.Sprintf("%d", major), "minor": fmt.Sprintf("%d", minor)},
		Passed:         passed,
	}}
}

// ─── Security Updates Check ───

func checkSecurityUpdates() []Finding {
	count := 0
	pkgManager := "unknown"

	if _, err := exec.LookPath("apt"); err == nil {
		pkgManager = "apt"
		out, err := exec.Command("bash", "-c", "apt list --upgradable 2>/dev/null | grep -ci security || true").Output()
		if err == nil {
			count, _ = strconv.Atoi(strings.TrimSpace(string(out)))
		}
	} else if _, err := exec.LookPath("yum"); err == nil {
		pkgManager = "yum"
		out, err := exec.Command("bash", "-c", "yum check-update --security 2>/dev/null | tail -n +3 | grep -c '^' || true").Output()
		if err == nil {
			count, _ = strconv.Atoi(strings.TrimSpace(string(out)))
		}
	} else {
		return []Finding{{
			Category:    "software_versions",
			Severity:    "info",
			CheckID:     "VER_SEC_UPDATES",
			Title:       "Security updates",
			Description: "No supported package manager detected (apt/yum)",
			Passed:      true,
		}}
	}

	severity := "info"
	passed := true
	if count > 10 {
		severity = "critical"
		passed = false
	} else if count > 0 {
		severity = "high"
		passed = false
	}

	return []Finding{{
		Category:       "software_versions",
		Severity:       severity,
		CheckID:        "VER_SEC_UPDATES",
		Title:          "Pending security updates",
		Description:    fmt.Sprintf("%d security update(s) available", count),
		Recommendation: conditionalStr(!passed, fmt.Sprintf("Install security updates: %s", updateCommand(pkgManager)), ""),
		Details:        map[string]string{"count": fmt.Sprintf("%d", count), "package_manager": pkgManager},
		Passed:         passed,
	}}
}

// ─── PHP Version Check ───

func checkPHPVersion() []Finding {
	if _, err := exec.LookPath("php"); err != nil {
		return []Finding{{
			Category:    "software_versions",
			Severity:    "info",
			CheckID:     "VER_PHP",
			Title:       "PHP version",
			Description: "PHP is not installed",
			Passed:      true,
		}}
	}

	out, err := exec.Command("php", "-v").Output()
	if err != nil {
		return []Finding{{
			Category:    "software_versions",
			Severity:    "info",
			CheckID:     "VER_PHP",
			Title:       "PHP version",
			Description: "Could not determine PHP version",
			Passed:      true,
		}}
	}

	version := parsePHPVersion(string(out))
	major, minor := parseMajorMinor(version)

	severity := "info"
	passed := true
	desc := fmt.Sprintf("PHP %s", version)

	if major < 8 || (major == 8 && minor < 1) {
		severity = "critical"
		passed = false
		desc += " — end of life, no security patches"
	} else if major == 8 && minor == 1 {
		severity = "medium"
		passed = false
		desc += " — security-only support, consider upgrading"
	} else {
		desc += " — supported"
	}

	return []Finding{{
		Category:       "software_versions",
		Severity:       severity,
		CheckID:        "VER_PHP",
		Title:          "PHP version",
		Description:    desc,
		Recommendation: conditionalStr(!passed, "Upgrade PHP to a supported version (8.2+)", ""),
		Details:        map[string]string{"version": version, "eol": fmt.Sprintf("%v", !passed)},
		Passed:         passed,
	}}
}

// ─── MySQL/MariaDB Version Check ───

func checkMySQLVersion() []Finding {
	// Try mysql first, then mariadb
	engine := ""
	version := ""

	if out, err := exec.Command("mysql", "--version").Output(); err == nil {
		raw := string(out)
		if strings.Contains(strings.ToLower(raw), "mariadb") {
			engine = "MariaDB"
			version = parseMariaDBVersion(raw)
		} else {
			engine = "MySQL"
			version = parseMySQLVersion(raw)
		}
	} else if out, err := exec.Command("mariadb", "--version").Output(); err == nil {
		engine = "MariaDB"
		version = parseMariaDBVersion(string(out))
	} else {
		return []Finding{{
			Category:    "software_versions",
			Severity:    "info",
			CheckID:     "VER_MYSQL",
			Title:       "Database version",
			Description: "No MySQL or MariaDB detected",
			Passed:      true,
		}}
	}

	major, minor := parseMajorMinor(version)
	severity := "info"
	passed := true
	desc := fmt.Sprintf("%s %s", engine, version)

	if engine == "MySQL" && (major < 8 || (major == 8 && minor < 0)) {
		severity = "high"
		passed = false
		desc += " — end of life"
	} else if engine == "MariaDB" && (major < 10 || (major == 10 && minor < 6)) {
		severity = "high"
		passed = false
		desc += " — end of life"
	} else {
		desc += " — supported"
	}

	return []Finding{{
		Category:       "software_versions",
		Severity:       severity,
		CheckID:        "VER_MYSQL",
		Title:          "Database version",
		Description:    desc,
		Recommendation: conditionalStr(!passed, fmt.Sprintf("Upgrade %s to a supported version", engine), ""),
		Details:        map[string]string{"engine": engine, "version": version, "eol": fmt.Sprintf("%v", !passed)},
		Passed:         passed,
	}}
}

// ─── OpenSSH Version Check ───

func checkOpenSSHVersion() []Finding {
	// ssh -V outputs to stderr
	cmd := exec.Command("ssh", "-V")
	stderr, err := cmd.CombinedOutput()
	if err != nil && len(stderr) == 0 {
		return []Finding{{
			Category:    "software_versions",
			Severity:    "info",
			CheckID:     "VER_OPENSSH",
			Title:       "OpenSSH version",
			Description: "Could not determine OpenSSH version",
			Passed:      true,
		}}
	}

	version := parseOpenSSHVersion(string(stderr))
	major, minor := parseMajorMinor(version)

	severity := "info"
	passed := true
	desc := fmt.Sprintf("OpenSSH %s", version)

	if major < 8 {
		severity = "high"
		passed = false
		desc += " — very old, known vulnerabilities"
	} else if major == 8 && minor < 9 {
		severity = "medium"
		passed = false
		desc += " — outdated"
	} else {
		desc += " — up to date"
	}

	return []Finding{{
		Category:       "software_versions",
		Severity:       severity,
		CheckID:        "VER_OPENSSH",
		Title:          "OpenSSH version",
		Description:    desc,
		Recommendation: conditionalStr(!passed, "Update OpenSSH to the latest version available for your OS", ""),
		Details:        map[string]string{"version": version},
		Passed:         passed,
	}}
}

// ─── Web Server Version Check ───

func checkWebServerVersion() []Finding {
	// Try nginx
	if out, err := exec.Command("nginx", "-v").CombinedOutput(); err == nil || len(out) > 0 {
		version := parseNginxVersion(string(out))
		if version != "" {
			major, minor := parseMajorMinor(version)
			severity := "info"
			passed := true
			desc := fmt.Sprintf("Nginx %s", version)

			if major == 1 && minor < 22 {
				severity = "high"
				passed = false
				desc += " — outdated, known vulnerabilities"
			} else if major == 1 && minor < 24 {
				severity = "medium"
				passed = false
				desc += " — consider upgrading"
			} else {
				desc += " — up to date"
			}

			return []Finding{{
				Category:       "software_versions",
				Severity:       severity,
				CheckID:        "VER_WEBSERVER",
				Title:          "Web server version",
				Description:    desc,
				Recommendation: conditionalStr(!passed, "Upgrade Nginx to the latest stable version", ""),
				Details:        map[string]string{"server": "nginx", "version": version},
				Passed:         passed,
			}}
		}
	}

	// Try apache
	for _, bin := range []string{"apache2", "httpd"} {
		if out, err := exec.Command(bin, "-v").Output(); err == nil {
			version := parseApacheVersion(string(out))
			if version != "" {
				_, minor := parseMajorMinor(version)
				// Apache 2.4.x — check patch level
				parts := strings.Split(version, ".")
				patch := 0
				if len(parts) >= 3 {
					patch, _ = strconv.Atoi(parts[2])
				}

				severity := "info"
				passed := true
				desc := fmt.Sprintf("Apache %s", version)

				_ = minor // Apache is always 2.4.x nowadays
				if patch < 54 {
					severity = "high"
					passed = false
					desc += " — outdated, known vulnerabilities"
				} else {
					desc += " — up to date"
				}

				return []Finding{{
					Category:       "software_versions",
					Severity:       severity,
					CheckID:        "VER_WEBSERVER",
					Title:          "Web server version",
					Description:    desc,
					Recommendation: conditionalStr(!passed, "Upgrade Apache to the latest stable version", ""),
					Details:        map[string]string{"server": "apache", "version": version},
					Passed:         passed,
				}}
			}
		}
	}

	return []Finding{{
		Category:    "software_versions",
		Severity:    "info",
		CheckID:     "VER_WEBSERVER",
		Title:       "Web server version",
		Description: "No web server detected",
		Passed:      true,
	}}
}

// ─── Version Parsing Helpers ───

func osReleaseValue(content, key string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, key+"=") {
			val := strings.TrimPrefix(line, key+"=")
			return strings.Trim(val, "\"")
		}
	}
	return ""
}

func parseKernelVersion(raw string) (int, int) {
	// "5.15.0-91-generic" → 5, 15
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return 0, 0
	}
	major, _ := strconv.Atoi(parts[0])
	minor, _ := strconv.Atoi(parts[1])
	return major, minor
}

func parsePHPVersion(raw string) string {
	// "PHP 8.2.14 (cli) ..." → "8.2.14"
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, "PHP ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return fields[1]
			}
		}
	}
	return "unknown"
}

func parseMySQLVersion(raw string) string {
	// "mysql  Ver 8.0.35 Distrib 8.0.35, ..." → "8.0.35"
	fields := strings.Fields(raw)
	for i, f := range fields {
		if strings.EqualFold(f, "Ver") && i+1 < len(fields) {
			return strings.TrimRight(fields[i+1], ",")
		}
	}
	return "unknown"
}

func parseMariaDBVersion(raw string) string {
	// "mariadb  Ver 15.1 Distrib 10.11.6-MariaDB, ..." → "10.11.6"
	lower := strings.ToLower(raw)
	idx := strings.Index(lower, "distrib ")
	if idx == -1 {
		return "unknown"
	}
	rest := raw[idx+8:]
	fields := strings.FieldsFunc(rest, func(c rune) bool {
		return c == ',' || c == ' ' || c == '-'
	})
	if len(fields) > 0 {
		return fields[0]
	}
	return "unknown"
}

func parseOpenSSHVersion(raw string) string {
	// "OpenSSH_9.2p1 Debian-2+deb12u2, ..." → "9.2"
	for _, part := range strings.Fields(raw) {
		if strings.HasPrefix(part, "OpenSSH_") {
			ver := strings.TrimPrefix(part, "OpenSSH_")
			// Strip trailing "p1" etc
			for i, c := range ver {
				if c != '.' && (c < '0' || c > '9') {
					return ver[:i]
				}
			}
			return ver
		}
	}
	return "unknown"
}

func parseNginxVersion(raw string) string {
	// "nginx version: nginx/1.24.0" → "1.24.0"
	idx := strings.Index(raw, "nginx/")
	if idx == -1 {
		return ""
	}
	rest := raw[idx+6:]
	fields := strings.Fields(rest)
	if len(fields) > 0 {
		return strings.TrimSpace(fields[0])
	}
	return ""
}

func parseApacheVersion(raw string) string {
	// "Server version: Apache/2.4.57 (Debian)" → "2.4.57"
	idx := strings.Index(raw, "Apache/")
	if idx == -1 {
		return ""
	}
	rest := raw[idx+7:]
	fields := strings.FieldsFunc(rest, func(c rune) bool {
		return c == ' ' || c == '(' || c == ')'
	})
	if len(fields) > 0 {
		return strings.TrimSpace(fields[0])
	}
	return ""
}

func parseMajorMinor(version string) (int, int) {
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return 0, 0
	}
	major, _ := strconv.Atoi(parts[0])
	minor, _ := strconv.Atoi(parts[1])
	return major, minor
}

func conditionalStr(cond bool, yes, no string) string {
	if cond {
		return yes
	}
	return no
}

func updateCommand(pkgManager string) string {
	if pkgManager == "apt" {
		return "apt update && apt upgrade -y"
	}
	return "yum update -y"
}
