package collector

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/defensia/agent/internal/monitor"
)

// AuditResult is the payload sent to the server.
type AuditResult struct {
	Summary     Summary       `json:"summary"`
	KeySoftware []KeySoftware `json:"key_software"`
	Packages    []Package     `json:"packages,omitempty"`
}

// Summary holds aggregate software inventory stats.
type Summary struct {
	TotalPackages    int    `json:"total_packages"`
	UpdatesAvailable int    `json:"updates_available"`
	SecurityUpdates  int    `json:"security_updates"`
	LastSystemUpdate string `json:"last_system_update,omitempty"`
}

// KeySoftware represents a single important piece of software.
type KeySoftware struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Status   string `json:"status"`   // up_to_date, outdated, eol, not_installed
	Category string `json:"category"` // system, runtime, database, webserver, security, container
}

// Package represents a single installed package.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Collect gathers the full software inventory from the system.
func Collect() AuditResult {
	result := AuditResult{}

	result.Packages = collectInstalledPackages()
	result.Summary.TotalPackages = len(result.Packages)
	result.Summary.UpdatesAvailable = countUpdatesAvailable()
	result.Summary.SecurityUpdates = countSecurityUpdates()
	result.Summary.LastSystemUpdate = getLastUpdateTime()
	result.KeySoftware = collectKeySoftware()

	return result
}

// ─── Package Collection ───

func collectInstalledPackages() []Package {
	// Try dpkg (Debian/Ubuntu)
	if _, err := exec.LookPath("dpkg-query"); err == nil {
		out, err := exec.Command("dpkg-query", "-W", "-f=${Package}\t${Version}\n").Output()
		if err == nil {
			return parseTSVPackages(string(out))
		}
	}

	// Try rpm (RHEL/CentOS)
	if _, err := exec.LookPath("rpm"); err == nil {
		out, err := exec.Command("rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\n").Output()
		if err == nil {
			return parseTSVPackages(string(out))
		}
	}

	return nil
}

func parseTSVPackages(output string) []Package {
	var packages []Package
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) == 2 {
			packages = append(packages, Package{Name: parts[0], Version: parts[1]})
		}
	}
	return packages
}

// ─── Update Counts ───

func countUpdatesAvailable() int {
	if _, err := exec.LookPath("apt"); err == nil {
		out, _ := exec.Command("bash", "-c", "apt list --upgradable 2>/dev/null | grep -c 'upgradable' || echo 0").Output()
		n, _ := strconv.Atoi(strings.TrimSpace(string(out)))
		return n
	}
	if _, err := exec.LookPath("yum"); err == nil {
		out, _ := exec.Command("bash", "-c", "yum check-update 2>/dev/null | tail -n +3 | grep -c '^' || echo 0").Output()
		n, _ := strconv.Atoi(strings.TrimSpace(string(out)))
		return n
	}
	return 0
}

func countSecurityUpdates() int {
	if _, err := exec.LookPath("apt"); err == nil {
		out, _ := exec.Command("bash", "-c", "apt list --upgradable 2>/dev/null | grep -ci security || echo 0").Output()
		n, _ := strconv.Atoi(strings.TrimSpace(string(out)))
		return n
	}
	if _, err := exec.LookPath("yum"); err == nil {
		out, _ := exec.Command("bash", "-c", "yum check-update --security 2>/dev/null | tail -n +3 | grep -c '^' || echo 0").Output()
		n, _ := strconv.Atoi(strings.TrimSpace(string(out)))
		return n
	}
	return 0
}

func getLastUpdateTime() string {
	// Try apt history log
	for _, path := range []string{"/var/log/apt/history.log", "/var/log/dpkg.log"} {
		if info, err := os.Stat(path); err == nil {
			return info.ModTime().Format(time.RFC3339)
		}
	}
	// Try yum history log
	if info, err := os.Stat("/var/log/yum.log"); err == nil {
		return info.ModTime().Format(time.RFC3339)
	}
	return ""
}

// ─── Key Software Detection ───

func collectKeySoftware() []KeySoftware {
	var sw []KeySoftware
	sw = append(sw, detectKernel())
	sw = append(sw, detectOpenSSH())
	sw = append(sw, detectWebServer())
	sw = append(sw, detectPHP())
	sw = append(sw, detectMySQL())
	sw = append(sw, detectNode())
	sw = append(sw, detectPython())
	sw = append(sw, detectDocker())

	// Filter out not_installed items
	var result []KeySoftware
	for _, s := range sw {
		if s.Status != "not_installed" {
			result = append(result, s)
		}
	}
	return result
}

func detectKernel() KeySoftware {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return KeySoftware{Name: "Linux Kernel", Version: "-", Status: "not_installed", Category: "system"}
	}
	version := strings.TrimSpace(string(out))
	major, minor := parseMajorMinor(version)
	status := "up_to_date"
	if major < 4 || (major == 4 && minor < 15) {
		status = "eol"
	} else if major < 5 || (major == 5 && minor < 4) {
		status = "outdated"
	}
	return KeySoftware{Name: "Linux Kernel", Version: version, Status: status, Category: "system"}
}

func detectOpenSSH() KeySoftware {
	out, _ := exec.Command("ssh", "-V").CombinedOutput()
	if len(out) == 0 {
		return KeySoftware{Name: "OpenSSH", Version: "-", Status: "not_installed", Category: "security"}
	}
	version := parseSSHVersion(string(out))
	major, minor := parseMajorMinor(version)
	status := "up_to_date"
	if major < 8 {
		status = "eol"
	} else if major == 8 && minor < 9 {
		status = "outdated"
	}
	return KeySoftware{Name: "OpenSSH", Version: version, Status: status, Category: "security"}
}

func detectWebServer() KeySoftware {
	// Nginx
	if out, err := exec.Command("nginx", "-v").CombinedOutput(); err == nil || len(out) > 0 {
		version := parseNginxVer(string(out))
		if version != "" {
			major, minor := parseMajorMinor(version)
			status := "up_to_date"
			if major == 1 && minor < 22 {
				status = "eol"
			} else if major == 1 && minor < 24 {
				status = "outdated"
			}
			return KeySoftware{Name: "Nginx", Version: version, Status: status, Category: "webserver"}
		}
	}
	// Apache
	for _, bin := range []string{"apache2", "httpd"} {
		if out, err := exec.Command(bin, "-v").Output(); err == nil {
			version := parseApacheVer(string(out))
			if version != "" {
				parts := strings.Split(version, ".")
				patch := 0
				if len(parts) >= 3 {
					patch, _ = strconv.Atoi(parts[2])
				}
				status := "up_to_date"
				if patch < 54 {
					status = "outdated"
				}
				return KeySoftware{Name: "Apache", Version: version, Status: status, Category: "webserver"}
			}
		}
	}
	return KeySoftware{Name: "Web Server", Version: "-", Status: "not_installed", Category: "webserver"}
}

func detectPHP() KeySoftware {
	if _, err := exec.LookPath("php"); err != nil {
		return KeySoftware{Name: "PHP", Version: "-", Status: "not_installed", Category: "runtime"}
	}
	out, err := exec.Command("php", "-r", "echo PHP_VERSION;").Output()
	if err != nil {
		return KeySoftware{Name: "PHP", Version: "-", Status: "not_installed", Category: "runtime"}
	}
	version := strings.TrimSpace(string(out))
	major, minor := parseMajorMinor(version)
	status := "up_to_date"
	if major < 8 || (major == 8 && minor < 1) {
		status = "eol"
	} else if major == 8 && minor == 1 {
		status = "outdated"
	}
	return KeySoftware{Name: "PHP", Version: version, Status: status, Category: "runtime"}
}

func detectMySQL() KeySoftware {
	// Try mysql
	if out, err := exec.Command("mysql", "--version").Output(); err == nil {
		raw := string(out)
		if strings.Contains(strings.ToLower(raw), "mariadb") {
			version := parseMariaDBVer(raw)
			major, minor := parseMajorMinor(version)
			status := "up_to_date"
			if major < 10 || (major == 10 && minor < 6) {
				status = "eol"
			}
			return KeySoftware{Name: "MariaDB", Version: version, Status: status, Category: "database"}
		}
		version := parseMySQLVer(raw)
		major, _ := parseMajorMinor(version)
		status := "up_to_date"
		if major < 8 {
			status = "eol"
		}
		return KeySoftware{Name: "MySQL", Version: version, Status: status, Category: "database"}
	}
	// Try mariadb
	if out, err := exec.Command("mariadb", "--version").Output(); err == nil {
		version := parseMariaDBVer(string(out))
		major, minor := parseMajorMinor(version)
		status := "up_to_date"
		if major < 10 || (major == 10 && minor < 6) {
			status = "eol"
		}
		return KeySoftware{Name: "MariaDB", Version: version, Status: status, Category: "database"}
	}
	return KeySoftware{Name: "Database", Version: "-", Status: "not_installed", Category: "database"}
}

func detectNode() KeySoftware {
	if _, err := exec.LookPath("node"); err != nil {
		return KeySoftware{Name: "Node.js", Version: "-", Status: "not_installed", Category: "runtime"}
	}
	out, err := exec.Command("node", "--version").Output()
	if err != nil {
		return KeySoftware{Name: "Node.js", Version: "-", Status: "not_installed", Category: "runtime"}
	}
	version := strings.TrimPrefix(strings.TrimSpace(string(out)), "v")
	major, _ := parseMajorMinor(version)
	status := "up_to_date"
	if major < 18 {
		status = "eol"
	} else if major == 18 || major == 19 {
		status = "outdated"
	}
	return KeySoftware{Name: "Node.js", Version: version, Status: status, Category: "runtime"}
}

func detectPython() KeySoftware {
	for _, bin := range []string{"python3", "python"} {
		if _, err := exec.LookPath(bin); err == nil {
			out, err := exec.Command(bin, "--version").Output()
			if err == nil {
				// "Python 3.11.2" → "3.11.2"
				version := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(out)), "Python "))
				major, minor := parseMajorMinor(version)
				status := "up_to_date"
				if major < 3 || (major == 3 && minor < 9) {
					status = "eol"
				} else if major == 3 && minor < 11 {
					status = "outdated"
				}
				return KeySoftware{Name: "Python", Version: version, Status: status, Category: "runtime"}
			}
		}
	}
	return KeySoftware{Name: "Python", Version: "-", Status: "not_installed", Category: "runtime"}
}

func detectDocker() KeySoftware {
	dockerBin := monitor.FindDockerBinary()
	if dockerBin == "" {
		// No CLI found — check if daemon socket exists (Docker running but CLI not in PATH)
		if monitor.HasDockerSocket() {
			return KeySoftware{Name: "Docker", Version: "unknown", Status: "up_to_date", Category: "container"}
		}
		return KeySoftware{Name: "Docker", Version: "-", Status: "not_installed", Category: "container"}
	}
	out, err := exec.Command(dockerBin, "--version").Output()
	if err != nil {
		return KeySoftware{Name: "Docker", Version: "-", Status: "not_installed", Category: "container"}
	}
	// "Docker version 24.0.7, build afdd53b" → "24.0.7"
	raw := string(out)
	version := "unknown"
	if idx := strings.Index(raw, "version "); idx != -1 {
		rest := raw[idx+8:]
		if comma := strings.Index(rest, ","); comma != -1 {
			version = strings.TrimSpace(rest[:comma])
		}
	}
	major, _ := parseMajorMinor(version)
	status := "up_to_date"
	if major < 24 {
		status = "outdated"
	}
	return KeySoftware{Name: "Docker", Version: version, Status: status, Category: "container"}
}

// ─── Parsing Helpers ───

func parseMajorMinor(version string) (int, int) {
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return 0, 0
	}
	major, _ := strconv.Atoi(parts[0])
	minor, _ := strconv.Atoi(parts[1])
	return major, minor
}

func parseSSHVersion(raw string) string {
	for _, part := range strings.Fields(raw) {
		if strings.HasPrefix(part, "OpenSSH_") {
			ver := strings.TrimPrefix(part, "OpenSSH_")
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

func parseNginxVer(raw string) string {
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

func parseApacheVer(raw string) string {
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

func parseMySQLVer(raw string) string {
	fields := strings.Fields(raw)
	for i, f := range fields {
		if strings.EqualFold(f, "Ver") && i+1 < len(fields) {
			return strings.TrimRight(fields[i+1], ",")
		}
	}
	return "unknown"
}

func parseMariaDBVer(raw string) string {
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
