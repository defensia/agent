package collector

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/defensia/agent/internal/monitor"
	"github.com/defensia/agent/internal/pkgmgr"
	"github.com/defensia/agent/internal/webserver"
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

	// PkgVerdict is what the host's package manager says: "current",
	// "update_pending", or "unknown". Status above is a version threshold
	// compiled into this agent and goes stale the moment upstream moves; this is
	// the live answer from the machine itself.
	//
	// The distinction matters because the panel suppresses CVE advisories for
	// distribution-packaged software the vendor has already patched — Ubuntu
	// backports security fixes into PHP 8.3.6 without ever moving the version, so
	// comparing upstream numbers is meaningless there. Suppression must act only
	// on "current". "unknown" means we could not ask, and a package we cannot see
	// must never buy itself silence.
	//
	// omitempty throughout: an older panel ignores these, and a newer panel can
	// tell an agent that does not send them from one that sent "unknown".
	PkgVerdict string `json:"pkg_verdict,omitempty"`
	PkgManager string `json:"pkg_manager,omitempty"` // apt, dnf, yum
	PkgName    string `json:"pkg_name,omitempty"`    // the package actually consulted
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

// packageCandidates maps an inventory entry to the package names that could
// provide it, most specific first. The same software is named differently across
// distributions — apache2 and httpd, mysql-server and mariadb-server — and PHP
// is named per branch, so the branch is read back out of the row.
//
// A name with no candidates is left unverified rather than guessed at.
func packageCandidates(sw KeySoftware) []string {
	name := sw.Name

	switch {
	case strings.HasPrefix(name, "PHP-LSAPI"):
		// OpenLiteSpeed installs lsphp84 and friends from the LiteSpeed
		// repository, which apt does manage.
		if b := branchCompact(sw.Version); b != "" {
			return []string{"lsphp" + b}
		}
		return nil
	case strings.HasPrefix(name, "PHP-FPM"):
		if b := branchDotted(sw.Version); b != "" {
			return []string{"php" + b + "-fpm", "php-fpm"}
		}
		return []string{"php-fpm"}
	case name == "PHP":
		if b := branchDotted(sw.Version); b != "" {
			return []string{"php" + b + "-cli", "php" + b + "-common", "php-cli", "php"}
		}
		return []string{"php-cli", "php"}
	}

	switch name {
	case "Linux Kernel":
		return []string{"linux-image-generic", "linux-image-amd64", "kernel", "kernel-core"}
	case "OpenSSH":
		return []string{"openssh-server", "openssh"}
	case "Nginx":
		return []string{"nginx", "nginx-core"}
	case "Apache":
		return []string{"apache2", "httpd"}
	case "LiteSpeed":
		return []string{"openlitespeed", "lsws"}
	case "Caddy":
		return []string{"caddy"}
	case "MySQL":
		return []string{"mysql-server", "mysql-community-server"}
	case "MariaDB":
		return []string{"mariadb-server"}
	case "Node.js":
		return []string{"nodejs"}
	case "Python":
		return []string{"python3", "python3-minimal"}
	case "Docker":
		return []string{"docker-ce", "docker.io", "docker"}
	}

	return nil
}

// branchDotted turns "8.3.36" into "8.3"; branchCompact turns it into "83",
// which is how LiteSpeed names its packages.
func branchDotted(version string) string {
	major, minor := parseMajorMinor(version)
	if major == 0 {
		return ""
	}
	return strconv.Itoa(major) + "." + strconv.Itoa(minor)
}

func branchCompact(version string) string {
	major, minor := parseMajorMinor(version)
	if major == 0 {
		return ""
	}
	return strconv.Itoa(major) + strconv.Itoa(minor)
}

// withPackageVerdict asks the package manager about each entry and records the
// answer. The version-threshold Status is left untouched: it still drives the
// existing panel display, and replacing it in the same change would conflate a
// new signal with a change of meaning for an old one.
func withPackageVerdict(sw []KeySoftware) []KeySoftware {
	// One manager lookup for the whole pass; Query would otherwise re-detect it
	// per package.
	if pkgmgr.Manager() == "" {
		return sw
	}

	for i := range sw {
		candidates := packageCandidates(sw[i])
		if len(candidates) == 0 {
			continue
		}
		r := pkgmgr.Query(candidates...)
		sw[i].PkgVerdict = string(r.Verdict)
		sw[i].PkgManager = r.Manager
		sw[i].PkgName = r.Package
	}

	return sw
}

func collectKeySoftware() []KeySoftware {
	var sw []KeySoftware
	sw = append(sw, detectKernel())
	sw = append(sw, detectOpenSSH())
	sw = append(sw, detectWebServer())
	sw = append(sw, detectPHP())
	sw = append(sw, detectServingPHP()...)
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

	return withPackageVerdict(result)
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

// detectWebServer reports the web server that actually serves this host.
//
// It asks internal/webserver, the same resolver the heartbeat uses, rather than
// walking installed packages in the order nginx, apache2, httpd as it used to.
// That order reported an idle Apache package as the web server on an
// OpenLiteSpeed box — so the inventory said "Apache 2.4.58" while the heartbeat
// said "litespeed", about the same machine at the same time, and the Apache
// version was the one that got matched against advisories.
func detectWebServer() KeySoftware {
	name, version := webserver.Detect()
	display := webserver.DisplayName(name)
	if display == "" || version == "" {
		return KeySoftware{Name: "Web Server", Version: "-", Status: "not_installed", Category: "webserver"}
	}

	return KeySoftware{Name: display, Version: version, Status: webServerStatus(name, version), Category: "webserver"}
}

// webServerStatus keeps the pre-existing per-server verdicts. LiteSpeed and
// Caddy have none, so they report "unknown" rather than claiming to be current:
// the whole key_software status rule is replaced by the real package manager
// signal in a separate change, and inventing a threshold here would only have to
// be removed again.
func webServerStatus(name, version string) string {
	major, minor := parseMajorMinor(version)
	switch name {
	case "nginx":
		if major == 1 && minor < 22 {
			return "eol"
		}
		if major == 1 && minor < 24 {
			return "outdated"
		}
		return "up_to_date"
	case "apache":
		patch := 0
		if parts := strings.Split(version, "."); len(parts) >= 3 {
			patch, _ = strconv.Atoi(parts[2])
		}
		if patch < 54 {
			return "outdated"
		}
		return "up_to_date"
	}

	return "unknown"
}

func detectPHP() KeySoftware {
	if _, err := exec.LookPath("php"); err != nil {
		return KeySoftware{Name: "PHP", Version: "-", Status: "not_installed", Category: "runtime"}
	}
	version := ""
	if out, err := exec.Command("php", "-r", "echo PHP_VERSION;").Output(); err == nil {
		version = phpVersionFromEcho(string(out))
	}
	if version == "" {
		// Startup warnings can swallow the echo output; the banner survives them.
		if out, err := exec.Command("php", "-v").Output(); err == nil {
			version = parsePHPBannerVersion(string(out))
		}
	}
	if version == "" {
		return KeySoftware{Name: "PHP", Version: "-", Status: "not_installed", Category: "runtime"}
	}
	// Name stays "PHP" so existing fleet queries and audit history keep working;
	// the web facing builds are reported alongside it, one row each.
	return KeySoftware{Name: "PHP", Version: version, Status: phpBranchStatus(version), Category: "runtime"}
}

// detectServingPHP reports the PHP builds that actually answer HTTP requests, one
// entry per distinct version so each branch is version matched on its own instead
// of hiding behind the CLI reading.
//
// Two SAPIs are covered and named apart, because "which PHP is installed" and
// "which PHP serves" are different questions and conflating them is what made us
// report a patched CLI as the server's runtime on an OpenLiteSpeed host.
func detectServingPHP() []KeySoftware {
	var sw []KeySoftware
	used := make(map[string]bool)
	for _, r := range servingPHPRuntimes() {
		name := r.sapi
		if major, minor := parseMajorMinor(r.version); major > 0 {
			name += " " + strconv.Itoa(major) + "." + strconv.Itoa(minor)
		}
		if used[name] {
			// Two builds of the same branch (system plus Remi/Sury, say): keep both
			// rows distinguishable for the panel, which keys by name.
			name = r.sapi + " " + r.version
		}
		used[name] = true
		sw = append(sw, KeySoftware{Name: name, Version: r.version, Status: phpBranchStatus(r.version), Category: "runtime"})
	}
	return sw
}

// phpBranchStatus is the pre-existing major/minor verdict, kept as-is so this
// change stays about detection. The whole key_software status rule is replaced by
// the real package manager signal in a separate change.
// phpEOLBranches are the branches upstream no longer issues security fixes for,
// newest first. php.net's own schedule, not a guess:
//
//	8.1  security support ended 31 Dec 2025
//	8.0  31 Nov 2023
//	7.4  28 Nov 2022
//
// This is load-bearing rather than cosmetic. The panel exempts a package from
// CVE matching when the host's package manager calls it current, and a dead
// branch is exactly where "current" means "the repository has nothing newer",
// not "this is fine" — Sury still packages PHP 5.6. Only "eol" overrides that
// exemption, so a dead branch misfiled as merely outdated is silently exempt
// from every PHP advisory in the catalogue.
//
// A branch that falls out of support has to be added here. 8.1 was not, and sat
// as "outdated" for ten months after upstream stopped patching it.
var phpEOLBranches = map[string]bool{
	"8.1": true,
	"8.0": true,
	"7.4": true,
	"7.3": true,
	"7.2": true,
	"7.1": true,
	"7.0": true,
	"5.6": true,
	"5.5": true,
	"5.4": true,
}

// phpBranchStatus classifies a PHP version for the software inventory.
func phpBranchStatus(version string) string {
	major, minor := parseMajorMinor(version)
	if major == 0 {
		return "unknown"
	}

	branch := strconv.Itoa(major) + "." + strconv.Itoa(minor)
	if phpEOLBranches[branch] {
		return "eol"
	}

	// Anything older than the oldest branch we name is certainly dead too.
	if major < 5 || (major == 5 && minor < 4) {
		return "eol"
	}

	// A branch newer than this build knows about must not be called dead.
	return "up_to_date"
}

// ─── Serving PHP Resolution ───

// phpFPMGlobs are the directories distributions and control panels install
// php-fpm into. Globbed rather than hardcoded so that multi version hosts
// (Remi, cPanel EA, Plesk, CloudLinux alt-php) report every pool build.
var phpFPMGlobs = []string{
	"/usr/sbin/php-fpm*",
	"/usr/sbin/php*-fpm",
	"/usr/bin/php-fpm*",
	"/usr/local/sbin/php-fpm*",
	"/usr/local/sbin/php*-fpm",
	"/usr/local/php*/sbin/php-fpm",
	"/opt/remi/php*/root/usr/sbin/php-fpm",
	"/opt/cpanel/ea-php*/root/usr/sbin/php-fpm",
	"/opt/plesk/php/*/sbin/php-fpm",
	"/opt/alt/php*/usr/sbin/php-fpm",
}

// phpLSAPIGlobs are LiteSpeed's lsphp locations. OpenLiteSpeed and CyberPanel
// install one tree per branch and serve through LSAPI, not FPM, so none of the
// php-fpm patterns above ever match on those hosts — which is why every
// OpenLiteSpeed server reported only its CLI binary.
var phpLSAPIGlobs = []string{
	"/usr/local/lsws/lsphp*/bin/lsphp",
	"/usr/local/lsws/fcgi-bin/lsphp*",
}

// maxServingPHPBinaries caps how many binaries get executed, so a host with a
// pathological number of installed branches cannot stall the audit.
const maxServingPHPBinaries = 32

// phpRuntime is one serving PHP build: its version and the SAPI that runs it.
type phpRuntime struct {
	version string
	sapi    string
}

// phpFPMBinaryNames lists the php-fpm command names worth a PATH lookup.
func phpFPMBinaryNames() []string {
	names := []string{"php-fpm"}
	for _, branch := range phpBranchesNewestFirst {
		compact := strings.ReplaceAll(branch, ".", "")
		names = append(names,
			"php-fpm"+branch,
			"php"+branch+"-fpm",
			"php-fpm"+compact,
			"php"+compact+"-fpm",
		)
	}
	return names
}

// phpLSAPIBinaryNames lists the lsphp command names worth a PATH lookup.
// LiteSpeed names its binaries with the branch compacted: lsphp84, not lsphp8.4.
func phpLSAPIBinaryNames() []string {
	names := []string{"lsphp"}
	for _, branch := range phpBranchesNewestFirst {
		names = append(names, "lsphp"+strings.ReplaceAll(branch, ".", ""))
	}
	return names
}

// phpBranchesNewestFirst drives the order in which branch suffixed binaries are
// probed, so the result is stable across runs.
var phpBranchesNewestFirst = []string{
	"8.5", "8.4", "8.3", "8.2", "8.1", "8.0",
	"7.4", "7.3", "7.2", "7.1", "7.0", "5.6",
}

// servingPHPBinaries resolves the serving PHP binaries present on the host to
// absolute paths, deduplicated by symlink target so that php-fpm and php-fpm8.3
// pointing at the same build are probed once. The SAPI each path belongs to is
// carried along, since that is not recoverable from the version banner alone.
func servingPHPBinaries() ([]string, map[string]string) {
	var bins []string
	sapiOf := make(map[string]string)
	seen := make(map[string]bool)

	add := func(path, sapi string) {
		if len(bins) >= maxServingPHPBinaries {
			return
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			resolved = path
		}
		if seen[resolved] {
			return
		}
		info, err := os.Stat(resolved)
		if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
			return
		}
		seen[resolved] = true
		bins = append(bins, resolved)
		sapiOf[resolved] = sapi
	}

	// Binaries on PATH first, including the branch suffixed names the distro
	// packages install when several branches coexist.
	for _, name := range phpFPMBinaryNames() {
		if path, err := exec.LookPath(name); err == nil {
			add(path, "PHP-FPM")
		}
	}
	for _, name := range phpLSAPIBinaryNames() {
		if path, err := exec.LookPath(name); err == nil {
			add(path, "PHP-LSAPI")
		}
	}
	for _, group := range []struct {
		globs []string
		sapi  string
	}{
		{phpFPMGlobs, "PHP-FPM"},
		{phpLSAPIGlobs, "PHP-LSAPI"},
	} {
		for _, pattern := range group.globs {
			matches, err := filepath.Glob(pattern)
			if err != nil {
				continue
			}
			sort.Strings(matches)
			for _, m := range matches {
				add(m, group.sapi)
			}
		}
	}
	return bins, sapiOf
}

// servingPHPRuntimes runs "<bin> -v" on every serving PHP binary found and
// returns the distinct versions, newest first. Both php-fpm and lsphp print the
// standard PHP banner, so one parser covers both.
func servingPHPRuntimes() []phpRuntime {
	bins, sapiOf := servingPHPBinaries()
	var runtimes []phpRuntime
	seen := make(map[string]bool)
	for _, bin := range bins {
		out, err := exec.Command(bin, "-v").Output()
		if err != nil && len(out) == 0 {
			continue
		}
		version := parsePHPBannerVersion(string(out))
		if version == "" {
			continue
		}
		key := sapiOf[bin] + " " + version
		if seen[key] {
			continue
		}
		seen[key] = true
		runtimes = append(runtimes, phpRuntime{version: version, sapi: sapiOf[bin]})
	}
	sort.Slice(runtimes, func(i, j int) bool {
		if runtimes[i].sapi != runtimes[j].sapi {
			return runtimes[i].sapi < runtimes[j].sapi
		}
		return runtimes[i].version > runtimes[j].version
	})
	return runtimes
}

// ─── PHP Output Parsing ───

// parsePHPBannerVersion extracts the version from "php -v", "php-fpm -v" or
// "lsphp -v" output. Startup warnings are printed before the banner and also
// begin with "PHP ", so only a line whose second field starts with a digit is
// accepted.
func parsePHPBannerVersion(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "PHP ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if v := fields[1]; v[0] >= '0' && v[0] <= '9' {
			return v
		}
	}
	return ""
}

// phpVersionFromEcho picks the version out of "php -r 'echo PHP_VERSION;'",
// whose output can be preceded by startup warnings on stdout. The version is the
// last line starting with a digit; a warning line never does.
func phpVersionFromEcho(raw string) string {
	lines := strings.Split(raw, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		if line[0] >= '0' && line[0] <= '9' {
			return line
		}
	}
	return ""
}

func mariaDBStatus(version string) string {
	major, minor := parseMajorMinor(version)
	if major == 0 {
		return "unknown"
	}
	// MariaDB EOL: 10.x below 10.6, or any single-digit major
	if major < 10 || (major == 10 && minor < 6) {
		return "eol"
	}
	return "up_to_date"
}

func detectMySQL() KeySoftware {
	// Try mysql
	if out, err := exec.Command("mysql", "--version").Output(); err == nil {
		raw := string(out)
		if strings.Contains(strings.ToLower(raw), "mariadb") {
			version := parseMariaDBVer(raw)
			status := mariaDBStatus(version)
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
		status := mariaDBStatus(version)
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
		// No CLI found — try Docker socket API for version
		if v := monitor.DockerVersion(); v != "" {
			major, _ := parseMajorMinor(v)
			status := "up_to_date"
			if major < 24 {
				status = "outdated"
			}
			return KeySoftware{Name: "Docker", Version: v, Status: status, Category: "container"}
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
	// Classic format: "mysql  Ver 15.1 Distrib 10.6.x-MariaDB"
	idx := strings.Index(lower, "distrib ")
	if idx != -1 {
		rest := raw[idx+8:]
		fields := strings.FieldsFunc(rest, func(c rune) bool {
			return c == ',' || c == ' ' || c == '-'
		})
		if len(fields) > 0 {
			return fields[0]
		}
	}
	// New format (MariaDB 11+): "mariadb from 11.8.9-MariaDB, client 15.2 ..."
	idx = strings.Index(lower, " from ")
	if idx != -1 {
		rest := raw[idx+6:]
		fields := strings.FieldsFunc(rest, func(c rune) bool {
			return c == ',' || c == ' ' || c == '-'
		})
		if len(fields) > 0 {
			return fields[0]
		}
	}
	return "unknown"
}
