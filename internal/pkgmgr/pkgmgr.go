// Package pkgmgr asks the host's package manager one question — is this package
// current? — and is careful to distinguish not knowing from knowing it is fine.
//
// That distinction is the whole point. The agent used to answer this with a
// bool, where "no update pending" and "could not tell" were the same value, and
// the panel then used that answer to suppress CVE advisories for a package. A
// package the package manager had never heard of therefore bought itself
// silence, which is the opposite of what a security tool should do when it
// cannot see. Verdict has a third value for exactly that case, and a caller that
// suppresses an alert must act only on Current.
package pkgmgr

import (
	"os/exec"
	"strings"
)

// Verdict is what the package manager says about a package.
type Verdict string

const (
	// Current means the manager knows this package and has no update for it.
	Current Verdict = "current"
	// UpdatePending means the manager has a newer version available.
	UpdatePending Verdict = "update_pending"
	// Unknown means we could not ask, or the manager does not know the package.
	// Never treat it as Current.
	Unknown Verdict = "unknown"
)

// Result is the answer for one package, naming which manager and which package
// name produced it so the reading can be audited rather than trusted.
type Result struct {
	Verdict Verdict
	Manager string
	Package string
}

// unknown is the zero answer, carrying whichever manager was detected.
func unknown(manager string) Result {
	return Result{Verdict: Unknown, Manager: manager}
}

// Manager returns the host's package manager: "apt", "dnf", "yum", or "" if none
// is present (a source build, a distroless container).
func Manager() string {
	for _, m := range []string{"apt", "dnf", "yum"} {
		if _, err := exec.LookPath(m); err == nil {
			return m
		}
	}
	return ""
}

// Query asks about each candidate package name in order and returns the first
// answer from a package that is actually installed. Candidates exist because the
// same software is named differently across distributions — apache2 and httpd,
// mysql-server and mariadb-server.
//
// If no candidate is installed, the answer is Unknown, not Current: software can
// be present without the package manager knowing it, built from source or
// vendored into a container, and in that case we have no verdict to offer.
func Query(candidates ...string) Result {
	manager := Manager()
	if manager == "" {
		return unknown("")
	}

	for _, pkg := range candidates {
		if pkg == "" {
			continue
		}
		if !installed(manager, pkg) {
			continue
		}
		r := Result{Manager: manager, Package: pkg}
		pending, ok := updatePending(manager, pkg)
		switch {
		case !ok:
			r.Verdict = Unknown
		case pending:
			r.Verdict = UpdatePending
		default:
			r.Verdict = Current
		}
		return r
	}

	return unknown(manager)
}

// installed reports whether the manager knows the package as installed.
func installed(manager, pkg string) bool {
	switch manager {
	case "apt":
		out, err := exec.Command("dpkg-query", "-W", "-f=${Status}", pkg).Output()
		if err != nil {
			return false
		}
		return ParseDpkgInstalled(string(out))
	case "dnf", "yum":
		return exec.Command("rpm", "-q", pkg).Run() == nil
	}
	return false
}

// updatePending reports whether a newer version is available. The second return
// is false when the question could not be answered at all, which the caller must
// not read as "no update".
func updatePending(manager, pkg string) (pending, ok bool) {
	switch manager {
	case "apt":
		out, err := exec.Command("apt-get", "--just-print", "upgrade", pkg).Output()
		if err != nil {
			// apt-get refuses when the package is held or unknown; fall back to
			// the upgradable list, which is advisory but better than guessing.
			listed, lerr := exec.Command("apt", "list", "--upgradable").Output()
			if lerr != nil {
				return false, false
			}
			return ParseAptUpgradable(string(listed), pkg), true
		}
		return ParseAptJustPrint(string(out), pkg), true
	case "dnf", "yum":
		err := exec.Command(manager, "check-update", "--quiet", pkg).Run()
		if err == nil {
			return false, true // exit 0: nothing to update
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			switch exitErr.ExitCode() {
			case 100:
				return true, true // updates available
			case 0:
				return false, true
			}
		}
		return false, false
	}
	return false, false
}

// ParseDpkgInstalled reads a "${Status}" field from dpkg-query. Only the
// "installed" state counts: a package can be known to dpkg as deinstalled,
// config-files or half-configured, none of which means it is on the host.
func ParseDpkgInstalled(status string) bool {
	fields := strings.Fields(strings.TrimSpace(status))
	if len(fields) < 3 {
		return false
	}
	return fields[0] == "install" && fields[2] == "installed"
}

// ParseAptUpgradable reports whether pkg appears in "apt list --upgradable".
//
// Matched on the package name up to the slash, not as a line prefix: a prefix
// match reports an update to php8.3-cli as an update to php8.3, and "nginx"
// would match "nginx-common".
func ParseAptUpgradable(output, pkg string) bool {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Listing") {
			continue
		}
		name := line
		if i := strings.Index(name, "/"); i >= 0 {
			name = name[:i]
		}
		if name == pkg {
			return true
		}
	}
	return false
}

// ParseAptJustPrint reads a dry-run "apt-get upgrade" plan and reports whether
// pkg is among the packages it would change.
//
// Lines look like "Inst nginx [1.24.0-1] (1.26.0-1 Ubuntu:24.04 [amd64])".
func ParseAptJustPrint(output, pkg string) bool {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 || fields[0] != "Inst" {
			continue
		}
		if fields[1] == pkg {
			return true
		}
	}
	return false
}
