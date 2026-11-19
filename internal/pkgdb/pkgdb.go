// Package pkgdb reads which packages a machine has installed, and at what
// version, straight out of the package manager's own database file.
//
// It exists because every other way the agent learns a version runs a program:
// `php -v`, `nginx -v`, `dpkg-query`. That works on a host and is wrong in a
// container, where those binaries belong to the agent's own image rather than
// to the machine being reported on. Running the node's binary instead would mean
// chroot or nsenter into the node — intrusive, and unnecessary, because the
// version is written down in a file we can simply read.
//
// Two formats are supported because two are what the fleet runs:
//
//   - dpkg (/var/lib/dpkg/status): Debian, Ubuntu and derivatives.
//   - apk (/lib/apk/db/installed): Alpine.
//
// RPM is deliberately absent rather than half-implemented. AlmaLinux 8 keeps its
// database in Berkeley DB and 9 and 10 in rpmdb.sqlite (measured at 14 and 20 MB,
// in WAL mode), and the agent builds with CGO_ENABLED=0 everywhere, so there is
// no SQLite driver available to it. Reporting nothing on an RPM node is honest;
// guessing from a filename would not be.
package pkgdb

import "strings"

// Format names where a reading came from, so a disputed version can be audited
// rather than trusted.
type Format string

const (
	Dpkg    Format = "dpkg"
	Apk     Format = "apk"
	Unknown Format = ""
)

// DB is the installed-package set of one machine: package name to version.
type DB struct {
	Packages map[string]string
	Format   Format
}

// Version returns the version of the first candidate name that is installed.
//
// Candidates exist because the same software is packaged under different names
// across distributions — apache2 and httpd, mysql-server and mariadb-server —
// and the caller knows which names mean the same thing.
func (d DB) Version(candidates ...string) (name, version string, ok bool) {
	for _, c := range candidates {
		if v, found := d.Packages[c]; found && v != "" {
			return c, v, true
		}
	}

	return "", "", false
}

// ParseDpkgStatus reads /var/lib/dpkg/status.
//
// Only packages whose Status field says "installed" count. dpkg keeps entries
// for packages that are deinstalled or config-files only, and treating those as
// present would report software the machine does not have — the same mistake
// ParseDpkgInstalled in the pkgmgr package was written to avoid.
func ParseDpkgStatus(content string) map[string]string {
	out := make(map[string]string)

	for _, block := range strings.Split(content, "\n\n") {
		var name, version string
		installed := false

		for _, line := range strings.Split(block, "\n") {
			switch {
			case strings.HasPrefix(line, "Package:"):
				name = strings.TrimSpace(strings.TrimPrefix(line, "Package:"))
			case strings.HasPrefix(line, "Version:"):
				version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
			case strings.HasPrefix(line, "Status:"):
				fields := strings.Fields(strings.TrimPrefix(line, "Status:"))
				installed = len(fields) >= 3 && fields[0] == "install" && fields[2] == "installed"
			}
		}

		if name != "" && version != "" && installed {
			out[name] = version
		}
	}

	return out
}

// ParseApkInstalled reads /lib/apk/db/installed, whose blocks are separated by a
// blank line and whose fields are single letters: P for package, V for version.
//
// The version carries Alpine's own revision suffix — nginx 1.31.9-r1 — and it is
// kept as read. Stripping it here would throw away the only thing that
// distinguishes two different builds of the same upstream release, and the
// caller comparing against an upstream version is the one that knows to trim it.
func ParseApkInstalled(content string) map[string]string {
	out := make(map[string]string)

	for _, block := range strings.Split(content, "\n\n") {
		var name, version string

		for _, line := range strings.Split(block, "\n") {
			if len(line) < 3 || line[1] != ':' {
				continue
			}

			switch line[0] {
			case 'P':
				name = strings.TrimSpace(line[2:])
			case 'V':
				version = strings.TrimSpace(line[2:])
			}
		}

		if name != "" && version != "" {
			out[name] = version
		}
	}

	return out
}
