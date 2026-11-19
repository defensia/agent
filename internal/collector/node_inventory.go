package collector

import (
	"regexp"
	"strings"

	"github.com/defensia/agent/internal/hostroot"
	"github.com/defensia/agent/internal/pkgdb"
)

// Inventory when the agent runs in a container, which is the Kubernetes case and
// also any Docker install of the agent image.
//
// Every other detector in this package learns a version by running a program:
// `php -v`, `nginx -v`, `sshd -V`. Inside a container those are the agent image's
// own binaries, so a node running Ubuntu with eighty packages reported the
// handful of things that happen to be in an Alpine agent image — a small,
// plausible inventory of the wrong machine. Measured in production: eight agents
// doing exactly that.
//
// Running the node's binaries instead would mean chroot or nsenter into the
// node. That is intrusive and unnecessary: the versions are written down in the
// package manager's database, which hostroot can read through /proc/1/root.
//
// This path is taken ONLY when the agent is containerised. On a host install
// nothing changes, which matters because that is the whole existing fleet.

// nodePackageSoftware is the software worth reporting from a node's package
// database, with the package names each one goes by. The names mirror
// packageCandidates(), which is the list the panel's own normalisation expects —
// keeping them in one shape means a node entry and a host entry describe the
// same software under the same name.
var nodePackageSoftware = []struct {
	display    string
	category   string
	candidates []string
}{
	{"OpenSSH", "security", []string{"openssh-server", "openssh"}},
	{"Nginx", "webserver", []string{"nginx", "nginx-core", "nginx-common"}},
	{"Apache", "webserver", []string{"apache2", "httpd"}},
	{"MySQL", "database", []string{"mysql-server", "mysql-community-server"}},
	{"MariaDB", "database", []string{"mariadb-server", "mariadb"}},
	{"Node.js", "runtime", []string{"nodejs", "node"}},
	{"Python", "runtime", []string{"python3", "python3-minimal", "python"}},
	{"Docker", "container", []string{"docker-ce", "docker.io", "docker", "containerd.io", "containerd"}},
}

// phpPackage matches the per-branch PHP packages a distro ships: php8.3-fpm,
// php8.1-cli, php-fpm. The branch is part of the answer — a host with a dead 7.4
// alongside a current 8.3 has to report both, which is why this is a pattern
// rather than a fixed candidate list.
var phpPackage = regexp.MustCompile(`^php(\d+\.\d+)?-(fpm|cli)$`)

// collectNodeSoftware builds the inventory from the node's package database.
//
// The second return is false when there is no database to read: an RPM node,
// whose format the agent cannot parse without cgo; an immutable node like
// Flatcar or Bottlerocket, which has no package manager; or a root we cannot
// see. The caller then keeps the existing behaviour rather than reporting an
// empty machine — "I could not tell" must never render as "nothing installed".
func collectNodeSoftware() ([]KeySoftware, bool) {
	db, ok := pkgdb.FromHostRoot()
	if !ok {
		return nil, false
	}

	// The kernel is the one reading that is already correct in a container: it is
	// shared with the node, so `uname -r` answers for the node.
	sw := []KeySoftware{detectKernel()}

	for _, want := range nodePackageSoftware {
		name, version, found := db.Version(want.candidates...)
		if !found {
			continue
		}

		sw = append(sw, nodeEntry(want.display, version, want.category, name, db.Format))
	}

	sw = append(sw, nodePHP(db)...)

	return sw, true
}

// nodePHP reports every PHP branch the node has packaged, named the way the
// host path names them so the panel treats them identically.
func nodePHP(db pkgdb.DB) []KeySoftware {
	var out []KeySoftware

	for pkg, version := range db.Packages {
		m := phpPackage.FindStringSubmatch(pkg)
		if m == nil {
			continue
		}

		display := "PHP"
		if strings.HasSuffix(pkg, "-fpm") {
			display = "PHP-FPM"
			if m[1] != "" {
				display = "PHP-FPM " + m[1]
			}
		}

		out = append(out, nodeEntry(display, version, "runtime", pkg, db.Format))
	}

	return out
}

// nodeEntry is one inventory row read from a package database.
//
// Two fields are set deliberately rather than by habit. Status is "unknown"
// because the per-software thresholds compiled into this agent are written
// against upstream version strings, and a distro package version
// (1.24.0-2ubuntu7.20, or 1:9.6p1-3ubuntu13.14 with its epoch) is not one —
// claiming "up_to_date" from it would be inventing a verdict.
//
// PkgVerdict is "unknown" for a stronger reason: it is the field the panel uses
// to decide whether a package is confirmed patched, and we have not asked any
// package manager whether an update is pending. We cannot ask: running apt or
// apk here would query the agent's own image. So the honest answer is that we do
// not know, which also keeps these entries out of the notification path.
func nodeEntry(display, version, category, pkg string, format pkgdb.Format) KeySoftware {
	return KeySoftware{
		Name:       display,
		Version:    version,
		Status:     "unknown",
		Category:   category,
		PkgName:    pkg,
		PkgManager: string(format),
		PkgVerdict: "unknown",
	}
}

// containerisedNode reports whether this agent is reading a machine other than
// the one it runs in. Wrapped so the collector reads as intent rather than as a
// hostroot implementation detail.
func containerisedNode() bool {
	return hostroot.IsContainerised()
}
