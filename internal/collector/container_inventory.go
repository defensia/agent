package collector

import (
	"fmt"
	"strings"

	"github.com/defensia/agent/internal/monitor"
	"github.com/defensia/agent/internal/pkgdb"
)

// What runs inside the containers on this machine, which the agent could not see
// at all until now.
//
// Two measured failures motivated this, in opposite directions. On our own
// platform server the agent reported the host's stopped nginx 1.24.0 as the web
// server while the container actually answering :443 ran 1.31.9 — a false
// positive about a service handling no traffic. On a customer host, two
// containers published nginx 1.31.6 on 0.0.0.0:8081 and :8083 and the agent said
// nothing at all — a false negative about software on the public internet.
//
// Versions come from each container's own package database, read through
// /proc/<pid>/root. No docker exec, no nsenter: file reads only, so nothing
// spawns a process per container and nothing can hang on a wedged one.

// containerSoftware is what is worth reporting from inside a container, with the
// package names it goes by. Shorter than the host list on purpose: an inventory
// of every library in every image is noise, and these are the ones the CVE
// catalogue is about.
var containerSoftware = []struct {
	display    string
	category   string
	candidates []string
}{
	{"Nginx", "webserver", []string{"nginx", "nginx-core", "nginx-common"}},
	{"Apache", "webserver", []string{"apache2", "httpd"}},
	{"MySQL", "database", []string{"mysql-server", "mariadb-server", "mysql", "mariadb"}},
	{"PostgreSQL", "database", []string{"postgresql", "postgresql-server"}},
	{"Redis", "database", []string{"redis", "redis-server"}},
	{"Node.js", "runtime", []string{"nodejs", "node"}},
	{"OpenSSL", "security", []string{"openssl", "libssl3"}},
}

// collectContainerSoftware inventories every running container on the machine.
//
// Returns nothing when there is no container runtime to ask, which is the common
// case on a plain server and must stay cheap: one socket probe and out.
func collectContainerSoftware() []KeySoftware {
	containers, err := monitor.ListDockerContainers()
	if err != nil || len(containers) == 0 {
		return nil
	}

	var rows []KeySoftware

	for _, c := range containers {
		pid := monitor.ContainerPid(c.ID)
		if pid == 0 {
			// Stopped between listing and inspecting, or the daemon declined.
			// Reporting the container with no version would be honest but
			// useless; reporting nothing keeps the inventory to what we read.
			continue
		}

		rows = append(rows, softwareInContainer(c, fmt.Sprintf("/proc/%d/root", pid))...)
	}

	return collapseByVersion(rows)
}

// collapseByVersion folds rows that describe the same software at the same
// version with the same exposure into one, listing the containers it was found
// in.
//
// Measured need, not tidiness: on our own platform server nine containers all
// carry openssl 3.5.9-r0, because they are all built from the same base image.
// Reporting that nine times would multiply the inventory by the container count
// and multiply every OpenSSL advisory with it — and OpenSSL is one of the
// heaviest CVE sources there is. One image gets patched by rebuilding it, so one
// finding is also the truthful shape: it is a fact about the image, not about
// nine machines.
//
// Exposure is part of the key, deliberately. A vulnerable OpenSSL in a container
// published on 0.0.0.0 is a different finding from the same version in one bound
// to nothing, and collapsing them together would let the exposed instance hide
// behind the others.
func collapseByVersion(rows []KeySoftware) []KeySoftware {
	type key struct {
		name    string
		version string
		distro  string
		exposed bool
	}

	var order []key
	byKey := make(map[key]KeySoftware)
	names := make(map[key][]string)

	for _, r := range rows {
		k := key{r.Name, r.Version, r.DistroVersion, r.Exposed}

		if _, seen := byKey[k]; !seen {
			byKey[k] = r
			order = append(order, k)
		}

		names[k] = append(names[k], r.SourceName)

		// Keep the union of exposed ports: two containers at the same version can
		// publish different ports, and both are reachable.
		merged := byKey[k]
		merged.ExposedPorts = unionPorts(merged.ExposedPorts, r.ExposedPorts)
		byKey[k] = merged
	}

	out := make([]KeySoftware, 0, len(order))
	for _, k := range order {
		row := byKey[k]
		row.SourceName = strings.Join(names[k], ", ")
		if len(names[k]) > 1 {
			// The image is what gets patched, so name it rather than implying one
			// of the containers is the subject.
			row.SourceName = fmt.Sprintf("%d containers: %s", len(names[k]), row.SourceName)
		}
		out = append(out, row)
	}

	return out
}

func unionPorts(a, b []int) []int {
	seen := make(map[int]struct{}, len(a)+len(b))
	var out []int

	for _, list := range [][]int{a, b} {
		for _, p := range list {
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}

	return out
}

// softwareInContainer reads one container's package database and turns it into
// inventory rows.
func softwareInContainer(c monitor.DockerContainer, root string) []KeySoftware {
	db, ok := pkgdb.FromRoot(root)
	if !ok {
		// No package database: distroless, scratch, a static binary, or a root we
		// could not read. The container is real and may well be serving traffic,
		// so it is reported as present with no version rather than omitted —
		// "something is running here and I cannot identify it" is a finding, and
		// silence is not.
		return []KeySoftware{containerEntry(c, "Unidentified container", "", "", "container", pkgdb.Unknown)}
	}

	var out []KeySoftware

	for _, want := range containerSoftware {
		pkg, version, found := db.Version(want.candidates...)
		if !found {
			continue
		}

		out = append(out, containerEntry(c, want.display, version, pkg, want.category, db.Format))
	}

	return out
}

// containerEntry is one inventory row for software found inside a container.
//
// The version field carries the upstream-comparable version only, and that is
// the decision taken for this phase rather than an oversight.
//
// An Alpine package version is 1.31.9-r1: upstream 1.31.9 plus Alpine's build
// revision, and nginx:alpine tracks upstream closely enough that comparing it to
// a CVE's fixed version is meaningful. A Debian-based image carries Debian's
// backported version — 1.26.3-3+deb13u2 — where the upstream number deliberately
// does not move, so comparison is not just imprecise but inverted: it reports a
// patched build as vulnerable forever. And unlike on a host, there is no
// changelog inside the image to rescue it, measured: apk has no CVE changelog at
// all and Debian slim images ship /usr/share/doc with zero changelog files.
//
// So a Debian container reports its real version in DistroVersion, where the
// panel can show it, and leaves Version empty so nothing compares it. That is
// the "report unknown, do not match" decision, implemented without inventing a
// second matching path.
func containerEntry(c monitor.DockerContainer, display, version, pkg, category string, format pkgdb.Format) KeySoftware {
	exposed, ports := exposure(c)

	e := KeySoftware{
		Name:         display,
		Version:      "-",
		Status:       "unknown",
		Category:     category,
		PkgName:      pkg,
		PkgManager:   string(format),
		PkgVerdict:   "unknown",
		Source:       "container",
		SourceName:   containerName(c),
		SourceImage:  c.Image,
		Exposed:      exposed,
		ExposedPorts: ports,
	}

	switch format {
	case pkgdb.Apk:
		e.Version = strings.TrimSpace(version)
		e.DistroVersion = version
	case pkgdb.Dpkg:
		e.DistroVersion = version
	}

	return e
}

// exposure reads whether any of the container's published ports is reachable
// from outside the machine, and which.
//
// This is the field that separates the two measured failures: a container bound
// to 127.0.0.1 behind a reverse proxy is not the same finding as one published on
// 0.0.0.0, and until now we recorded neither.
func exposure(c monitor.DockerContainer) (bool, []int) {
	var ports []int
	seen := make(map[int]struct{})

	for _, p := range c.Ports {
		if !p.Exposed() {
			continue
		}
		if _, dup := seen[p.PublicPort]; dup {
			continue
		}
		seen[p.PublicPort] = struct{}{}
		ports = append(ports, p.PublicPort)
	}

	return len(ports) > 0, ports
}

// containerName strips the leading slash the Docker API puts on every name.
func containerName(c monitor.DockerContainer) string {
	if len(c.Names) == 0 {
		return c.ID[:min(12, len(c.ID))]
	}

	return strings.TrimPrefix(c.Names[0], "/")
}

func min(a, b int) int {
	if a < b {
		return a
	}

	return b
}
