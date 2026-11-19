// Package webserver answers one question for the whole agent: which web server
// is actually serving this host, and at what version.
//
// It exists because that question used to have two answers. The agent's
// heartbeat asked the listening sockets, while the software inventory walked
// installed packages in the order nginx, apache2, httpd — so an OpenLiteSpeed
// host with an idle Apache package reported "litespeed" in one place and
// "Apache 2.4.58" in the other, about the same machine, at the same time. A
// customer found that and was right to.
package webserver

import (
	"os"
	"os/exec"
	"strings"

	"github.com/defensia/agent/internal/monitor"
)

// Detect returns the web server serving this host and its version.
//
// What is listening on the public ports wins; installed packages are consulted
// only when nothing is serving — a box mid-provision, or with the server
// stopped. Installed-package order used to decide this outright, which
// misreported any box with more than one server present: a customer running
// OpenLiteSpeed on :80/:443 with an idle Apache on :8082 was reported as Apache,
// so the panel offered them an Apache ModSecurity install that would have sat in
// front of no traffic at all, and added surface to a service they had stopped.
func Detect() (name, version string) {
	if served := OnPublicPorts(); served != "" {
		// Something is serving, but it lives in a container and the host's own
		// packages say nothing about it. Falling through to Installed() here is
		// exactly the bug this package exists to prevent: on our own platform
		// server it reported the host's stopped nginx 1.24.0 as the serving web
		// server while the container actually answering :443 ran 1.31.9 — right
		// name, wrong version, and a service that handles no traffic.
		//
		// No version is reported rather than a wrong one. Resolving which
		// container holds the port, and what it runs, is a separate change;
		// until then "we can see something serving but cannot identify it" is
		// the honest answer, and it is strictly better than naming the host's.
		if served == ContainerPublished {
			return ContainerPublished, ""
		}

		return served, Version(served)
	}

	return Installed()
}

// OnPublicPorts returns the web server serving :80 or :443, or "" if none is.
//
// A real host web server outranks the container signal, deliberately: a host can
// hold :443 with its own nginx while a container publishes :80, and in that case
// the host's server is a true answer and ContainerPublished is only the absence
// of one. So the loop cannot return on the first match — it has to see every
// public port before settling for the weaker signal.
func OnPublicPorts() string {
	container := false

	for _, svc := range monitor.DetectListeningServices() {
		if svc.Port != 80 && svc.Port != 443 {
			continue
		}

		switch name := FromProcess(svc.Process); name {
		case "":
			// Not a web server and not docker-proxy: some other listener.
		case ContainerPublished:
			container = true
		default:
			return name
		}
	}

	if container {
		return ContainerPublished
	}

	return ""
}

// ContainerPublished means a container holds the public port, so whatever serves
// this host is not a host process at all.
//
// It is deliberately NOT the name of a web server. Mapping docker-proxy to
// "nginx" would look like it fixed the problem and would instead make Version()
// run `nginx -v` on the host, reporting the host package's version for software
// running inside a container: the same lie, now harder to spot.
const ContainerPublished = "container"

// FromProcess maps a process name to the web server it belongs to.
//
// Prefix matching, not equality: /proc/<pid>/comm is truncated to 15 bytes, and
// OpenLiteSpeed's master shows up as "litespeed" or "lshttpd" depending on the
// build.
//
// docker-proxy is the userland process Docker puts in front of a published
// container port, so finding it on :80 or :443 means a container is serving.
// Its absence does not mean the opposite: Docker can DNAT in iptables with no
// userland proxy at all, in which case no host process holds the port and this
// returns "" — which is why the container case must stay a hint rather than the
// mechanism that detects containers.
func FromProcess(process string) string {
	proc := strings.ToLower(strings.TrimSpace(process))
	switch {
	case strings.HasPrefix(proc, "litespeed"), strings.HasPrefix(proc, "lshttpd"), strings.HasPrefix(proc, "openlitespeed"):
		return "litespeed"
	case strings.HasPrefix(proc, "nginx"):
		return "nginx"
	case strings.HasPrefix(proc, "apache"), strings.HasPrefix(proc, "httpd"):
		return "apache"
	case strings.HasPrefix(proc, "caddy"):
		return "caddy"
	case strings.HasPrefix(proc, "docker-proxy"), strings.HasPrefix(proc, "rootlesskit"):
		return ContainerPublished
	}

	return ""
}

// Version asks a named server for its version.
func Version(name string) string {
	switch name {
	case "litespeed":
		return liteSpeedVersion()
	case "nginx":
		if out, err := exec.Command("nginx", "-v").CombinedOutput(); err == nil {
			return ParseNginxVersion(string(out))
		}
	case "apache":
		for _, bin := range []string{"apache2", "httpd"} {
			if out, err := exec.Command(bin, "-v").CombinedOutput(); err == nil {
				return ParseApacheVersion(string(out))
			}
		}
	case "caddy":
		if out, err := exec.Command("caddy", "version").CombinedOutput(); err == nil {
			if f := strings.Fields(strings.TrimSpace(string(out))); len(f) > 0 {
				return strings.TrimPrefix(f[0], "v")
			}
		}
	}

	return ""
}

// liteSpeedVersion reads the version from lshttpd, which is not on PATH by default.
func liteSpeedVersion() string {
	for _, bin := range []string{"/usr/local/lsws/bin/lshttpd", "/usr/local/lsws/bin/openlitespeed", "lshttpd"} {
		out, err := exec.Command(bin, "-v").CombinedOutput()
		if err != nil && len(out) == 0 {
			continue
		}
		if v := ParseLiteSpeedVersion(string(out)); v != "" {
			return v
		}
	}

	return ""
}

// Installed is the fallback for a box where nothing is serving yet — during
// provisioning, or with the server stopped.
func Installed() (name, version string) {
	// LiteSpeed does not put its binaries on PATH, so check the install root.
	if _, err := os.Stat("/usr/local/lsws/bin/lshttpd"); err == nil {
		return "litespeed", liteSpeedVersion()
	}

	if path, err := exec.LookPath("nginx"); err == nil && path != "" {
		if out, err := exec.Command("nginx", "-v").CombinedOutput(); err == nil {
			return "nginx", ParseNginxVersion(string(out))
		}
	}

	for _, bin := range []string{"apache2", "httpd"} {
		if path, err := exec.LookPath(bin); err == nil && path != "" {
			if out, err := exec.Command(bin, "-v").CombinedOutput(); err == nil {
				return "apache", ParseApacheVersion(string(out))
			}
		}
	}

	return "", ""
}

// ParseApacheVersion extracts the version from "Server version: Apache/2.4.57 (Debian)".
func ParseApacheVersion(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if idx := strings.Index(line, "Apache/"); idx >= 0 {
			if fields := strings.Fields(line[idx+len("Apache/"):]); len(fields) > 0 {
				return fields[0]
			}
		}
	}
	return ""
}

// ParseNginxVersion extracts the version from "nginx version: nginx/1.24.0",
// which nginx prints to stderr.
func ParseNginxVersion(output string) string {
	s := strings.TrimSpace(output)
	if idx := strings.Index(s, "nginx/"); idx >= 0 {
		if f := strings.Fields(s[idx+len("nginx/"):]); len(f) > 0 {
			return f[0]
		}
	}
	return ""
}

// ParseLiteSpeedVersion extracts the version from "LiteSpeed/1.9.3 Open (BUILD)"
// or "openlitespeed/1.7.19".
func ParseLiteSpeedVersion(output string) string {
	s := strings.TrimSpace(output)
	for _, marker := range []string{"LiteSpeed/", "litespeed/", "openlitespeed/"} {
		if idx := strings.Index(s, marker); idx >= 0 {
			if f := strings.Fields(s[idx+len(marker):]); len(f) > 0 {
				return f[0]
			}
		}
	}
	return ""
}

// DisplayName is the human name for the inventory and the panel.
func DisplayName(name string) string {
	switch name {
	case "litespeed":
		return "LiteSpeed"
	case "nginx":
		return "Nginx"
	case "apache":
		return "Apache"
	case "caddy":
		return "Caddy"
	}
	return ""
}
