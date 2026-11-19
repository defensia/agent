package webserver

import "testing"

// A customer running OpenLiteSpeed on :80/:443 with an idle Apache on :8082 was reported
// as Apache, because detection read installed packages rather than listening sockets.
// The panel then offered them an Apache ModSecurity install that would have sat in front
// of no traffic.
func TestWebServerFromProcess(t *testing.T) {
	cases := map[string]string{
		"litespeed":                 "litespeed",
		"lshttpd":                   "litespeed",
		"openlitespeed":             "litespeed",
		"litespeed (lshttpd - #01)": "litespeed",
		"LSHTTPD":                   "litespeed",
		"nginx":                     "nginx",
		"nginx: worker":             "nginx",
		"apache2":                   "apache",
		"httpd":                     "apache",
		"caddy":                     "caddy",

		// Not web servers, and must not be mistaken for one.
		"sshd":     "",
		"mysqld":   "",
		"php-fpm8": "",
		"":         "",
		"   ":      "",
	}

	for process, want := range cases {
		if got := FromProcess(process); got != want {
			t.Errorf("FromProcess(%q) = %q, want %q", process, got, want)
		}
	}
}

func TestParseVersions(t *testing.T) {
	if got := ParseApacheVersion("Server version: Apache/2.4.58 (Ubuntu)"); got != "2.4.58" {
		t.Errorf("ParseApacheVersion() = %q, want 2.4.58", got)
	}
	if got := ParseNginxVersion("nginx version: nginx/1.24.0"); got != "1.24.0" {
		t.Errorf("ParseNginxVersion() = %q, want 1.24.0", got)
	}
	for raw, want := range map[string]string{
		"LiteSpeed/1.9.3 Open (BUILD)": "1.9.3",
		"openlitespeed/1.7.19":         "1.7.19",
		"nothing here":                 "",
	} {
		if got := ParseLiteSpeedVersion(raw); got != want {
			t.Errorf("ParseLiteSpeedVersion(%q) = %q, want %q", raw, got, want)
		}
	}
}

// The inventory and the heartbeat must name the same server the same way. They
// used to disagree: one said "litespeed", the other reported the idle Apache.
func TestDisplayNameCoversEveryDetectedServer(t *testing.T) {
	for _, name := range []string{"litespeed", "nginx", "apache", "caddy"} {
		if DisplayName(name) == "" {
			t.Errorf("DisplayName(%q) is empty; a detected server with no display name vanishes from the inventory", name)
		}
	}
	if DisplayName("mysqld") != "" {
		t.Error("DisplayName() named something that is not a web server")
	}
}

// On our own platform server :80 and :443 are held by docker-proxy, so
// FromProcess had no case for the process actually holding the port,
// OnPublicPorts returned "", and Detect fell through to Installed() — which
// found the host's nginx package and reported "Nginx 1.24.0" as the serving web
// server. Measured the same day: that host's nginx service was inactive and
// disabled, and the container answering :443 ran 1.31.9.
//
// So the guard written to stop an idle package outranking what serves traffic
// fell open and landed on the exact fallback it exists to avoid.
func TestDockerProxyIsNotMistakenForAWebServer(t *testing.T) {
	cases := map[string]string{
		"docker-proxy": ContainerPublished,
		// /proc/<pid>/comm truncates at 15 bytes, so the real reading is clipped.
		"docker-proxy\n": ContainerPublished,
		"DOCKER-PROXY":   ContainerPublished,
		// Podman's equivalent.
		"rootlesskit": ContainerPublished,
	}

	for process, want := range cases {
		if got := FromProcess(process); got != want {
			t.Errorf("FromProcess(%q) = %q, want %q", process, got, want)
		}
	}
}

// The container signal must never be a web server name. Mapping docker-proxy to
// "nginx" would look like a fix and would instead send Version() to run
// `nginx -v` on the host, reporting the host package's version for software
// running inside a container — the same lie, harder to spot.
func TestTheContainerSignalIsNotAWebServerName(t *testing.T) {
	if DisplayName(ContainerPublished) != "" {
		t.Errorf("DisplayName(%q) must be empty so the inventory cannot present it as a host web server", ContainerPublished)
	}

	if v := Version(ContainerPublished); v != "" {
		t.Errorf("Version(%q) = %q, want empty: asking a container signal for a host version is the bug", ContainerPublished, v)
	}

	for _, real := range []string{"nginx", "apache", "litespeed", "caddy"} {
		if ContainerPublished == real {
			t.Fatalf("ContainerPublished collides with the real server name %q", real)
		}
	}
}

// DisplayName returning "" routes detectWebServer() to its honest branch, which
// reports no version rather than the host's. This pins that the two agree.
func TestDisplayNameCoversOnlyRealServers(t *testing.T) {
	for _, name := range []string{"nginx", "apache", "litespeed", "caddy"} {
		if DisplayName(name) == "" {
			t.Errorf("DisplayName(%q) is empty, so a real serving host would report no web server", name)
		}
	}
}
