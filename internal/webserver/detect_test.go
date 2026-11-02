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
