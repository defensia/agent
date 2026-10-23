package main

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
		if got := webServerFromProcess(process); got != want {
			t.Errorf("webServerFromProcess(%q) = %q, want %q", process, got, want)
		}
	}
}
