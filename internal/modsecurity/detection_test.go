package modsecurity

import (
	"os"
	"path/filepath"
	"testing"
)

// The bug this file exists for: detection fell back to os.Stat on
// /etc/modsecurity/modsecurity.conf, so a host where the package had ever been
// installed reported ModSecurity active for ever after — whether or not any web
// server could load it.
//
// Measured in production on 19 Nov 2026: 15 of 127 agents reported it active and
// only 5 had ever intercepted a request. On one of our own servers the agent had
// written its rules correctly to /etc/modsecurity/defensia/defensia-static.conf
// while `nginx -V` showed no ModSecurity module at all. The rules were there and
// nothing read them, silently, for months.

// Real output from `apachectl -M` on a host with the module loaded.
const apacheModulesWithModSec = ` core_module (static)
 so_module (static)
 security2_module (shared)
 mpm_prefork_module (shared)
`

const apacheModulesWithout = ` core_module (static)
 so_module (static)
 mpm_prefork_module (shared)
 rewrite_module (shared)
`

func TestApacheModuleListDecidesForApache(t *testing.T) {
	if !ParseApacheModules(apacheModulesWithModSec) {
		t.Error("a module list naming security2_module must count as active")
	}

	if ParseApacheModules(apacheModulesWithout) {
		t.Error("a module list without it must not")
	}
}

// Real `nginx -V` output. The flag appears among the configure arguments when
// the module is compiled in.
const nginxCompiledIn = `nginx version: nginx/1.24.0
built with OpenSSL 3.0.13
configure arguments: --with-compat --add-module=/build/ModSecurity-nginx`

const nginxPlain = `nginx version: nginx/1.24.0 (Ubuntu)
built with OpenSSL 3.0.13
configure arguments: --with-http_ssl_module --with-http_v2_module`

func TestNginxCompiledInCounts(t *testing.T) {
	if !nginxModSecurityAt(func() string { return nginxCompiledIn }, nil) {
		t.Error("nginx built with the ModSecurity module must count as active")
	}

	if nginxModSecurityAt(func() string { return nginxPlain }, nil) {
		t.Error("a plain nginx must not")
	}
}

// This is the case measured on our own server: nginx serving :80 and :443 with
// no ModSecurity module, while /etc/modsecurity/modsecurity.conf and our own
// rules sat on disk. The old detection said active. It must not.
func TestAConfigFileOnDiskIsNotProtection(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "modsecurity.conf")
	if err := os.WriteFile(conf, []byte("SecRuleEngine On\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rules := filepath.Join(dir, "defensia-static.conf")
	if err := os.WriteFile(rules, []byte("SecRule ARGS \"@rx x\" \"id:9910001\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// A plain nginx, and no nginx.conf loading the module.
	if nginxModSecurityAt(func() string { return nginxPlain }, []string{conf, rules}) {
		t.Error("configuration files on disk must not be read as a loaded module — that is the bug")
	}
}

func TestADynamicLoadModuleCounts(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	body := "user www-data;\nload_module modules/ngx_http_modsecurity_module.so;\nhttp { }\n"
	if err := os.WriteFile(conf, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	if !nginxModSecurityAt(func() string { return nginxPlain }, []string{conf}) {
		t.Error("a dynamic load_module line must count as active")
	}
}

// A commented-out load_module is the shape of a host where somebody tried
// ModSecurity and backed out. It must not count.
func TestACommentedLoadModuleDoesNotCount(t *testing.T) {
	cases := []string{
		"# load_module modules/ngx_http_modsecurity_module.so;",
		"   #load_module modules/ngx_http_modsecurity_module.so;",
	}

	for _, line := range cases {
		if HasModSecurityLoadModule(line + "\nhttp { }\n") {
			t.Errorf("commented line counted as active: %q", line)
		}
	}
}

// And an unrelated dynamic module must not be mistaken for this one.
func TestAnotherModuleIsNotModSecurity(t *testing.T) {
	if HasModSecurityLoadModule("load_module modules/ngx_http_geoip_module.so;\n") {
		t.Error("an unrelated load_module counted as ModSecurity")
	}
}

// The case measured on our own server, and the reason IsActive asks the serving
// web server rather than the filesystem or the module list alone: Apache had
// security2_module genuinely loaded, the agent had written its rules correctly,
// and nginx held :80 and :443 with no ModSecurity. Module present, rules
// present, traffic unprotected — and the panel said "active" for months.
//
// Pinned at the level of the decision rather than the plumbing, since
// OnPublicPorts reads live sockets and cannot be faked in a unit test.
func TestWhichServerMattersIsTheOneHoldingThePublicPorts(t *testing.T) {
	cases := []struct {
		serving      string
		apacheModule bool
		nginxModule  bool
		want         bool
		why          string
	}{
		{"apache", true, false, true, "Apache serves and carries the module"},
		{"apache", false, true, false, "Apache serves but the module is nginx's"},
		{"nginx", true, false, false, "OUR SERVER: nginx serves, the module is Apache's"},
		{"nginx", false, true, true, "nginx serves and carries the module"},
		{"container", true, true, false, "a container holds the port; we cannot see inside it"},
	}

	for _, c := range cases {
		got := decideActive(c.serving, c.apacheModule, c.nginxModule, false)
		if got != c.want {
			t.Errorf("serving=%s apache=%v nginx=%v → %v, want %v (%s)",
				c.serving, c.apacheModule, c.nginxModule, got, c.want, c.why)
		}
	}
}

// Mismatch is the finding worth telling a customer about: they already did the
// work, and it is guarding the wrong door. Our own server is the case —
// everything about its ModSecurity is correct except which port it sits in
// front of.
func TestMismatchNamesTheServerThatHasTheModule(t *testing.T) {
	cases := []struct {
		serving string
		apache  bool
		nginx   bool
		lite    bool
		want    string
	}{
		{"nginx", true, false, false, "ModSecurity is loaded in Apache, but nginx serves the public ports"},
		{"apache", false, true, false, "ModSecurity is loaded in nginx, but apache serves the public ports"},
		{"nginx", false, false, true, "ModSecurity is loaded in LiteSpeed, but nginx serves the public ports"},
		// No mismatch: the serving server has it.
		{"nginx", false, true, false, ""},
		{"apache", true, false, false, ""},
		// Nothing has it: that is "no WAF", not a misplaced one, and the
		// existing no-logs path already covers telling them.
		{"nginx", false, false, false, ""},
	}

	for _, c := range cases {
		got := describeMismatch(c.serving, c.apache, c.nginx, c.lite)
		if got != c.want {
			t.Errorf("serving=%s apache=%v nginx=%v lite=%v\n got: %q\nwant: %q",
				c.serving, c.apache, c.nginx, c.lite, got, c.want)
		}
	}
}

// A container holding the port is not a mismatch we can diagnose: the module
// would be inside an image we cannot inspect.
func TestAContainerIsNotReportedAsAMismatch(t *testing.T) {
	if got := describeMismatch("container", true, true, true); got != "" {
		t.Errorf("want no mismatch for a container-held port, got %q", got)
	}
}
