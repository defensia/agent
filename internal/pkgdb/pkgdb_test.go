package pkgdb

import "testing"

// A real extract of /var/lib/dpkg/status, including the two states that must not
// count as installed: a deinstalled package that dpkg still remembers, and one
// left at config-files.
const dpkgStatus = `Package: nginx
Status: install ok installed
Priority: optional
Version: 1.24.0-2ubuntu7.20
Description: small, powerful, scalable web/proxy server

Package: openssh-server
Status: install ok installed
Version: 1:9.6p1-3ubuntu13.14

Package: apache2
Status: deinstall ok config-files
Version: 2.4.58-1ubuntu8.5

Package: php8.3-fpm
Status: install ok installed
Version: 8.3.6-0ubuntu0.24.04.5
`

// /lib/apk/db/installed from the nginx:alpine image, trimmed. The -r1 suffix is
// Alpine's build revision and is part of the answer.
const apkInstalled = `C:Q1eVpkE9fGZBbFyRZ6Xk1kAsJqmcc=
P:nginx
V:1.31.9-r1
A:aarch64
S:598841
I:1183744

C:Q1MxVQ2V5s2tHKPGaOtQ1nZGZNz4M=
P:openssl
V:3.3.5-r0
A:aarch64

C:Q1broken
V:9.9.9-r9
`

func TestDpkgStatusGivesOnlyInstalledPackages(t *testing.T) {
	got := ParseDpkgStatus(dpkgStatus)

	if v := got["nginx"]; v != "1.24.0-2ubuntu7.20" {
		t.Errorf("nginx = %q, want 1.24.0-2ubuntu7.20", v)
	}
	if v := got["openssh-server"]; v != "1:9.6p1-3ubuntu13.14" {
		t.Errorf("openssh-server = %q, want the epoch kept", v)
	}
	if v := got["php8.3-fpm"]; v != "8.3.6-0ubuntu0.24.04.5" {
		t.Errorf("php8.3-fpm = %q", v)
	}
}

// dpkg remembers packages that are gone. Counting those would report software
// the machine does not have.
func TestADeinstalledPackageIsNotInstalled(t *testing.T) {
	if v, found := ParseDpkgStatus(dpkgStatus)["apache2"]; found {
		t.Errorf("apache2 is deinstalled/config-files and must not be reported; got %q", v)
	}
}

func TestApkInstalledKeepsTheAlpineRevision(t *testing.T) {
	got := ParseApkInstalled(apkInstalled)

	if v := got["nginx"]; v != "1.31.9-r1" {
		t.Errorf("nginx = %q, want 1.31.9-r1 — the -rN distinguishes two builds of the same upstream release", v)
	}
	if v := got["openssl"]; v != "3.3.5-r0" {
		t.Errorf("openssl = %q", v)
	}
}

// A block with a version and no name is not a package.
func TestABlockWithoutANameIsSkipped(t *testing.T) {
	for name := range ParseApkInstalled(apkInstalled) {
		if name == "" {
			t.Error("an empty package name was recorded")
		}
	}
	if len(ParseApkInstalled(apkInstalled)) != 2 {
		t.Errorf("want 2 packages, got %d", len(ParseApkInstalled(apkInstalled)))
	}
}

func TestVersionTriesEveryCandidateName(t *testing.T) {
	db := DB{Packages: ParseDpkgStatus(dpkgStatus), Format: Dpkg}

	name, version, ok := db.Version("httpd", "apache2", "nginx")
	if !ok {
		t.Fatal("want nginx found via the third candidate")
	}
	if name != "nginx" || version != "1.24.0-2ubuntu7.20" {
		t.Errorf("got %s %s", name, version)
	}

	if _, _, ok := db.Version("litespeed", "caddy"); ok {
		t.Error("want no answer when no candidate is installed")
	}
}

func TestEmptyInputIsNoPackagesNotACrash(t *testing.T) {
	if n := len(ParseDpkgStatus("")); n != 0 {
		t.Errorf("want 0 packages from empty dpkg status, got %d", n)
	}
	if n := len(ParseApkInstalled("")); n != 0 {
		t.Errorf("want 0 packages from empty apk db, got %d", n)
	}
}
