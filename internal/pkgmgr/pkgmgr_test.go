package pkgmgr

import "testing"

// The whole reason this package exists: "could not tell" must never read as
// "fine". A bool conflated them, and the panel used that bool to suppress CVE
// advisories, so a package the manager had never heard of bought itself silence.
func TestUnknownIsNotCurrent(t *testing.T) {
	if Unknown == Current {
		t.Fatal("Unknown and Current must be distinguishable")
	}
	r := unknown("apt")
	if r.Verdict != Unknown {
		t.Errorf("unknown() verdict = %q, want %q", r.Verdict, Unknown)
	}
	if r.Manager != "apt" {
		t.Errorf("unknown() must still name the manager it tried, got %q", r.Manager)
	}
	if r.Package != "" {
		t.Errorf("unknown() must not name a package it never confirmed, got %q", r.Package)
	}
}

func TestParseDpkgInstalled(t *testing.T) {
	cases := map[string]bool{
		"install ok installed":       true,
		"  install ok installed  ":   true,
		"deinstall ok config-files":  false,
		"install ok half-configured": false,
		"unknown ok not-installed":   false,
		"purge ok not-installed":     false,
		"":                           false,
		"install ok":                 false,
	}
	for status, want := range cases {
		if got := ParseDpkgInstalled(status); got != want {
			t.Errorf("ParseDpkgInstalled(%q) = %v, want %v", status, got, want)
		}
	}
}

// A prefix match would report an update to php8.3-cli as an update to php8.3,
// and would match nginx-common for nginx. The name is compared whole.
func TestParseAptUpgradableMatchesTheWholeName(t *testing.T) {
	output := `Listing...
nginx-common/noble-updates 1.24.0-2ubuntu7.1 all [upgradable from: 1.24.0-2ubuntu7]
php8.3-cli/noble-updates 8.3.37-1 amd64 [upgradable from: 8.3.36-1]
openssh-server/noble-security 1:9.6p1-3ubuntu13.5 amd64 [upgradable from: 1:9.6p1-3ubuntu13.4]
`
	cases := map[string]bool{
		"openssh-server": true,
		"php8.3-cli":     true,
		"nginx-common":   true,
		"nginx":          false, // must not match nginx-common
		"php8.3":         false, // must not match php8.3-cli
		"php":            false,
		"apache2":        false,
	}
	for pkg, want := range cases {
		if got := ParseAptUpgradable(output, pkg); got != want {
			t.Errorf("ParseAptUpgradable(_, %q) = %v, want %v", pkg, got, want)
		}
	}
}

func TestParseAptUpgradableOnAnEmptyList(t *testing.T) {
	if ParseAptUpgradable("Listing...\n", "nginx") {
		t.Error("an empty upgradable list must not report an update")
	}
}

func TestParseAptJustPrint(t *testing.T) {
	output := `NOTE: This is only a simulation!
Inst nginx [1.24.0-2ubuntu7] (1.26.0-1 Ubuntu:24.04/noble-updates [amd64])
Conf nginx (1.26.0-1 Ubuntu:24.04/noble-updates [amd64])
Inst libssl3t64 [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04 [amd64])
`
	cases := map[string]bool{
		"nginx":       true,
		"libssl3t64":  true,
		"nginx-extra": false,
		"apache2":     false,
	}
	for pkg, want := range cases {
		if got := ParseAptJustPrint(output, pkg); got != want {
			t.Errorf("ParseAptJustPrint(_, %q) = %v, want %v", pkg, got, want)
		}
	}
	// "Conf" lines are not installs and must not count on their own.
	if ParseAptJustPrint("Conf onlyconf (1.0 [amd64])\n", "onlyconf") {
		t.Error("a Conf-only line must not report an update")
	}
}

// With no package manager at all — a source build, a distroless container —
// every answer must be Unknown, never Current.
func TestQueryWithoutAManagerIsUnknown(t *testing.T) {
	if Manager() == "" {
		r := Query("nginx")
		if r.Verdict != Unknown {
			t.Errorf("Query() with no manager = %q, want %q", r.Verdict, Unknown)
		}
	} else {
		t.Skip("a package manager is present on this host")
	}
}

func TestQueryIgnoresEmptyCandidates(t *testing.T) {
	// Must not panic or consult an empty package name.
	r := Query("", "")
	if r.Verdict != Unknown {
		t.Errorf("Query(\"\",\"\") = %q, want %q", r.Verdict, Unknown)
	}
}

// Exercises the real package manager when the host has one. On a Debian or
// RHEL-family box this is the only test that proves the dpkg-query / rpm and
// upgrade-check plumbing actually works; the parser tests above cannot.
func TestQueryAgainstTheRealManager(t *testing.T) {
	manager := Manager()
	if manager == "" {
		t.Skip("no package manager on this host")
	}

	// A package that is certainly installed wherever a manager exists. The
	// verdict may be either, but it must not be Unknown: that would mean the
	// installed-check or the upgrade-check is broken, which is precisely the
	// failure that let unverified packages pass as current.
	for _, candidates := range [][]string{{"bash"}, {"coreutils"}} {
		r := Query(candidates...)
		if r.Verdict == Unknown {
			t.Errorf("Query(%v) = Unknown on a host with %s; the installed or upgrade check is broken", candidates, manager)
		}
		if r.Verdict != Unknown && r.Package == "" {
			t.Errorf("Query(%v) returned %q without naming the package consulted", candidates, r.Verdict)
		}
	}

	// A package no distribution ships must be Unknown, never Current.
	if r := Query("defensia-no-such-package-exists"); r.Verdict != Unknown {
		t.Errorf("Query(nonexistent) = %q, want %q", r.Verdict, Unknown)
	}
}
