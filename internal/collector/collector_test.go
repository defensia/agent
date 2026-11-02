package collector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFakePHP drops an executable that answers "-v" like a PHP SAPI binary does.
// It prints with the shell's printf builtin, not cat: these tests clear PATH so
// that a real php-fpm on the build machine cannot leak into the results, and an
// external command would not be found.
func writeFakePHP(t *testing.T, dir, name, banner string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	script := "#!/bin/sh\nprintf '%s\\n'"
	for _, line := range strings.Split(banner, "\n") {
		script += " '" + strings.ReplaceAll(line, "'", "") + "'"
	}
	script += "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}

func TestParsePHPBannerVersion(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "php-fpm banner",
			raw:  "PHP 8.3.36 (fpm-fcgi) (built: Oct 14 2026 09:11:02)\nCopyright (c) The PHP Group",
			want: "8.3.36",
		},
		{
			name: "lsphp banner",
			raw:  "PHP 8.4.27 (litespeed) (built: Oct 20 2026 11:02:41)\nCopyright (c) The PHP Group",
			want: "8.4.27",
		},
		{
			name: "startup warning before the banner is not mistaken for it",
			raw:  "PHP Warning:  Module \"redis\" is already loaded in Unknown on line 0\nPHP 8.5.11 (litespeed) (built: Oct 2 2026)",
			want: "8.5.11",
		},
		{
			name: "no banner at all",
			raw:  "some unrelated output\n",
			want: "",
		},
	}
	for _, c := range cases {
		if got := parsePHPBannerVersion(c.raw); got != c.want {
			t.Errorf("%s: parsePHPBannerVersion() = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestPHPVersionFromEcho(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{name: "bare version", raw: "8.4.27", want: "8.4.27"},
		{
			name: "warning on stdout before the value",
			raw:  "PHP Warning:  Cannot load module\n8.3.36",
			want: "8.3.36",
		},
		{name: "nothing usable", raw: "PHP Warning:  broken\n", want: ""},
	}
	for _, c := range cases {
		if got := phpVersionFromEcho(c.raw); got != c.want {
			t.Errorf("%s: phpVersionFromEcho() = %q, want %q", c.name, got, c.want)
		}
	}
}

// An OpenLiteSpeed host serves through lsphp trees that no php-fpm pattern
// matches. Before this was covered, such a host reported only its CLI binary.
func TestServingPHPRuntimesFindsLiteSpeedTrees(t *testing.T) {
	root := t.TempDir()
	for branch, version := range map[string]string{
		"lsphp82": "8.2.35",
		"lsphp83": "8.3.36",
		"lsphp84": "8.4.27",
		"lsphp85": "8.5.11",
	} {
		dir := filepath.Join(root, "lsws", branch, "bin")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		writeFakePHP(t, dir, "lsphp", "PHP "+version+" (litespeed) (built: Oct 20 2026)")
	}

	withGlobs(t, nil, []string{filepath.Join(root, "lsws", "lsphp*", "bin", "lsphp")})

	runtimes := servingPHPRuntimes()
	if len(runtimes) != 4 {
		t.Fatalf("servingPHPRuntimes() = %+v, want 4 runtimes", runtimes)
	}
	want := []string{"8.5.11", "8.4.27", "8.3.36", "8.2.35"}
	for i, r := range runtimes {
		if r.sapi != "PHP-LSAPI" {
			t.Errorf("runtime %d sapi = %q, want PHP-LSAPI", i, r.sapi)
		}
		if r.version != want[i] {
			t.Errorf("runtime %d version = %q, want %q (newest first)", i, r.version, want[i])
		}
	}
}

// The two SAPIs coexist on control-panel hosts, and each must be reported under
// its own name so the panel can tell which one serves what.
func TestDetectServingPHPNamesEachSAPI(t *testing.T) {
	root := t.TempDir()
	fpmDir := filepath.Join(root, "sbin")
	lsDir := filepath.Join(root, "lsws", "lsphp84", "bin")
	for _, d := range []string{fpmDir, lsDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFakePHP(t, fpmDir, "php-fpm8.3", "PHP 8.3.36 (fpm-fcgi) (built: Oct 14 2026)")
	writeFakePHP(t, lsDir, "lsphp", "PHP 8.4.27 (litespeed) (built: Oct 20 2026)")

	withGlobs(t,
		[]string{filepath.Join(fpmDir, "php-fpm*")},
		[]string{filepath.Join(root, "lsws", "lsphp*", "bin", "lsphp")},
	)

	got := map[string]string{}
	for _, sw := range detectServingPHP() {
		got[sw.Name] = sw.Version
		if sw.Category != "runtime" {
			t.Errorf("%s category = %q, want runtime", sw.Name, sw.Category)
		}
	}
	for name, version := range map[string]string{
		"PHP-FPM 8.3":   "8.3.36",
		"PHP-LSAPI 8.4": "8.4.27",
	} {
		if got[name] != version {
			t.Errorf("detectServingPHP() missing %s=%s, got %v", name, version, got)
		}
	}
}

// Debian installs php-fpm8.3 as a symlink to php-fpm. Probing both would report
// the same build twice.
func TestServingPHPBinariesDedupesSymlinks(t *testing.T) {
	root := t.TempDir()
	writeFakePHP(t, root, "php-fpm", "PHP 8.3.36 (fpm-fcgi) (built: Oct 14 2026)")
	if err := os.Symlink(filepath.Join(root, "php-fpm"), filepath.Join(root, "php8.3-fpm")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	withGlobs(t, []string{filepath.Join(root, "php*fpm*")}, nil)

	if runtimes := servingPHPRuntimes(); len(runtimes) != 1 {
		t.Errorf("servingPHPRuntimes() = %+v, want 1 runtime (symlink deduped)", runtimes)
	}
}

func TestServingPHPBinariesHonoursTheCap(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < maxServingPHPBinaries+8; i++ {
		writeFakePHP(t, root, "php-fpm"+string(rune('a'+i%26))+string(rune('a'+i/26)),
			"PHP 8.3.36 (fpm-fcgi) (built: Oct 14 2026)")
	}

	withGlobs(t, []string{filepath.Join(root, "php-fpm*")}, nil)

	bins, _ := servingPHPBinaries()
	if len(bins) > maxServingPHPBinaries {
		t.Errorf("servingPHPBinaries() returned %d entries, cap is %d", len(bins), maxServingPHPBinaries)
	}
}

func TestPHPLSAPIBinaryNamesUseCompactBranches(t *testing.T) {
	names := phpLSAPIBinaryNames()
	index := map[string]bool{}
	for _, n := range names {
		index[n] = true
	}
	// LiteSpeed names them lsphp84, never lsphp8.4.
	for _, want := range []string{"lsphp", "lsphp82", "lsphp83", "lsphp84", "lsphp85"} {
		if !index[want] {
			t.Errorf("phpLSAPIBinaryNames() missing %q", want)
		}
	}
	if index["lsphp8.4"] {
		t.Error("phpLSAPIBinaryNames() contains lsphp8.4; LiteSpeed compacts the branch")
	}
}

// withGlobs points the resolvers at a temporary tree for the duration of a test
// and clears PATH so a real php-fpm on the build machine cannot leak in.
func withGlobs(t *testing.T, fpm, lsapi []string) {
	t.Helper()
	origFPM, origLSAPI, origPath := phpFPMGlobs, phpLSAPIGlobs, os.Getenv("PATH")
	phpFPMGlobs, phpLSAPIGlobs = fpm, lsapi
	if err := os.Setenv("PATH", ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		phpFPMGlobs, phpLSAPIGlobs = origFPM, origLSAPI
		os.Setenv("PATH", origPath)
	})
}

// The package names are where this is easiest to get quietly wrong: a bad name
// means pkgmgr answers Unknown for software that is perfectly well managed, and
// the panel then reports advisories the distribution has already patched.
func TestPackageCandidates(t *testing.T) {
	cases := []struct {
		name string
		sw   KeySoftware
		want []string
	}{
		{
			name: "LiteSpeed PHP uses the compact branch, as LiteSpeed names it",
			sw:   KeySoftware{Name: "PHP-LSAPI 8.4", Version: "8.4.27"},
			want: []string{"lsphp84"},
		},
		{
			name: "PHP-FPM uses the dotted branch, as Debian names it",
			sw:   KeySoftware{Name: "PHP-FPM 8.3", Version: "8.3.36"},
			want: []string{"php8.3-fpm", "php-fpm"},
		},
		{
			name: "the CLI row asks about the CLI package",
			sw:   KeySoftware{Name: "PHP", Version: "8.3.36"},
			want: []string{"php8.3-cli", "php8.3-common", "php-cli", "php"},
		},
		{
			name: "Apache covers both distro families",
			sw:   KeySoftware{Name: "Apache", Version: "2.4.58"},
			want: []string{"apache2", "httpd"},
		},
		{
			name: "kernel covers Ubuntu, Debian and RHEL naming",
			sw:   KeySoftware{Name: "Linux Kernel", Version: "6.8.0-147-generic"},
			want: []string{"linux-image-generic", "linux-image-amd64", "kernel", "kernel-core"},
		},
		{
			name: "nginx must not be asked about as nginx-common only",
			sw:   KeySoftware{Name: "Nginx", Version: "1.24.0"},
			want: []string{"nginx", "nginx-core"},
		},
		{
			name: "an entry we have no package name for stays unverified",
			sw:   KeySoftware{Name: "Web Server", Version: "-"},
			want: nil,
		},
	}

	for _, c := range cases {
		got := packageCandidates(c.sw)
		if len(got) != len(c.want) {
			t.Errorf("%s: packageCandidates() = %v, want %v", c.name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: packageCandidates()[%d] = %q, want %q", c.name, i, got[i], c.want[i])
			}
		}
	}
}

func TestBranchFormatting(t *testing.T) {
	for version, want := range map[string]string{"8.4.27": "8.4", "8.5.11": "8.5", "7.4.33": "7.4", "": "", "garbage": ""} {
		if got := branchDotted(version); got != want {
			t.Errorf("branchDotted(%q) = %q, want %q", version, got, want)
		}
	}
	for version, want := range map[string]string{"8.4.27": "84", "8.5.11": "85", "": ""} {
		if got := branchCompact(version); got != want {
			t.Errorf("branchCompact(%q) = %q, want %q", version, got, want)
		}
	}
}

// An entry with no package name must come back untouched rather than carrying a
// verdict nobody produced.
func TestWithPackageVerdictLeavesUnmappedEntriesAlone(t *testing.T) {
	in := []KeySoftware{{Name: "Web Server", Version: "-", Status: "not_installed"}}
	out := withPackageVerdict(in)
	if out[0].PkgVerdict != "" || out[0].PkgName != "" {
		t.Errorf("unmapped entry gained a verdict: %+v", out[0])
	}
}
