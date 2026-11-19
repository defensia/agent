package pkgmgr

import (
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The real thing, trimmed: /usr/share/doc/nginx-common/changelog.Debian.gz from
// nginx 1.24.0-2ubuntu7.20 on Ubuntu 24.04, read on 19 Nov 2026. Kept verbatim
// because the shape is the point — the CVE appears both in a patch filename and
// on its own line, and Ubuntu is inconsistent about case between the two.
const ubuntuNginxChangelog = `nginx (1.24.0-2ubuntu7.20) noble-security; urgency=medium

  * SECURITY UPDATE: Arbitrary code execution in send_window
    - debian/patches/CVE-2026-123007.patch: Account for queued frames when
      validating WINDOW_UPDATE in src/http/v2/ngx_http_v2.c and
      ../ngx_http_v2_filter_module.c
    - CVE-2026-123007
  * SECURITY UPDATE: Arbitrary code execution in HTTP/2
    - debian/patches/CVE-2026-123633.patch: Reset reusable connection status
      on stream creation in src/http/v2/ngx_http_v2.c
    - CVE-2026-123633
  * SECURITY UPDATE: Use-after-free in mail proxy
    - debian/patches/CVE-2026-113425-1.patch: Set handlers on s->quit in
      ngx_mail_send() in src/mail/ngx_mail_handler.c
    - CVE-2026-113425

 -- Marc Deslauriers <marc.deslauriers@ubuntu.com>  Wed, 19 Nov 2026 08:11:03 -0500

nginx (1.24.0-2ubuntu7.8) noble-security; urgency=medium

  [ Thomas Ward ]
  * SECURITY UPDATE: buffer overrun in ngx_http_rewrite_module
    (LP: #2152577)
    - d/patches/cve-2026-42945.patch: Apply upstream commit/fix
      for CVE
    - CVE-2026-42945

 -- Marc Deslauriers <marc.deslauriers@ubuntu.com>  Thu, 14 May 2026 09:55:14 +0200
`

func TestTheBackportedCVEsAreReadOffTheChangelog(t *testing.T) {
	got := ParseChangelogCVEs(ubuntuNginxChangelog)

	for _, want := range []string{"CVE-2026-123007", "CVE-2026-123633", "CVE-2026-113425", "CVE-2026-42945"} {
		if !contains(got, want) {
			t.Errorf("want %s among %v", want, got)
		}
	}
}

// The fifth nginx2root CVE is the HTTP/3 one, and Ubuntu's nginx 1.24.0 is built
// without QUIC, so it is absent from a changelog that fixed the other four. The
// caller must read that absence as "no evidence", never as "unpatched" — this
// test exists to pin the fact that the parser reports it as simply missing and
// says nothing more.
func TestACVEThatDoesNotApplyIsSimplyAbsent(t *testing.T) {
	got := ParseChangelogCVEs(ubuntuNginxChangelog)

	if contains(got, "CVE-2026-121810") {
		t.Fatalf("CVE-2026-121810 does not apply to this build and must not be reported as fixed: %v", got)
	}
}

// Ubuntu names the same CVE twice in one entry, once lower-cased inside a patch
// filename. One identifier out, upper-cased.
func TestTheSameCVENamedTwiceInTwoCasesIsOneIdentifier(t *testing.T) {
	got := ParseChangelogCVEs("- d/patches/cve-2026-42945.patch\n    - CVE-2026-42945\n")

	if len(got) != 1 || got[0] != "CVE-2026-42945" {
		t.Fatalf("want exactly [CVE-2026-42945], got %v", got)
	}
}

// Changelog order is newest first, and the cap drops the oldest. A package with
// a long security history must therefore keep the identifiers an advisory is
// likely to be about.
func TestTheCapDropsTheOldestEntriesNotTheNewest(t *testing.T) {
	var b strings.Builder
	b.WriteString("CVE-2026-100000\n") // newest, must survive
	for i := 0; i < maxFixedCVEs+50; i++ {
		b.WriteString("CVE-2019-")
		b.WriteString(pad(i))
		b.WriteString("\n")
	}

	got := ParseChangelogCVEs(b.String())

	if len(got) != maxFixedCVEs {
		t.Fatalf("want the cap of %d, got %d", maxFixedCVEs, len(got))
	}
	if got[0] != "CVE-2026-100000" {
		t.Errorf("the newest identifier must survive the cap, got %s first", got[0])
	}
}

func TestNoCVEsIsAnEmptyAnswerNotAFailure(t *testing.T) {
	got := ParseChangelogCVEs("nginx (1.24.0-1) noble; urgency=low\n\n  * Initial release.\n")

	if len(got) != 0 {
		t.Fatalf("want no identifiers, got %v", got)
	}
}

// A malformed reference must not be reported. Three digits is too few for the
// post-2014 identifier format, and a year of two digits is not a year.
func TestMalformedReferencesAreNotIdentifiers(t *testing.T) {
	got := ParseChangelogCVEs("CVE-2026-123 and CVE-26-1234 and CVE-XXXX-YYYY\n")

	if len(got) != 0 {
		t.Fatalf("want nothing matched, got %v", got)
	}
}

func TestAGzippedChangelogIsDecompressed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "changelog.Debian.gz")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(f)
	if _, err := zw.Write([]byte(ubuntuNginxChangelog)); err != nil {
		t.Fatal(err)
	}
	zw.Close()
	f.Close()

	text, ok := readMaybeGzipped(path)
	if !ok {
		t.Fatal("want the gzipped changelog to be readable")
	}
	if !contains(ParseChangelogCVEs(text), "CVE-2026-123007") {
		t.Error("want the nginx2root CVE out of the decompressed text")
	}
}

func TestAPlainChangelogIsReadAsIs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "changelog")
	if err := os.WriteFile(path, []byte("- CVE-2026-123007\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	text, ok := readMaybeGzipped(path)
	if !ok || !strings.Contains(text, "CVE-2026-123007") {
		t.Fatalf("want the plain file read verbatim, got ok=%v text=%q", ok, text)
	}
}

func TestAMissingChangelogIsNoAnswer(t *testing.T) {
	if _, ok := readMaybeGzipped(filepath.Join(t.TempDir(), "absent.gz")); ok {
		t.Fatal("a missing file must be no answer, not an empty one")
	}
}

// A name that is not a plain package name must never be turned into a path.
// Nothing upstream of here should produce one, which is exactly why it is worth
// refusing rather than trusting.
func TestAPackageNameIsNeverAPath(t *testing.T) {
	for _, pkg := range []string{"../../etc/passwd", "nginx/../../etc", `..\..\windows`, "/etc/shadow", ""} {
		if _, ok := readDebianChangelog(pkg); ok {
			t.Errorf("want %q refused", pkg)
		}
	}
}

func TestAnUnknownManagerHasNoChangelogReader(t *testing.T) {
	if _, ok := FixedCVEs("pacman", "nginx"); ok {
		t.Error("want no answer for a manager we have no reader for")
	}
	if _, ok := FixedCVEs("apt", ""); ok {
		t.Error("want no answer without a package name")
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// pad renders i as at least four digits, so every generated identifier is a
// well-formed CVE reference.
func pad(i int) string {
	s := "0000" + itoa(i)
	return s[len(s)-4:]
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
