package pkgmgr

import (
	"compress/gzip"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// The evidence this file collects is different in kind from the Verdict above,
// and stronger.
//
// A Verdict of Current says "the repository has nothing newer for this package".
// That is a statement about the repository, it is true only at the moment it is
// read, and it says nothing about any particular vulnerability. It is why the
// backport exemption it feeds has to be fenced in by an audit-freshness window:
// a package that was current a month ago may have had three security updates
// since, and the panel cannot tell.
//
// A distribution's own changelog says something narrower and far more useful:
// this build carries the fix for CVE-2026-123007. Debian and Ubuntu name the CVE
// in the changelog entry of the backported package, and RPM distributions do the
// same, which is what makes a patched host identifiable at all — the upstream
// version string deliberately does not move, so 1.24.0-2ubuntu7.20 still reports
// itself as "nginx/1.24.0" and every version-based scanner on the internet keeps
// flagging it.
//
// Two properties follow, and both matter:
//
//  1. The evidence does not go stale in the dangerous direction. A package cannot
//     un-patch itself, so a changelog read a month ago that named a CVE is still
//     telling the truth today; a newer build would only ever name more. That is
//     why this signal needs no freshness window, while the Current verdict does.
//
//  2. Absence proves nothing. A CVE missing from the changelog may be unpatched,
//     may not apply to this build at all (nginx 1.24 has no HTTP/3, so the QUIC
//     CVE of a set of five never appears), or may simply have been trimmed —
//     binary packages ship truncated changelogs. So this is read in one direction
//     only: naming a CVE can clear an advisory, never raise one. The asymmetry is
//     the same one the Verdict doc comment above insists on, for the same reason.
//
// Verified on 19 Nov 2026 against three hosts: nginx 1.24.0-2ubuntu7.20 names
// four of the five nginx2root CVEs (the fifth being the HTTP/3 one, which does
// not apply), while 1.24.0-2ubuntu7.8 on an unpatched host names none of them.
//
// One implementation note that is not an implementation detail: this reads the
// file dpkg installed, deliberately, and never `apt changelog`. That command
// fetches the changelog from repository metadata, so it describes what the
// repository holds rather than the build in front of us, and it does not
// reliably show third-party packages at all. Backported nginx and PHP packages
// from a vendor outside the distribution are exactly the case this evidence
// exists for — a host on a release with no official update left is the one most
// likely to be running one — so sourcing it from the repository would have
// silently excluded the population it was built to serve. Pointed out by Jo
// Goossens (Hosted Power) before it shipped.

// cveRef matches a CVE identifier. Case-insensitive on purpose: Ubuntu's own
// changelogs mix cases within a single entry, naming the patch file as
// "d/patches/cve-2026-42945.patch" two lines above "- CVE-2026-42945".
var cveRef = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,7}`)

// maxChangelogBytes caps how much of a changelog is read after decompression.
// Real ones are tens of kilobytes; this exists so a corrupt or hostile gzip
// cannot make the agent allocate without bound.
const maxChangelogBytes = 2 << 20 // 2 MiB

// maxFixedCVEs caps how many identifiers are reported for one package, so a
// package with a very long security history cannot bloat every audit payload.
// Oldest entries are dropped rather than newest: the recent ones are the ones an
// advisory is likely to be about.
const maxFixedCVEs = 400

// FixedCVEs returns the CVE identifiers named in the installed package's own
// changelog, and whether the changelog could be read at all.
//
// A false second return means no answer — the file is absent, unreadable, or the
// manager is one we have no reader for. It must never be treated as "this
// package fixes nothing", for the reason given at the top of this file: the
// caller would then suppress nothing, which is the safe direction, but a caller
// that inverted it would silently clear advisories on every host whose changelog
// it simply failed to open.
func FixedCVEs(manager, pkg string) ([]string, bool) {
	if pkg == "" {
		return nil, false
	}

	switch manager {
	case "apt":
		text, ok := readDebianChangelog(pkg)
		if !ok {
			return nil, false
		}
		return ParseChangelogCVEs(text), true
	case "dnf", "yum":
		out, err := exec.Command("rpm", "-q", "--changelog", pkg).Output()
		if err != nil {
			return nil, false
		}
		return ParseChangelogCVEs(string(out)), true
	}

	return nil, false
}

// readDebianChangelog finds and decompresses the changelog dpkg installed for a
// package. Both names occur: changelog.Debian.gz for a package carrying Debian
// changes on top of an upstream release, changelog.gz for a native one.
func readDebianChangelog(pkg string) (string, bool) {
	// Reject anything that is not a plain package name before building a path
	// from it. Package names cannot contain a separator, so a value that does is
	// either a bug upstream of here or an attempt to walk out of /usr/share/doc.
	if pkg != filepath.Base(pkg) || strings.ContainsAny(pkg, `/\`) {
		return "", false
	}

	dir := filepath.Join("/usr/share/doc", pkg)
	for _, name := range []string{"changelog.Debian.gz", "changelog.gz", "changelog.Debian", "changelog"} {
		text, ok := readMaybeGzipped(filepath.Join(dir, name))
		if ok {
			return text, true
		}
	}

	return "", false
}

// readMaybeGzipped reads a file, transparently decompressing it when the name
// says gzip. Reading is capped; a truncated read is still usable, since every
// entry is self-contained and the newest ones come first.
func readMaybeGzipped(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return "", false
		}
		defer zr.Close()
		r = zr
	}

	b, err := io.ReadAll(io.LimitReader(r, maxChangelogBytes))
	if err != nil && len(b) == 0 {
		return "", false
	}

	return string(b), true
}

// ParseChangelogCVEs extracts the distinct CVE identifiers from changelog text,
// upper-cased and in the order they first appear — which in both Debian and RPM
// changelogs means newest entry first, so the cap drops the oldest.
func ParseChangelogCVEs(text string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, 16)

	for _, m := range cveRef.FindAllString(text, -1) {
		id := strings.ToUpper(m)
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
		if len(out) >= maxFixedCVEs {
			break
		}
	}

	return out
}

// SortedFixedCVEs is FixedCVEs with the result sorted, for callers that want a
// stable payload rather than changelog order.
func SortedFixedCVEs(manager, pkg string) ([]string, bool) {
	ids, ok := FixedCVEs(manager, pkg)
	if !ok {
		return nil, false
	}
	sort.Strings(ids)

	return ids, true
}
