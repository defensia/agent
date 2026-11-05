package firewall

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// Fork identifiers. Report-only: never branch agent behaviour on the fork in
// Phase 15 — unknown must keep everything working exactly like every other
// value.
const (
	ForkCPanel       = "cpanel"
	ForkDirectAdmin  = "directadmin"
	ForkAetherinox   = "aetherinox"
	ForkSentinel     = "sentinel"
	ForkOriginal1500 = "original-15.00"
	ForkUnknown      = "unknown"
)

// forkEnv carries every signal detectFork needs to tell CSF forks apart.
// `csf -v`'s own panel-name suffix (GENERIC/DirectAdmin/CWP/...) is NOT part
// of this struct and is never used as evidence — it comes straight from a
// csf.conf flag the admin can set on any fork, including plain original CSF
// running on a server that also happens to have a control panel installed.
type forkEnv struct {
	Version         string            // from version.txt, else parsed csf -v
	CSFVOutput      string            // raw csf -v (non-TTY)
	Conf            map[string]string // parsed csf.conf
	DownloadServers []string          // active (non-#, non-empty) lines
	HasPath         func(p string) bool
	ReadHead        func(p string, n int) string
	RPMHasCPanelCSF bool // `rpm -q cpanel-csf` exit 0 (plan 02 only, when rpm exists)
}

// detectFork identifies the CSF fork from evidence, never from the version
// number alone (overlapping release numbers across forks make that
// unreliable — see 15-RESEARCH.md). Rules are ordered, first match wins.
// Evidence is capped (8 entries, 100 chars each) and always non-empty.
func detectFork(e forkEnv) (fork string, evidence []string) {
	if e.HasPath == nil {
		e.HasPath = defaultHasPath
	}
	if e.ReadHead == nil {
		e.ReadHead = defaultReadHead
	}
	if e.Conf == nil {
		e.Conf = map[string]string{}
	}

	// 1. cpanel
	if e.RPMHasCPanelCSF {
		return ForkCPanel, capEvidence("rpm:cpanel-csf")
	}
	if majorVersion(e.Version) >= 16 && e.HasPath("/usr/local/cpanel") {
		return ForkCPanel, capEvidence("version>=16", "dir:/usr/local/cpanel")
	}

	// 2. sentinel
	if e.HasPath("/usr/local/csf/lib/Sentinel") {
		return ForkSentinel, capEvidence("dir:/usr/local/csf/lib/Sentinel")
	}
	if containsFold(e.ReadHead("/usr/local/csf/bin/csf.pl", 80), "use Sentinel::") ||
		containsFold(e.ReadHead("/usr/sbin/csf", 80), "use Sentinel::") {
		return ForkSentinel, capEvidence("module:Sentinel")
	}
	if anyContainsFold(e.DownloadServers, "sentinelfw") || anyContainsFold(e.DownloadServers, "sentinelfirewall") {
		return ForkSentinel, capEvidence("downloadservers:sentinel")
	}

	// 3. aetherinox
	if anyContainsFold(e.DownloadServers, "configserver.dev") || anyContainsFold(e.DownloadServers, "aetherinox") {
		return ForkAetherinox, capEvidence("downloadservers:configserver.dev")
	}
	if hasLicenseChannelBanner(e.CSFVOutput) {
		return ForkAetherinox, capEvidence("csf-v:license-channel")
	}

	// 4. original-15.00
	if e.Version == "15.00" {
		return ForkOriginal1500, capEvidence("version:15.00")
	}

	// 5. directadmin: a DirectAdmin signal (conf flag or binary) combined
	// with a version genuinely newer than the unforked 15.00 baseline — a
	// DIRECTADMIN=1 flag alone, on an old pre-fork 15.00 install, is not
	// enough (rule 4 above already claimed that version as original-15.00).
	daEvidence := ""
	if e.Conf["DIRECTADMIN"] == "1" {
		daEvidence = "conf:DIRECTADMIN=1"
	} else if e.HasPath("/usr/local/directadmin/directadmin") {
		daEvidence = "bin:/usr/local/directadmin"
	}
	if daEvidence != "" && compareVersions(e.Version, "15.00") > 0 {
		return ForkDirectAdmin, capEvidence(daEvidence)
	}

	// 6. unknown — still report what we know; never breaks anything else.
	if e.Version == "" {
		return ForkUnknown, capEvidence("none")
	}
	return ForkUnknown, capEvidence("version:" + e.Version)
}

func containsFold(haystack, needle string) bool {
	if haystack == "" {
		return false
	}
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func anyContainsFold(list []string, needle string) bool {
	for _, s := range list {
		if containsFold(s, needle) {
			return true
		}
	}
	return false
}

// hasLicenseChannelBanner reports whether out (ANSI-stripped) has both a line
// starting "License:" and a line starting "Channel:" — the Aetherinox
// doversion banner shape, verified from source (15-RESEARCH.md Pattern 2).
func hasLicenseChannelBanner(out string) bool {
	stripped := ansiRe.ReplaceAllString(out, "")
	hasLicense, hasChannel := false, false
	for _, line := range strings.Split(stripped, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "License:") {
			hasLicense = true
		}
		if strings.HasPrefix(line, "Channel:") {
			hasChannel = true
		}
	}
	return hasLicense && hasChannel
}

// majorVersion returns the first numeric segment of v (ignoring an RPM-style
// "-N" release suffix), or 0 when v doesn't start with a number.
func majorVersion(v string) int {
	main, _, _ := strings.Cut(v, "-")
	parts := strings.Split(main, ".")
	n, _ := strconv.Atoi(parts[0])
	return n
}

// compareVersions does a numeric, per-segment comparison of a and b (up to 3
// segments), ignoring any RPM-style "-N" release suffix. Returns 1 if a>b, -1
// if a<b, 0 if equal (including when both are unparsable/empty).
func compareVersions(a, b string) int {
	aMain, _, _ := strings.Cut(a, "-")
	bMain, _, _ := strings.Cut(b, "-")
	aParts := strings.Split(aMain, ".")
	bParts := strings.Split(bMain, ".")
	for i := 0; i < 3; i++ {
		av, bv := 0, 0
		if i < len(aParts) {
			av, _ = strconv.Atoi(aParts[i])
		}
		if i < len(bParts) {
			bv, _ = strconv.Atoi(bParts[i])
		}
		if av != bv {
			if av > bv {
				return 1
			}
			return -1
		}
	}
	return 0
}

func defaultHasPath(p string) bool {
	_, err := os.Stat(hostPath(p))
	return err == nil
}

func defaultReadHead(p string, n int) string {
	f, err := os.Open(hostPath(p))
	if err != nil {
		return ""
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	var lines []string
	for i := 0; i < n && sc.Scan(); i++ {
		lines = append(lines, sc.Text())
	}
	return strings.Join(lines, "\n")
}

// capEvidence enforces the evidence-list contract: at most 8 entries, each at
// most 100 chars.
func capEvidence(evidence ...string) []string {
	if len(evidence) > 8 {
		evidence = evidence[:8]
	}
	out := make([]string, len(evidence))
	for i, ev := range evidence {
		if len(ev) > 100 {
			ev = ev[:100]
		}
		out[i] = ev
	}
	return out
}
