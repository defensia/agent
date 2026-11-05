package firewall

// Fixture-driven tests (Phase 14 plan 07, LAB-04): parse the real per-fork
// CSF artefacts captured from the lab in internal/firewall/testdata/<fork>/
// (see testdata/README.md for provenance and regeneration) through the
// plan-01 csfDir/csfExec seam. These run anywhere — Mac, CI — with no VM,
// no root, and no csf binary on PATH.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixtureExpect mirrors testdata/<fork>/expected.json.
type fixtureExpect struct {
	CSFVersion            string `json:"csf_version"`
	Variant               string `json:"variant"`
	Testing               string `json:"testing"`
	LFDActive             bool   `json:"lfd_active"`
	ConfigserverComSource bool   `json:"configserver_com_source"`
	DenyContains          string `json:"deny_contains"`
	AllowCommentContains  string `json:"allow_comment_contains"`
}

// fixtureDirs is the fixed set of fixture directories this plan captured.
// Kept explicit (not derived from os.ReadDir) so TestFixtureSetComplete can
// assert "exactly these 5, no more, no fewer" independently of whatever
// os.ReadDir happens to return.
var fixtureDirs = []string{
	"original-15.00",
	"aetherinox-15.10",
	"sentinel-15.13",
	"directadmin-15.12",
	"cwp-orphan-15.00",
}

// fixtureRequiredFiles is every file capture-fixtures.sh writes per
// directory, plus the hand-maintained expected.json. lfd-ps.txt is the one
// file allowed to be empty (cwp-orphan-15.00's lfd is not running), so it is
// checked for *existence* everywhere but only checked non-empty where the
// fixture's own expected.json says lfd_active is true.
var fixtureRequiredFiles = []string{
	"csf-v.txt", "version.txt", "downloadservers", "csf.conf", "csf.allow",
	"csf.deny", "lfd-ps.txt", "lfd-active.txt", "captured.txt", "expected.json",
}

func readFixtureExpect(t *testing.T, dir string) fixtureExpect {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", dir, "expected.json"))
	if err != nil {
		t.Fatalf("read %s/expected.json: %v", dir, err)
	}
	var exp fixtureExpect
	if err := json.Unmarshal(data, &exp); err != nil {
		t.Fatalf("parse %s/expected.json: %v", dir, err)
	}
	return exp
}

func TestFixtureSetComplete(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}

	var gotDirs []string
	for _, e := range entries {
		if e.IsDir() {
			gotDirs = append(gotDirs, e.Name())
		}
	}

	if len(gotDirs) != len(fixtureDirs) {
		t.Fatalf("testdata has %d fixture dirs %v, want exactly %d %v", len(gotDirs), gotDirs, len(fixtureDirs), fixtureDirs)
	}
	for _, want := range fixtureDirs {
		found := false
		for _, got := range gotDirs {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected fixture dir %q missing from testdata (found %v)", want, gotDirs)
		}
	}

	for _, dir := range fixtureDirs {
		exp := readFixtureExpect(t, dir)
		for _, f := range fixtureRequiredFiles {
			path := filepath.Join("testdata", dir, f)
			info, err := os.Stat(path)
			if err != nil {
				t.Errorf("%s: missing required file %s: %v", dir, f, err)
				continue
			}
			if f == "lfd-ps.txt" && !exp.LFDActive {
				// cwp-orphan-15.00: lfd is not running, so there is
				// legitimately no "lfd" process line to capture.
				continue
			}
			if info.Size() == 0 {
				t.Errorf("%s: required file %s is empty", dir, f)
			}
		}
	}
}

func TestFixturesParse(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := e.Name()
		t.Run(dir, func(t *testing.T) {
			exp := readFixtureExpect(t, dir)
			fixtureDir := filepath.Join("testdata", dir)

			csfV, err := os.ReadFile(filepath.Join(fixtureDir, "csf-v.txt"))
			if err != nil {
				t.Fatalf("read csf-v.txt: %v", err)
			}

			if got := parseCSFVersion(csfV); got != exp.CSFVersion {
				t.Errorf("parseCSFVersion() = %q, want %q (expected.csf_version)", got, exp.CSFVersion)
			}

			if !strings.Contains(string(csfV), "("+exp.Variant+")") {
				t.Errorf("csf-v.txt %q does not contain variant marker %q", string(csfV), "("+exp.Variant+")")
			}

			withCSFDir(t, fixtureDir)

			if got := csfConfigValue("TESTING"); got != exp.Testing {
				t.Errorf("csfConfigValue(TESTING) = %q, want %q", got, exp.Testing)
			}

			info := csfInfoFrom(csfV)
			if !info.Installed {
				t.Error("csfInfoFrom().Installed = false, want true")
			}
			if info.Version != exp.CSFVersion {
				t.Errorf("csfInfoFrom().Version = %q, want %q", info.Version, exp.CSFVersion)
			}
			if info.DenyCount < 1 {
				t.Errorf("csfInfoFrom().DenyCount = %d, want >= 1", info.DenyCount)
			}
			if info.AllowCount < 1 {
				t.Errorf("csfInfoFrom().AllowCount = %d, want >= 1", info.AllowCount)
			}
			if info.PortsIn == "" {
				t.Error("csfInfoFrom().PortsIn is empty, want non-empty")
			} else if !strings.Contains(info.PortsIn, "22") {
				t.Errorf("csfInfoFrom().PortsIn = %q, want it to contain \"22\"", info.PortsIn)
			}

			deny := CSFDenyList()
			foundDeny := false
			for _, e := range deny {
				if e.IP == exp.DenyContains {
					foundDeny = true
					break
				}
			}
			if !foundDeny {
				t.Errorf("CSFDenyList() = %#v, want an entry with IP %q", deny, exp.DenyContains)
			}

			allow := CSFAllowList()
			foundAllow := false
			for _, e := range allow {
				if strings.Contains(e.Comment, exp.AllowCommentContains) {
					foundAllow = true
					break
				}
			}
			if !foundAllow {
				t.Errorf("CSFAllowList() = %#v, want an entry whose comment contains %q", allow, exp.AllowCommentContains)
			}

			lfdActive, err := os.ReadFile(filepath.Join(fixtureDir, "lfd-active.txt"))
			if err != nil {
				t.Fatalf("read lfd-active.txt: %v", err)
			}
			gotActive := strings.TrimSpace(string(lfdActive)) == "active"
			if gotActive != exp.LFDActive {
				t.Errorf("lfd-active.txt = %q (active=%v), want lfd_active=%v", string(lfdActive), gotActive, exp.LFDActive)
			}
		})
	}
}

func TestFixtureDownloadservers(t *testing.T) {
	for _, dir := range fixtureDirs {
		dir := dir
		t.Run(dir, func(t *testing.T) {
			exp := readFixtureExpect(t, dir)
			data, err := os.ReadFile(filepath.Join("testdata", dir, "downloadservers"))
			if err != nil {
				t.Fatalf("read downloadservers: %v", err)
			}

			hasConfigserverCom := false
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if strings.Contains(line, "configserver.com") {
					hasConfigserverCom = true
					break
				}
			}

			if hasConfigserverCom != exp.ConfigserverComSource {
				t.Errorf("downloadservers active-line configserver.com presence = %v, want configserver_com_source=%v (raw: %q)", hasConfigserverCom, exp.ConfigserverComSource, string(data))
			}
		})
	}
}

// TestFixtureSentinelVersionQuirk documents, on its own (independent of
// TestFixturesParse), that the Sentinel fork's 15.13 release reports
// "15.11" via `csf -v` — a deliberate fork-internal version-string lag, not
// a capture mistake. A future change to parseCSFVersion that starts
// returning "15.13" here would be a real behaviour change and must fail
// this test, not be silently absorbed.
func TestFixtureSentinelVersionQuirk(t *testing.T) {
	csfV, err := os.ReadFile(filepath.Join("testdata", "sentinel-15.13", "csf-v.txt"))
	if err != nil {
		t.Fatalf("read sentinel-15.13/csf-v.txt: %v", err)
	}
	if got := parseCSFVersion(csfV); got != "15.11" {
		t.Errorf("parseCSFVersion(sentinel-15.13/csf-v.txt) = %q, want %q (release 15.13 reports 15.11)", got, "15.11")
	}
}
