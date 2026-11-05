package firewall

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseCSFConf(t *testing.T) {
	conf := "" +
		"TESTING = \"1\"\n" +
		"TESTING=\"0\"\n" + // later line wins, no-space form
		"AUTO_UPDATES = \"1\" # comment\n" +
		"# LF_DAEMON = \"0\"\n" + // commented out: ignored entirely
		"  IPV6 = \"1\"\n" + // leading spaces
		"BAD LINE\n" + // malformed: ignored
		""

	vals, dups := parseCSFConf(strings.NewReader(conf))

	if got := vals["TESTING"]; got != "0" {
		t.Errorf("vals[TESTING] = %q, want %q (later line wins)", got, "0")
	}
	if dups["TESTING"] != 2 {
		t.Errorf("dups[TESTING] = %d, want 2", dups["TESTING"])
	}
	if got := vals["AUTO_UPDATES"]; got != "1" {
		t.Errorf("vals[AUTO_UPDATES] = %q, want %q", got, "1")
	}
	if _, ok := vals["LF_DAEMON"]; ok {
		t.Errorf("vals[LF_DAEMON] present = %v, want absent (commented out)", vals["LF_DAEMON"])
	}
	if got := vals["IPV6"]; got != "1" {
		t.Errorf("vals[IPV6] = %q, want %q (leading spaces tolerated)", got, "1")
	}
	if _, ok := vals["BAD"]; ok {
		t.Errorf("malformed line produced a key: %v", vals)
	}
	if _, ok := vals["MISSING"]; ok {
		t.Errorf("vals[MISSING] present, want absent")
	}
}

func TestConfBoolInt(t *testing.T) {
	m := map[string]string{
		"TESTING_ON":  "1",
		"TESTING_OFF": "0",
		"TESTING_YES": "yes",
		"LIMIT":       "200",
		"LIMIT_BAD":   "abc",
	}

	if got := confBool(m, "TESTING_ON"); got == nil || *got != true {
		t.Errorf("confBool(TESTING_ON) = %v, want *true", got)
	}
	if got := confBool(m, "TESTING_OFF"); got == nil || *got != false {
		t.Errorf("confBool(TESTING_OFF) = %v, want *false", got)
	}
	if got := confBool(m, "TESTING_YES"); got != nil {
		t.Errorf("confBool(TESTING_YES) = %v, want nil", *got)
	}
	if got := confBool(m, "ABSENT"); got != nil {
		t.Errorf("confBool(ABSENT) = %v, want nil", *got)
	}

	if got := confInt(m, "LIMIT"); got == nil || *got != 200 {
		t.Errorf("confInt(LIMIT) = %v, want *200", got)
	}
	if got := confInt(m, "LIMIT_BAD"); got != nil {
		t.Errorf("confInt(LIMIT_BAD) = %v, want nil", *got)
	}
	if got := confInt(m, "ABSENT"); got != nil {
		t.Errorf("confInt(ABSENT) = %v, want nil", *got)
	}
}

// TestParseCSFVersionRobust extends TestParseCSFVersion (csf_test.go) with the
// ANSI-stripping and RPM-release-suffix cases Phase 15 adds, plus a negative
// case ("version 1.2") that must never be mistaken for a "vX.Y" token.
func TestParseCSFVersionRobust(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want string
	}{
		{"original 15.00", "csf: v15.00 (generic)", "15.00"},
		{
			"warning then version line",
			"*WARNING* URLGET set to use LWP but perl module is not installed, reverting to HTTP::Tiny\ncsf: v15.00 (generic)",
			"15.00",
		},
		{
			"aetherinox multi-line",
			"ConfigServer Security & Firewall\nv15.10 (generic)\nLicense: None\nChannel: Stable Channel",
			"15.10",
		},
		{"ANSI coloured TTY banner", "\x1b[1;32mv15.10\x1b[0m (generic)", "15.10"},
		{"cpanel RPM release suffix", "csf: v16.34-1 (cPanel)", "16.34-1"},
		{"legacy short form", "csf: v14.20", "14.20"},
		{"empty output", "", ""},
		{"garbage output", "garbage\n", ""},
		{"word starting with v is not a version", "version 1.2", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseCSFVersion([]byte(tc.out))
			if got != tc.want {
				t.Errorf("parseCSFVersion(%q) = %q, want %q", tc.out, got, tc.want)
			}
		})
	}
}

func TestReadCSFVersionFile(t *testing.T) {
	dir := t.TempDir()
	withCSFDir(t, dir)

	writeVersion := func(content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "version.txt"), []byte(content), 0o644); err != nil {
			t.Fatalf("write version.txt: %v", err)
		}
	}

	writeVersion("15.12\n")
	if got := readCSFVersionFile(); got != "15.12" {
		t.Errorf("readCSFVersionFile() = %q, want %q", got, "15.12")
	}

	writeVersion("16.34-1")
	if got := readCSFVersionFile(); got != "16.34-1" {
		t.Errorf("readCSFVersionFile() = %q, want %q", got, "16.34-1")
	}

	writeVersion("junk")
	if got := readCSFVersionFile(); got != "" {
		t.Errorf("readCSFVersionFile() with junk content = %q, want empty", got)
	}

	// Missing file.
	withCSFDir(t, t.TempDir())
	if got := readCSFVersionFile(); got != "" {
		t.Errorf("readCSFVersionFile() with missing file = %q, want empty", got)
	}
}
