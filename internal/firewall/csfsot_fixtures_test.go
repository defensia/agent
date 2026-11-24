package firewall

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// copyFixture copies the flat Phase 14 fixture directory testdata/<name>
// into a fresh t.TempDir(), points csfDir at it for the duration of the
// test (via withCSFDir), and returns the temp dir path so callers can
// mutate individual files (e.g. append a duplicate key) before observing.
func copyFixture(t *testing.T, name string) string {
	t.Helper()

	src := filepath.Join("testdata", name)
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatalf("read fixture dir %s: %v", src, err)
	}

	dst := t.TempDir()
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatalf("read fixture file %s: %v", e.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), data, 0o644); err != nil {
			t.Fatalf("write fixture file %s: %v", e.Name(), err)
		}
	}

	withCSFDir(t, dst)

	return dst
}

// confKeyLine matches an uncommented `KEY = "value"` (or `KEY="value"`)
// line, capturing the key and value separately from any surrounding
// whitespace and trailing comment.
var confKeyLine = regexp.MustCompile(`^\s*([A-Z0-9_]+)\s*=\s*"([^"]*)"`)

// saveconfReplay emulates the CSF UI's (Aetherinox DisplayUI.pm) saveconf
// action: every uncommented KEY = "value" line is rewritten with
// normalised "KEY = \"value\"" spacing and any trailing comment dropped;
// comment lines and blank lines are kept as-is. This is used to prove
// that a whole-file rewrite with zero semantic change never registers as
// drift (TestSaveconfReplayNoDrift).
func saveconfReplay(content []byte) []byte {
	lines := strings.Split(string(content), "\n")
	out := make([]string, len(lines))

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			out[i] = line

			continue
		}

		m := confKeyLine.FindStringSubmatch(line)
		if m == nil {
			out[i] = line

			continue
		}

		out[i] = m[1] + ` = "` + m[2] + `"`
	}

	return []byte(strings.Join(out, "\n"))
}

// writeConfKey rewrites (or appends) a single csf.conf key in the current
// csfDir, for tests that need to set up a specific value (e.g. a
// duplicate or unparseable key) without going through the production
// rewrite path.
func writeConfKey(t *testing.T, key, value string) {
	t.Helper()

	path := csfPath("csf.conf")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read csf.conf: %v", err)
	}

	lines := strings.Split(string(data), "\n")
	replaced := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		m := confKeyLine.FindStringSubmatch(line)
		if m != nil && m[1] == key {
			lines[i] = key + ` = "` + value + `"`
			replaced = true
		}
	}
	if !replaced {
		lines = append(lines, key+` = "`+value+`"`)
	}

	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatalf("write csf.conf: %v", err)
	}
}

// appendConfLine appends a raw line to the current csfDir's csf.conf
// (used to create a genuine duplicate-key scenario: writeConfKey replaces
// every existing occurrence, so a duplicate needs a raw append instead).
func appendConfLine(t *testing.T, line string) {
	t.Helper()

	path := csfPath("csf.conf")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open csf.conf for append: %v", err)
	}
	defer f.Close()

	if _, err := f.WriteString("\n" + line); err != nil {
		t.Fatalf("append to csf.conf: %v", err)
	}
}
