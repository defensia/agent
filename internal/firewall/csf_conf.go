package firewall

import (
	"bufio"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// confLine matches `KEY = "value"` and `KEY="value"` (with or without a
// trailing comment); csf.conf tolerates both forms across forks.
var confLine = regexp.MustCompile(`^\s*([A-Z0-9_]+)\s*=\s*"([^"]*)"`)

// ansiRe strips ANSI colour/cursor escape sequences (e.g. a TTY-coloured
// `csf -v` banner) before version parsing.
var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// verRe matches a version token at the start of a `csf -v` output line, after
// an optional "csf:" prefix: "csf: v15.00 (generic)", "v15.10 (generic)",
// "csf: v16.34-1 (cPanel)", "csf: v14.20". It deliberately does not match
// "version 1.2" (no literal "v" immediately followed by a digit).
var verRe = regexp.MustCompile(`^(?:csf:\s*)?v(\d+\.\d+(?:\.\d+)?(?:-\d+)?)(?:\s|$|\()`)

// verFileRe validates the content of version.txt: a bare version number,
// optionally with a patch segment and/or an RPM-style "-N" release suffix.
var verFileRe = regexp.MustCompile(`^\d+\.\d+(?:\.\d+)?(?:-\d+)?$`)

// parseCSFConf tolerantly parses a csf.conf stream into a map of key -> value
// (absent key means absent from the map, never an empty string — this is the
// tri-state the collector needs: present-and-empty vs. not-present-at-all are
// different facts). dups counts how many uncommented occurrences of each key
// were seen; when a key appears more than once (malformed, but it happens),
// the LAST uncommented occurrence wins, matching how CSF's own perl config
// reader behaves.
func parseCSFConf(r io.Reader) (vals map[string]string, dups map[string]int) {
	vals = map[string]string{}
	dups = map[string]int{}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)

	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		m := confLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key, val := m[1], m[2]
		vals[key] = val
		dups[key]++
	}

	return vals, dups
}

// readCSFConf opens and parses csf.conf from the current csfDir seam.
func readCSFConf() (map[string]string, map[string]int, error) {
	f, err := os.Open(csfPath("csf.conf"))
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	vals, dups := parseCSFConf(f)
	return vals, dups, nil
}

// confBool interprets a csf.conf boolean value ("1"/"0"). Any other value
// (absent key, "yes", garbage) returns nil — tri-state, never a guessed
// default.
func confBool(m map[string]string, key string) *bool {
	v, ok := m[key]
	if !ok {
		return nil
	}
	switch v {
	case "1":
		b := true
		return &b
	case "0":
		b := false
		return &b
	default:
		return nil
	}
}

// confInt interprets a csf.conf integer value. Absent key or a non-numeric
// value both return nil.
func confInt(m map[string]string, key string) *int {
	v, ok := m[key]
	if !ok {
		return nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return nil
	}
	return &n
}

// readCSFVersionFile reads /etc/csf/version.txt (relative to the csfDir seam),
// which every CSF fork writes directly (no exec, no ANSI, no suffix text) and
// which this package prefers over parsing `csf -v` output. Returns "" if the
// file is absent or its content doesn't look like a version string.
func readCSFVersionFile() string {
	data, err := os.ReadFile(csfPath("version.txt"))
	if err != nil {
		return ""
	}
	first := strings.TrimSpace(strings.SplitN(string(data), "\n", 2)[0])
	if !verFileRe.MatchString(first) {
		return ""
	}
	return first
}
