//go:build integration

package integration

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// csfAllowPath/csfDenyPath mirror csfConfPath for the two tagged list
// files every TestLabSOT* list/guard test reads or writes.
const (
	csfAllowPath = "/etc/csf/csf.allow"
	csfDenyPath  = "/etc/csf/csf.deny"
)

// csfBackupsDir is the one directory applySotPorts' underlying
// safeConfUpdate (Phase 15) ever writes a backup into.
const csfBackupsDir = "/etc/defensia/csf-backups"

// diffOnlyKeys asserts before and after (both full csf.conf byte slices)
// differ on exactly the same number of lines, and every line that did
// change is a `KEY = "..."` assignment whose KEY is in allowed -- the
// real-file proof that a multi-key port apply never touches anything
// outside the keys it was asked to change.
func diffOnlyKeys(t *testing.T, before, after []byte, allowed ...string) {
	t.Helper()
	allow := map[string]bool{}
	for _, k := range allowed {
		allow[k] = true
	}

	beforeLines := strings.Split(string(before), "\n")
	afterLines := strings.Split(string(after), "\n")
	if len(beforeLines) != len(afterLines) {
		t.Fatalf("csf.conf line count changed: before=%d after=%d", len(beforeLines), len(afterLines))
	}

	changed := 0
	for i := range beforeLines {
		if beforeLines[i] == afterLines[i] {
			continue
		}
		changed++
		key := confLineKey(beforeLines[i])
		if key == "" || !allow[key] {
			t.Fatalf("csf.conf line %d changed outside allowed keys %v:\n- %s\n+ %s", i, allowed, beforeLines[i], afterLines[i])
		}
	}
	if changed == 0 {
		t.Fatalf("csf.conf has zero changed lines, want changes restricted to %v", allowed)
	}
}

// confLineKey extracts the KEY half of a `KEY = "value"` csf.conf line,
// or "" for anything else (comments, blank lines).
func confLineKey(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return ""
	}
	idx := strings.Index(trimmed, "=")
	if idx <= 0 {
		return ""
	}
	return strings.TrimSpace(trimmed[:idx])
}

// appendRawLine appends line (with no "defensia:" ownership tag) to path
// -- a foreign csf.allow/csf.deny entry, written directly rather than
// through the agent, so the ownership guard has a real foreign line to
// refuse against. Callers must have already called backupFile(t, path)
// so the append is undone by that helper's own t.Cleanup.
func appendRawLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("append %s: %v", path, err)
	}
	defer f.Close()
	if _, err := fmt.Fprintf(f, "%s\n", line); err != nil {
		t.Fatalf("append %s: %v", path, err)
	}
}

// countLinesContaining counts the lines in path containing needle --
// used to assert a foreign line is still present (or a tagged one is
// gone) after an apply.
func countLinesContaining(t *testing.T, path, needle string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	n := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), needle) {
			n++
		}
	}
	return n
}

// canonCoversPort reports whether canon (a SotCanon-normalised port
// list: comma-separated tokens, each either a bare port "N" or a
// merged/sorted interval "N:M") covers port -- unlike a flat
// comma-token equality check (csf_ports_test.go's portInList, which
// only matches a standalone token), a real TCP_IN default like
// "20:22,25,53,..." covers port 22 via the RANGE token "20:22", not a
// bare "22" token.
func canonCoversPort(canon string, port int) bool {
	for _, tok := range strings.Split(canon, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		lo, hi, ok := strings.Cut(tok, ":")
		if !ok {
			if n, err := strconv.Atoi(lo); err == nil && n == port {
				return true
			}
			continue
		}
		loN, err1 := strconv.Atoi(lo)
		hiN, err2 := strconv.Atoi(hi)
		if err1 == nil && err2 == nil && port >= loN && port <= hiN {
			return true
		}
	}
	return false
}

// confMtime stats path and returns its ModTime, failing the test on any
// read error.
func confMtime(t *testing.T, path string) time.Time {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.ModTime()
}

// containsStr reports whether needle is exactly one of vals.
func containsStr(vals []string, needle string) bool {
	for _, v := range vals {
		if v == needle {
			return true
		}
	}
	return false
}

// onlyArgsEqual asserts calls (from countCommands' calls()) whose argv[0]
// is cmdName have, as a set (regardless of call order), exactly the
// flags in wantFlags at argv[1] -- the "-ar/-dr observed, nothing else"
// proof TestLabSOTListOps needs without caring about per-op ordering.
func flagCounts(calls [][]string, cmdName string) map[string]int {
	counts := map[string]int{}
	for _, call := range calls {
		if len(call) < 2 {
			continue
		}
		if !strings.HasSuffix(call[0], cmdName) && call[0] != cmdName {
			continue
		}
		counts[call[1]]++
	}
	return counts
}
