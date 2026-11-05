package firewall

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestParseCSFListKinds covers every classification branch classifyCSFLine
// must distinguish: ip, cidr, advanced (CSF's pipe-delimited filter
// syntax), include, other, and the lines that aren't entries at all.
func TestParseCSFListKinds(t *testing.T) {
	cases := []struct {
		name        string
		line        string
		wantOK      bool
		wantValue   string
		wantKind    string
		wantComment string
	}{
		{"ip with comment", "203.0.113.9 # lfd: x", true, "203.0.113.9", "ip", "lfd: x"},
		{"cidr", "198.51.100.0/24", true, "198.51.100.0/24", "cidr", ""},
		{"ipv6", "2001:db8::1", true, "2001:db8::1", "ip", ""},
		{"advanced filter", "tcp|in|d=22|s=198.51.100.7 # adv", true, "tcp|in|d=22|s=198.51.100.7", "advanced", "adv"},
		{"include directive", "Include /etc/csf/extra.deny", true, "Include /etc/csf/extra.deny", "include", ""},
		{"hostname", "hostname.example", true, "hostname.example", "other", ""},
		{"full-line comment", "# just a comment", false, "", "", ""},
		{"blank line", "   ", false, "", "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entry, ok := classifyCSFLine(tc.line)
			if ok != tc.wantOK {
				t.Fatalf("classifyCSFLine(%q) ok = %v, want %v", tc.line, ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if entry.Value != tc.wantValue {
				t.Errorf("classifyCSFLine(%q).Value = %q, want %q", tc.line, entry.Value, tc.wantValue)
			}
			if entry.Kind != tc.wantKind {
				t.Errorf("classifyCSFLine(%q).Kind = %q, want %q", tc.line, entry.Kind, tc.wantKind)
			}
			if entry.Comment != tc.wantComment {
				t.Errorf("classifyCSFLine(%q).Comment = %q, want %q", tc.line, entry.Comment, tc.wantComment)
			}
		})
	}
}

// TestCSFDenyListAdvancedNotIP proves the misparse fix: an advanced filter
// line in csf.allow (directadmin-15.12's real fixture has two: "tcp|out|u=0"
// and "udp|out|u=0", both "Give root account full access") is never
// presented with IP set, while the real IP entry in the same file keeps its
// IP populated as before.
func TestCSFDenyListAdvancedNotIP(t *testing.T) {
	withCSFDir(t, "testdata/directadmin-15.12")

	allow := CSFAllowList()
	if len(allow) < 3 {
		t.Fatalf("CSFAllowList() len = %d, want >= 3 (2 advanced + 1 ip) (%#v)", len(allow), allow)
	}

	sawAdvanced, sawIP := false, false
	for _, e := range allow {
		if e.Kind == "advanced" {
			sawAdvanced = true
			if e.IP != "" {
				t.Errorf("advanced entry %#v has IP set, want empty (this is the misparse bug)", e)
			}
			if !strings.Contains(e.Comment, "Give root account full access") {
				t.Errorf("advanced entry %#v does not match the fixture's expected comment", e)
			}
		}
		if e.Kind == "ip" {
			sawIP = true
			if e.IP == "" {
				t.Errorf("ip entry %#v has empty IP", e)
			}
		}
	}
	if !sawAdvanced {
		t.Error("CSFAllowList() never classified any entry as advanced — fixture or classifier regressed")
	}
	if !sawIP {
		t.Error("CSFAllowList() never classified any entry as ip — fixture or classifier regressed")
	}

	// Phase 14's own fixture test (TestFixturesParse) already pins that
	// CSFAllowList() still finds the "lab-panel" comment and CSFDenyList()
	// still finds "203.0.113.9" across all 5 fixtures — that test is left
	// untouched and must keep passing (see <verify> for this task).
}

// TestListsCap50k proves the collector stays fast and bounded even against
// a pathologically large csf.deny: 50,000 lines, every 7th one carrying an
// oversized (300-char) comment that must be truncated to 200 before being
// counted.
func TestListsCap50k(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "csf.deny")

	var b strings.Builder
	const n = 50000
	for i := 0; i < n; i++ {
		ip := fmt.Sprintf("198.18.%d.%d", (i/256)%256, i%256)
		if i%7 == 0 {
			fmt.Fprintf(&b, "%s # %s\n", ip, strings.Repeat("c", 300))
		} else {
			fmt.Fprintf(&b, "%s\n", ip)
		}
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write csf.deny: %v", err)
	}

	start := time.Now()
	list := readCSFList(path, sha256.New())
	elapsed := time.Since(start)

	if len(list.Entries) != csfListCap {
		t.Errorf("len(Entries) = %d, want %d", len(list.Entries), csfListCap)
	}
	if list.Total != n {
		t.Errorf("Total = %d, want %d", list.Total, n)
	}
	if !list.Truncated {
		t.Error("Truncated = false, want true")
	}
	for _, e := range list.Entries {
		if len([]rune(e.Comment)) > csfCommentMax {
			t.Fatalf("entry %#v has a comment longer than %d runes", e, csfCommentMax)
		}
	}
	if elapsed > time.Second {
		t.Errorf("readCSFList(50k lines) took %s, want < 1s", elapsed)
	}
}

// TestListsLongValueSkipped proves an over-long value (longer than
// csfValueMax) is counted in Total but never added to Entries, and still
// sets Truncated.
func TestListsLongValueSkipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "csf.deny")

	long := strings.Repeat("a", 400)
	if err := os.WriteFile(path, []byte(long+"\n"), 0o644); err != nil {
		t.Fatalf("write csf.deny: %v", err)
	}

	list := readCSFList(path, sha256.New())
	if list.Total != 1 {
		t.Errorf("Total = %d, want 1", list.Total)
	}
	if len(list.Entries) != 0 {
		t.Errorf("len(Entries) = %d, want 0", len(list.Entries))
	}
	if !list.Truncated {
		t.Error("Truncated = false, want true")
	}
}

// TestListsHashStable proves readCSFLists' hash is: (1) stable across
// repeated reads of unchanged content, (2) sensitive to any content change
// including one past the 1000-entry cap (line 49,999 of a 50k-line file),
// and (3) always 64 hex chars.
func TestListsHashStable(t *testing.T) {
	dir := t.TempDir()
	withCSFDir(t, dir)

	writeLists := func(denyExtra string) {
		var b strings.Builder
		for i := 0; i < 50000; i++ {
			ip := fmt.Sprintf("198.18.%d.%d", (i/256)%256, i%256)
			if i == 49999 {
				fmt.Fprintf(&b, "%s # %s\n", ip, denyExtra)
			} else {
				fmt.Fprintf(&b, "%s\n", ip)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, "csf.deny"), []byte(b.String()), 0o644); err != nil {
			t.Fatalf("write csf.deny: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "csf.allow"), []byte("1.1.1.1\n"), 0o644); err != nil {
			t.Fatalf("write csf.allow: %v", err)
		}
	}

	writeLists("first")
	_, _, hash1 := readCSFLists()
	_, _, hash2 := readCSFLists()
	if hash1 != hash2 {
		t.Errorf("hash changed across two reads of unchanged content: %q != %q", hash1, hash2)
	}
	if len(hash1) != 64 {
		t.Errorf("len(hash) = %d, want 64 (hex sha256)", len(hash1))
	}

	writeLists("second")
	_, _, hash3 := readCSFLists()
	if hash1 == hash3 {
		t.Error("hash unchanged after changing the comment on line 49,999 (past the 1000-entry cap) — hash does not cover the full list")
	}
}

// TestListsMissingFiles proves readCSFList/readCSFLists degrade cleanly
// when csf.deny/csf.allow are simply absent.
func TestListsMissingFiles(t *testing.T) {
	withCSFDir(t, t.TempDir())

	deny, allow, hashHex := readCSFLists()

	if deny.Total != 0 || allow.Total != 0 {
		t.Errorf("Total = deny:%d allow:%d, want 0/0", deny.Total, allow.Total)
	}
	if deny.Entries == nil || allow.Entries == nil {
		t.Errorf("Entries = deny:%#v allow:%#v, want non-nil empty slices", deny.Entries, allow.Entries)
	}
	if len(deny.Entries) != 0 || len(allow.Entries) != 0 {
		t.Errorf("len(Entries) = deny:%d allow:%d, want 0/0", len(deny.Entries), len(allow.Entries))
	}
	if deny.Truncated || allow.Truncated {
		t.Error("Truncated = true for a missing file, want false")
	}
	if len(hashHex) != 64 {
		t.Errorf("len(hash) = %d, want 64 (hex sha256) even with no files", len(hashHex))
	}
}
