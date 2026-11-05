package firewall

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"net"
	"os"
	"strings"
)

// csfListCap matches the panel's own ingest cap (POST /api/v1/agent/csf/lists,
// 15-10): 1000 entries per list.
const csfListCap = 1000

// csfCommentMax/csfValueMax keep a single malformed line from blowing the
// panel's 1 MiB body cap on its own.
const (
	csfCommentMax = 200
	csfValueMax   = 256
)

// CSFListEntry is one classified csf.deny/csf.allow line.
type CSFListEntry struct {
	Value   string `json:"value"`
	Kind    string `json:"kind"`
	Comment string `json:"comment,omitempty"`
}

// CSFList is a capped, classified view of a csf.deny/csf.allow file. Total
// is the real line count (uncapped) so the panel always knows how much was
// truncated.
type CSFList struct {
	Entries   []CSFListEntry `json:"entries"`
	Total     int            `json:"total"`
	Truncated bool           `json:"truncated"`
}

// classifyCSFLine classifies a single csf.deny/csf.allow line. ok is false
// for blank lines and full-line comments, which are not entries at all.
//
// This is the fix for the CSFDenyList misparse: the old csfListEntries just
// split every line on '#' and called whatever was left of it an "IP". An
// advanced filter line (csf's own documented
// "tcp/udp|in/out|s/d=port,port,...|s/d=ip" syntax) or an "Include <path>"
// directive both split into a left half that is NOT an IP — it was being
// presented as one anyway.
func classifyCSFLine(line string) (CSFListEntry, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return CSFListEntry{}, false
	}

	// "Include " is a CSF directive, checked before splitting on '#' (the
	// included path itself never contains one in practice, but a trailing
	// comment might).
	if strings.HasPrefix(trimmed, "Include ") {
		value := trimmed
		if idx := strings.Index(value, "#"); idx >= 0 {
			value = strings.TrimSpace(value[:idx])
		}
		return CSFListEntry{Value: value, Kind: "include"}, true
	}

	value, comment := trimmed, ""
	if idx := strings.Index(trimmed, "#"); idx >= 0 {
		value = strings.TrimSpace(trimmed[:idx])
		comment = strings.TrimSpace(trimmed[idx+1:])
	}
	if value == "" {
		return CSFListEntry{}, false
	}

	return CSFListEntry{Value: value, Kind: classifyCSFValue(value), Comment: comment}, true
}

// classifyCSFValue classifies the value half of a csf.deny/csf.allow entry
// (after stripping any trailing "# comment"): "advanced" for CSF's
// pipe-delimited advanced filter syntax, "ip"/"cidr" for a real address,
// "other" for anything else (a hostname, which CSF itself ignores, or
// something unrecognised).
func classifyCSFValue(value string) string {
	if strings.Contains(value, "|") {
		return "advanced"
	}
	if net.ParseIP(value) != nil {
		return "ip"
	}
	if _, _, err := net.ParseCIDR(value); err == nil {
		return "cidr"
	}
	return "other"
}

// readCSFList streams path (a csf.deny or csf.allow file) through
// classifyCSFLine, capping the returned Entries at csfListCap while still
// counting every line in Total and writing every classified entry into h —
// the hash must cover the FULL list, not just the capped slice that gets
// returned, or a change past entry 1000 would never change the hash and the
// panel's hash-gated upload would never fire for it.
func readCSFList(path string, h hash.Hash) CSFList {
	list := CSFList{Entries: []CSFListEntry{}}

	f, err := os.Open(path)
	if err != nil {
		return list
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)

	for sc.Scan() {
		entry, ok := classifyCSFLine(sc.Text())
		if !ok {
			continue
		}
		list.Total++

		entry.Comment = truncateRunes(entry.Comment, csfCommentMax)

		fmt.Fprintf(h, "%s\x1f%s\x1f%s\n", entry.Value, entry.Kind, entry.Comment)

		if len(entry.Value) > csfValueMax {
			list.Truncated = true
			continue
		}
		if len(list.Entries) >= csfListCap {
			list.Truncated = true
			continue
		}
		list.Entries = append(list.Entries, entry)
	}

	return list
}

// readCSFLists reads csf.deny then csf.allow from the current csfDir seam,
// returning both capped+classified lists plus a single sha256 hash (hex)
// covering both files' full, uncapped content in a stable order — reading
// the files sequentially and hashing as we go, never via an intermediate
// map or sorted structure, is what keeps the hash order-independent of
// nothing but the files' own on-disk order (which CSF itself never
// reorders between heartbeats unless the lists actually change).
func readCSFLists() (deny, allow CSFList, hashHex string) {
	h := sha256.New()
	h.Write([]byte("deny\n"))
	deny = readCSFList(csfPath("csf.deny"), h)
	h.Write([]byte("allow\n"))
	allow = readCSFList(csfPath("csf.allow"), h)
	return deny, allow, hex.EncodeToString(h.Sum(nil))
}

// truncateRunes truncates s to at most max runes (never splitting a
// multi-byte character in two).
func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max])
}
