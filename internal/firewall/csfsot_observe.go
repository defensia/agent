package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/defensia/agent/internal/csfsotwire"
)

// sotPortKeys/sotPortKeys6 are the csf.conf keys the source-of-truth
// feature manages. The *6 keys are only ever in scope when IPV6="1" AND
// the key is actually present in the fork's csf.conf (tri-state absent:
// a key missing from the file is simply out of scope, never a problem).
var sotPortKeys = []string{"TCP_IN", "TCP_OUT", "UDP_IN", "UDP_OUT"}

var sotPortKeys6 = []string{"TCP6_IN", "TCP6_OUT", "UDP6_IN", "UDP6_OUT"}

// Shared wire type aliases so the rest of this package can keep using the
// short "Sot*" names while the actual definitions live in the leaf
// package internal/csfsotwire (shared with internal/api, no import
// cycle).
type (
	SotEntry     = csfsotwire.Entry
	SotProblem   = csfsotwire.Problem
	SotManaged   = csfsotwire.Managed
	SotDriftItem = csfsotwire.DriftItem
)

// sotObservation is the full read-only snapshot of the managed CSF scope
// plus everything the ingest/apply layers need to make decisions without
// re-reading the files themselves.
type sotObservation struct {
	Managed SotManaged

	IPv6        bool
	ManagedKeys []string
	Problems    []SotProblem

	// ForeignAllow/ForeignDeny hold the IP/CIDR values of NON-tagged
	// plain entries, for the ownership checks Decision 3 requires before
	// any add/remove (never touch another tool's entry for the same IP).
	ForeignAllow map[string]bool
	ForeignDeny  map[string]bool

	DenyTotal   int
	DenyIPLimit int
	Testing     bool

	ConfMtime time.Time
}

// observeSot reads csf.conf, csf.allow and csf.deny (and stats
// csf.disable) and returns everything the source-of-truth feature needs
// to know about the current managed scope. It never execs a command and
// never writes a file (SOT-02: activation is a read-only snapshot).
func observeSot() (sotObservation, error) {
	vals, dups, err := readCSFConf()
	if err != nil {
		return sotObservation{}, fmt.Errorf("read csf.conf: %w", err)
	}

	obs := sotObservation{
		ForeignAllow: map[string]bool{},
		ForeignDeny:  map[string]bool{},
	}

	obs.IPv6 = confBool(vals, "IPV6") != nil && *confBool(vals, "IPV6")
	obs.Testing = confBool(vals, "TESTING") != nil && *confBool(vals, "TESTING")
	if lim := confInt(vals, "DENY_IP_LIMIT"); lim != nil {
		obs.DenyIPLimit = *lim
	}

	ports := map[string]string{}
	keys := sotPortKeys
	if obs.IPv6 {
		keys = append(append([]string{}, sotPortKeys...), sotPortKeys6...)
	}

	for _, key := range keys {
		value, present := vals[key]
		if !present {
			continue // tri-state absent: simply not in scope, never a problem
		}

		if dups[key] > 1 {
			obs.Problems = append(obs.Problems, SotProblem{Reason: "duplicate_key", Detail: key})

			continue
		}

		if _, ok := canonPorts(value); !ok {
			obs.Problems = append(obs.Problems, SotProblem{Reason: "unparseable", Detail: key})

			continue
		}

		ports[key] = value
		obs.ManagedKeys = append(obs.ManagedKeys, key)
	}
	sort.Strings(obs.ManagedKeys)
	obs.Managed.Ports = ports

	if _, err := os.Stat(csfPath("csf.disable")); err == nil {
		obs.Problems = append(obs.Problems, SotProblem{Reason: "csf_disabled"})
	}

	if st, err := os.Stat(csfPath("csf.conf")); err == nil {
		obs.ConfMtime = st.ModTime()
	}

	allow, allowForeign, err := observeList(csfPath("csf.allow"))
	if err != nil {
		return sotObservation{}, fmt.Errorf("read csf.allow: %w", err)
	}
	obs.Managed.Allow = allow
	obs.ForeignAllow = allowForeign

	deny, denyForeign, total, err := observeDenyList(csfPath("csf.deny"))
	if err != nil {
		return sotObservation{}, fmt.Errorf("read csf.deny: %w", err)
	}
	obs.Managed.Deny = deny
	obs.ForeignDeny = denyForeign
	obs.DenyTotal = total

	return obs, nil
}

// observeList reads a csf.allow/csf.deny file (read-only, no hashing)
// and splits its plain ip/cidr entries into tagged (managed) and foreign
// (everyone else's), per Decision 3: only entries whose comment starts
// with "defensia:" (after stripping any CSF-appended date) are managed.
func observeList(path string) (tagged []SotEntry, foreign map[string]bool, err error) {
	foreign = map[string]bool{}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, foreign, nil
		}

		return nil, foreign, err
	}

	for _, line := range strings.Split(string(data), "\n") {
		entry, ok := classifyCSFLine(line)
		if !ok {
			continue
		}
		if entry.Kind != "ip" && entry.Kind != "cidr" {
			continue // advanced/include/other lines are never managed or foreign-tracked
		}

		comment := stripCSFDate(entry.Comment)
		if isSotTag(comment) {
			tagged = append(tagged, SotEntry{Value: entry.Value, Comment: comment})
		} else {
			foreign[entry.Value] = true
		}
	}

	return tagged, foreign, nil
}

// observeDenyList is observeList plus the total (uncapped) entry count
// Decision 3's DENY_IP_LIMIT drift-hint needs.
func observeDenyList(path string) (tagged []SotEntry, foreign map[string]bool, total int, err error) {
	foreign = map[string]bool{}

	data, rerr := os.ReadFile(path)
	if rerr != nil {
		if os.IsNotExist(rerr) {
			return nil, foreign, 0, nil
		}

		return nil, foreign, 0, rerr
	}

	for _, line := range strings.Split(string(data), "\n") {
		entry, ok := classifyCSFLine(line)
		if !ok {
			continue
		}
		total++
		if entry.Kind != "ip" && entry.Kind != "cidr" {
			continue
		}

		comment := stripCSFDate(entry.Comment)
		if isSotTag(comment) {
			tagged = append(tagged, SotEntry{Value: entry.Value, Comment: comment})
		} else {
			foreign[entry.Value] = true
		}
	}

	return tagged, foreign, total, nil
}

// isSotTag reports whether a (date-stripped) csf.allow/csf.deny comment
// marks the entry as owned by Defensia.
func isSotTag(comment string) bool {
	return strings.HasPrefix(strings.TrimSpace(comment), "defensia:")
}

// csfDateSuffix matches the " - <Weekday> <Mon> <d> <hh:mm:ss> <yyyy>"
// suffix csf -a/-d appends to the comment it was given.
var csfDateSuffix = regexp.MustCompile(
	`\s+-\s+(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}\s*$`,
)

// stripCSFDate removes a trailing CSF-appended date suffix from a
// csf.allow/csf.deny comment, if present.
func stripCSFDate(comment string) string {
	return strings.TrimSpace(csfDateSuffix.ReplaceAllString(comment, ""))
}

// sotHashShape is the exact JSON shape CONTRACT §8 hashes: Allow/Deny as
// sorted value-only strings (comment ignored), Ports in canonical form.
// Field order matches the contract's literal example byte-for-byte.
type sotHashShape struct {
	Allow []string          `json:"allow"`
	Deny  []string          `json:"deny"`
	Ports map[string]string `json:"ports"`
}

// sotHash computes the CONTRACT §8 hash of a managed scope: formatting
// differences (order, spacing, quote style, a whole-file saveconf
// rewrite) never change it, because every value is canonicalised first.
func sotHash(m SotManaged) string {
	shape := sotHashShape{
		Allow: sortedEntryValues(m.Allow),
		Deny:  sortedEntryValues(m.Deny),
		Ports: map[string]string{},
	}
	for key, raw := range m.Ports {
		canon, ok := canonPorts(raw)
		if !ok {
			canon = raw // defensive: unparseable values never reach here in practice
		}
		shape.Ports[key] = canon
	}

	b, _ := json.Marshal(shape)
	sum := sha256.Sum256(b)

	return hex.EncodeToString(sum[:])
}

func sortedEntryValues(entries []SotEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Value)
	}
	sort.Strings(out)

	return out
}

// sotFingerprint is a cheap "did anything change" signal: size+mtime of
// csf.conf/csf.allow/csf.deny plus whether csf.disable exists. Any
// metadata change (including ones that wouldn't change the hash, like a
// touch) changes the fingerprint.
func sotFingerprint() string {
	var b strings.Builder
	for _, name := range []string{"csf.conf", "csf.allow", "csf.deny"} {
		st, err := os.Stat(csfPath(name))
		if err != nil {
			fmt.Fprintf(&b, "%s:absent|", name)

			continue
		}
		fmt.Fprintf(&b, "%s:%d:%d|", name, st.Size(), st.ModTime().UnixNano())
	}

	_, disableErr := os.Stat(csfPath("csf.disable"))
	fmt.Fprintf(&b, "disable:%v", disableErr == nil)

	return b.String()
}

// diffSot computes the drift between a desired and an observed managed
// scope. Items are returned in a deterministic order: all port items
// first (sorted by key), then allow items (sorted by value), then deny
// items (sorted by value) — so two calls on equal inputs always produce
// byte-identical output.
func diffSot(desired, observed SotManaged) []SotDriftItem {
	var items []SotDriftItem

	keys := map[string]bool{}
	for k := range desired.Ports {
		keys[k] = true
	}
	for k := range observed.Ports {
		keys[k] = true
	}
	sortedKeys := make([]string, 0, len(keys))
	for k := range keys {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	for _, key := range sortedKeys {
		dv, ov := desired.Ports[key], observed.Ports[key]
		dc, _ := canonPorts(dv)
		oc, _ := canonPorts(ov)
		if dc == oc {
			continue
		}

		added, removed := portDiff(dv, ov)
		items = append(items, SotDriftItem{Kind: "port", Key: key, Added: added, Removed: removed})
	}

	items = append(items, diffEntries("allow", desired.Allow, observed.Allow)...)
	items = append(items, diffEntries("deny", desired.Deny, observed.Deny)...)

	return items
}

// diffEntries compares two tagged-entry lists by value and returns one
// drift item per value that appears on only one side, sorted by value.
func diffEntries(kind string, desired, observed []SotEntry) []SotDriftItem {
	d := map[string]bool{}
	for _, e := range desired {
		d[e.Value] = true
	}
	o := map[string]bool{}
	for _, e := range observed {
		o[e.Value] = true
	}

	var values []string
	seen := map[string]bool{}
	for v := range d {
		if !seen[v] {
			values = append(values, v)
			seen[v] = true
		}
	}
	for v := range o {
		if !seen[v] {
			values = append(values, v)
			seen[v] = true
		}
	}
	sort.Strings(values)

	var items []SotDriftItem
	for _, v := range values {
		inD, inO := d[v], o[v]
		if inD == inO {
			continue
		}

		change := "added"
		if inD && !inO {
			change = "removed"
		}
		items = append(items, SotDriftItem{Kind: kind, Value: v, Change: change})
	}

	return items
}
