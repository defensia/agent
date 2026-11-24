package firewall

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// portIv is a closed interval [lo, hi], both 1-65535, lo<=hi.
type portIv struct{ lo, hi int }

// portSet is a sorted, merged (overlapping AND adjacent) list of
// intervals — the canonical in-memory form of a csf.conf port list.
type portSet []portIv

// parsePortSet parses a csf.conf-style port list ("22,80,443" or
// "30000:35000"), validates every token (1<=lo<=hi<=65535, no empty
// tokens), and returns it sorted and merged. An empty (or all-whitespace)
// string is a valid, empty set.
func parsePortSet(raw string) (portSet, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, true
	}

	var ivs []portIv
	for _, tok := range strings.Split(raw, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			return nil, false
		}

		lo, hi, isRange := strings.Cut(tok, ":")
		a, err := strconv.Atoi(lo)
		if err != nil || a < 1 || a > 65535 {
			return nil, false
		}

		b := a
		if isRange {
			if hi == "" {
				return nil, false
			}
			b, err = strconv.Atoi(hi)
			if err != nil || b < a || b > 65535 {
				return nil, false
			}
		}

		ivs = append(ivs, portIv{a, b})
	}

	return mergePortIvs(ivs), true
}

func mergePortIvs(ivs []portIv) portSet {
	if len(ivs) == 0 {
		return nil
	}

	sort.Slice(ivs, func(i, j int) bool { return ivs[i].lo < ivs[j].lo })

	merged := []portIv{ivs[0]}
	for _, x := range ivs[1:] {
		last := &merged[len(merged)-1]
		if x.lo <= last.hi+1 {
			if x.hi > last.hi {
				last.hi = x.hi
			}
		} else {
			merged = append(merged, x)
		}
	}

	return merged
}

// String renders the set in canonical form: individual ports for
// single-value intervals, "lo:hi" for ranges, comma-joined, in ascending
// order. An empty set renders as "".
func (s portSet) String() string {
	parts := make([]string, 0, len(s))
	for _, iv := range s {
		if iv.lo == iv.hi {
			parts = append(parts, strconv.Itoa(iv.lo))
		} else {
			parts = append(parts, fmt.Sprintf("%d:%d", iv.lo, iv.hi))
		}
	}

	return strings.Join(parts, ",")
}

// covers reports whether port p falls inside any interval of s.
func (s portSet) covers(p int) bool {
	for _, iv := range s {
		if p >= iv.lo && p <= iv.hi {
			return true
		}
	}

	return false
}

// coversAll reports whether every port in ps is covered by s.
func (s portSet) coversAll(ps []int) bool {
	for _, p := range ps {
		if !s.covers(p) {
			return false
		}
	}

	return true
}

// canonPorts validates and canonicalises a csf.conf port list value,
// merging overlapping/adjacent ranges and sorting ascending. Returns
// ok=false for any malformed token (out of range, non-numeric, empty
// token, inverted range).
func canonPorts(raw string) (string, bool) {
	s, ok := parsePortSet(raw)
	if !ok {
		return "", false
	}

	return s.String(), true
}

// portDiff computes the set difference between a desired and an observed
// csf.conf port list value, both already-valid raw strings. added is what
// observed has that desired doesn't; removed is what desired has that
// observed doesn't. Each side is rendered as individual ports when the
// expanded gap is small (<=64 ports) or as an interval string otherwise,
// to keep drift payloads compact for large ranges while staying readable
// for small ones.
func portDiff(desiredRaw, observedRaw string) (added, removed []string) {
	desired, ok1 := parsePortSet(desiredRaw)
	observed, ok2 := parsePortSet(observedRaw)
	if !ok1 || !ok2 {
		return nil, nil
	}

	added = renderGaps(subtractPortSets(observed, desired))
	removed = renderGaps(subtractPortSets(desired, observed))

	return added, removed
}

// subtractPortSets returns the intervals present in a but not in b, as a
// new (unmerged-across-sides, but each gap internally contiguous) portSet.
func subtractPortSets(a, b portSet) portSet {
	var gaps portSet
	for _, iv := range a {
		cur := iv.lo
		for cur <= iv.hi {
			if b.covers(cur) {
				cur++

				continue
			}
			// Extend the gap while still inside iv and still not covered by b.
			start := cur
			for cur <= iv.hi && !b.covers(cur) {
				cur++
			}
			gaps = append(gaps, portIv{start, cur - 1})
		}
	}

	return gaps
}

// renderGaps renders each gap interval as individual ports when small
// (<=64 ports), or as a single "lo:hi" token otherwise.
func renderGaps(gaps portSet) []string {
	if len(gaps) == 0 {
		return nil
	}

	out := make([]string, 0, len(gaps))
	for _, g := range gaps {
		n := g.hi - g.lo + 1
		if n <= 64 {
			for p := g.lo; p <= g.hi; p++ {
				out = append(out, strconv.Itoa(p))
			}
		} else {
			out = append(out, fmt.Sprintf("%d:%d", g.lo, g.hi))
		}
	}

	return out
}
