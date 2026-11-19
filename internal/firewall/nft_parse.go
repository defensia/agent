package firewall

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// parseNftSetElements parses the `elem` array out of `nft -j list set ...`
// output. Each element is either a bare JSON string, an object
// {"elem":{"val": <value>, ...}} (val itself may be a string, a
// {"prefix":{"addr","len"}} or a {"range":[a,b]} for interval sets), or
// (defensively) a bare prefix/range object with no elem/val wrapper.
func parseNftSetElements(js []byte) ([]string, error) {
	var top struct {
		Nftables []struct {
			Set *struct {
				Elem []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(js, &top); err != nil {
		return nil, fmt.Errorf("parse nft set JSON: %w", err)
	}

	var out []string
	for _, entry := range top.Nftables {
		if entry.Set == nil {
			continue
		}
		for _, raw := range entry.Set.Elem {
			v, err := decodeNftSetElem(raw)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
	}
	return out, nil
}

// decodeNftSetElem decodes one item of a set's "elem" array.
func decodeNftSetElem(raw json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil
	}

	var wrapper struct {
		Elem struct {
			Val json.RawMessage `json:"val"`
		} `json:"elem"`
	}
	if err := json.Unmarshal(raw, &wrapper); err == nil && len(wrapper.Elem.Val) > 0 {
		return decodeNftSetElemValue(wrapper.Elem.Val)
	}

	return decodeNftSetElemValue(raw)
}

// decodeNftSetElemValue decodes a value that is either a bare string, a
// {"prefix":{"addr","len"}} (interval CIDR), or a {"range":[a,b]} (interval
// range) — rendered "addr/len" and "a-b" respectively.
func decodeNftSetElemValue(raw json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil
	}

	var v struct {
		Prefix *struct {
			Addr string `json:"addr"`
			Len  int    `json:"len"`
		} `json:"prefix"`
		Range []string `json:"range"`
	}
	if err := json.Unmarshal(raw, &v); err == nil {
		if v.Prefix != nil {
			return fmt.Sprintf("%s/%d", v.Prefix.Addr, v.Prefix.Len), nil
		}
		if len(v.Range) == 2 {
			return v.Range[0] + "-" + v.Range[1], nil
		}
	}

	return "", fmt.Errorf("unrecognized nft set element value: %s", string(raw))
}

// nftRuleRef is one rule's handle and comment, as listed via
// `nft -j -a list chain ...`.
type nftRuleRef struct {
	Handle  int
	Comment string
}

// parseNftChainRules parses every "rule" entry's handle and comment.
// Rules without a comment are kept, with Comment == "" — callers filter by
// comment prefix themselves (nftRuleKeyPrefix / nftGeoKeyPrefix).
func parseNftChainRules(js []byte) ([]nftRuleRef, error) {
	var top struct {
		Nftables []struct {
			Rule *struct {
				Handle  int    `json:"handle"`
				Comment string `json:"comment"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(js, &top); err != nil {
		return nil, fmt.Errorf("parse nft chain rules JSON: %w", err)
	}

	var out []nftRuleRef
	for _, entry := range top.Nftables {
		if entry.Rule == nil {
			continue
		}
		out = append(out, nftRuleRef{Handle: entry.Rule.Handle, Comment: entry.Rule.Comment})
	}
	return out, nil
}

// nftVersionRe matches the version triplet out of `nft --version` output,
// e.g. "nftables v1.0.6 (Lester Gooch #5)".
var nftVersionRe = regexp.MustCompile(`nftables v(\d+)\.(\d+)\.(\d+)`)

// parseNftVersion extracts major/minor/patch from `nft --version` output.
// ok is false when the output does not look like an nft version string.
func parseNftVersion(out string) (maj, minor, patch int, ok bool) {
	m := nftVersionRe.FindStringSubmatch(out)
	if m == nil {
		return 0, 0, 0, false
	}
	maj, _ = strconv.Atoi(m[1])
	minor, _ = strconv.Atoi(m[2])
	patch, _ = strconv.Atoi(m[3])
	return maj, minor, patch, true
}

// nftVersionAtLeast reports whether `nft --version`'s output is >= minVersion
// ("major.minor.patch"). An unparseable version is never "at least" anything.
func nftVersionAtLeast(out, minVersion string) bool {
	maj, minor, patch, ok := parseNftVersion(out)
	if !ok {
		return false
	}
	want := strings.Split(minVersion, ".")
	if len(want) != 3 {
		return false
	}
	wantMaj, _ := strconv.Atoi(want[0])
	wantMinor, _ := strconv.Atoi(want[1])
	wantPatch, _ := strconv.Atoi(want[2])

	if maj != wantMaj {
		return maj > wantMaj
	}
	if minor != wantMinor {
		return minor > wantMinor
	}
	return patch >= wantPatch
}

// isNftNotFound reports whether nft's combined output is nftables' way of
// saying "that element/rule/set/table doesn't exist" — never an error for an
// unban/remove of something already gone.
func isNftNotFound(out []byte) bool {
	return strings.Contains(string(out), "No such file or directory")
}
