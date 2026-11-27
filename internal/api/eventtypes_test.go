package api

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestNeverAggregateLocked(t *testing.T) {
	severities := []string{"info", "warning", "high", "critical"}
	for lockedType := range lockedNeverAggregate {
		for _, sev := range severities {
			e := EventRequest{Type: lockedType, Severity: sev}

			if got := ShouldAggregate(e, nil); got {
				t.Errorf("ShouldAggregate(%s/%s, nil) = true, want false (locked)", lockedType, sev)
			}

			// A permissive panelTypes that explicitly allows this type must
			// not un-lock it — the lock is not configurable.
			permissive := map[string]bool{lockedType: true}
			if got := ShouldAggregate(e, permissive); got {
				t.Errorf("ShouldAggregate(%s/%s, permissive panelTypes) = true, want false (locked)", lockedType, sev)
			}
		}
	}
}

func TestNeverAggregateCritical(t *testing.T) {
	for aggType := range aggregatableTypes {
		e := EventRequest{Type: aggType, Severity: "critical"}
		if got := ShouldAggregate(e, nil); got {
			t.Errorf("ShouldAggregate(%s/critical, nil) = true, want false", aggType)
		}
		permissive := map[string]bool{aggType: true}
		if got := ShouldAggregate(e, permissive); got {
			t.Errorf("ShouldAggregate(%s/critical, permissive panelTypes) = true, want false", aggType)
		}
	}
}

func TestUnknownTypeFailSafe(t *testing.T) {
	for _, sev := range []string{"info", "warning", "high"} {
		e := EventRequest{Type: "brand_new_type", Severity: sev}
		if got := ShouldAggregate(e, nil); got {
			t.Errorf("ShouldAggregate(brand_new_type/%s, nil) = true, want false (fail-safe)", sev)
		}
		// Even a panelTypes map that names the unknown type explicitly must
		// not enable it: panelTypes can only restrict the agent's own
		// structural allowlist, never extend it past what the agent itself
		// recognizes.
		permissive := map[string]bool{"brand_new_type": true}
		if got := ShouldAggregate(e, permissive); got {
			t.Errorf("ShouldAggregate(brand_new_type/%s, permissive panelTypes) = true, want false", sev)
		}
	}
}

func TestPanelTypesOnlyRestrict(t *testing.T) {
	// Pick one real aggregatable type to prove panelTypes can enable it,
	// and pair it in the same panelTypes map with a locked type and an
	// unknown type to prove those two stay false regardless.
	var sample string
	for typ := range aggregatableTypes {
		sample = typ
		break
	}
	var locked string
	for typ := range lockedNeverAggregate {
		locked = typ
		break
	}

	panelTypes := map[string]bool{
		sample:           true,
		locked:           true,
		"brand_new_type": true,
	}

	if got := ShouldAggregate(EventRequest{Type: sample, Severity: "info"}, panelTypes); !got {
		t.Errorf("ShouldAggregate(%s/info, panelTypes) = false, want true", sample)
	}
	if got := ShouldAggregate(EventRequest{Type: locked, Severity: "info"}, panelTypes); got {
		t.Errorf("ShouldAggregate(%s/info, panelTypes containing it) = true, want false (locked)", locked)
	}
	if got := ShouldAggregate(EventRequest{Type: "brand_new_type", Severity: "info"}, panelTypes); got {
		t.Error("ShouldAggregate(brand_new_type/info, panelTypes containing it) = true, want false (unknown)")
	}

	// A restrictive panelTypes that omits the sample type must turn it off.
	restrictive := map[string]bool{"some_other_type": true}
	if got := ShouldAggregate(EventRequest{Type: sample, Severity: "info"}, restrictive); got {
		t.Errorf("ShouldAggregate(%s/info, restrictive panelTypes) = true, want false", sample)
	}
}

func TestAllowlistShape(t *testing.T) {
	for t2 := range aggregatableTypes {
		if lockedNeverAggregate[t2] {
			t.Errorf("aggregatableTypes and lockedNeverAggregate both contain %q, they must be disjoint", t2)
		}
		if !botTypes[t2] && !webTypes[t2] {
			t.Errorf("aggregatableTypes contains %q, which is in neither botTypes nor webTypes", t2)
		}
	}
}

// --- Source scan: every type literal the agent emits -----------------------

// typeFromEventRequestLiteral matches the Type field directly inside an
// EventRequest{...} struct literal, within a bounded lookahead window
// (handled by the caller) so a later, unrelated struct literal's own Type
// field is never mistaken for this one.
var typeFromEventRequestLiteral = regexp.MustCompile(`Type:\s*"([a-z0-9_]+)"`)

// onEventCallWithLiteralType matches an onEvent(...) call whose type
// argument is a string literal, in either calling convention used in this
// codebase: onEvent(ip, "type", severity, ...) (watcher package, ip is an
// unquoted identifier or, in one case, a quoted IP literal) and
// onEvent("type", severity, ...) (session package, no ip argument). Calls
// where the type argument is itself a variable (e.g. onEvent(ip, reason,
// ...)) do not match and are intentionally not counted — this is a
// best-effort literal scan, not a full Go evaluator.
var onEventCallWithLiteralType = regexp.MustCompile(
	`onEvent\(\s*(?:[A-Za-z0-9_.]+\s*,\s*|"(?:\d{1,3}\.){3}\d{1,3}"\s*,\s*)?"([a-z0-9_]+)"`,
)

// scanEmittedEventTypes walks the given root directories (relative to this
// package's directory) and collects every event type literal found via the
// two patterns above, skipping _test.go files.
func scanEmittedEventTypes(t *testing.T, roots ...string) map[string]bool {
	t.Helper()
	found := make(map[string]bool)

	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			content := string(raw)

			for _, idx := range allIndexes(content, "EventRequest{") {
				start := idx + len("EventRequest{")
				end := start + 400
				if end > len(content) {
					end = len(content)
				}
				window := content[start:end]
				if m := typeFromEventRequestLiteral.FindStringSubmatch(window); m != nil {
					found[m[1]] = true
				}
			}

			for _, m := range onEventCallWithLiteralType.FindAllStringSubmatch(content, -1) {
				found[m[1]] = true
			}

			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", root, err)
		}
	}

	return found
}

func allIndexes(s, substr string) []int {
	var out []int
	offset := 0
	for {
		i := strings.Index(s[offset:], substr)
		if i < 0 {
			return out
		}
		out = append(out, offset+i)
		offset += i + len(substr)
	}
}

func TestEveryEmittedTypeClassified(t *testing.T) {
	found := scanEmittedEventTypes(t, "../../cmd", "..")

	if len(found) < 15 {
		t.Fatalf("found only %d event type literals, want >= 15 (sanity floor): %v", len(found), sortedKeys(found))
	}

	for typ := range found {
		if strings.HasPrefix(typ, "malware_") && !lockedNeverAggregate[typ] {
			t.Errorf("emitted type %q starts with malware_ but is not in lockedNeverAggregate", typ)
		}
	}
}

// knownRejectedByPanel pins the exact set of emitted type literals that the
// panel's EventController does NOT currently accept, as of the panel base
// this plan was executed against. Expected empty: on the current panel base
// the controller already accepts every type literal found by the scan
// above. If a future scan finds this non-empty, pin the new list here and
// treat it as a finding to report, not something to silently absorb.
var knownRejectedByPanel = []string{}

func TestEmittedTypesAcceptedByPanel(t *testing.T) {
	found := scanEmittedEventTypes(t, "../../cmd", "..")

	raw, err := os.ReadFile(filepath.Join("testdata", "contracts", "accepted_event_types.json"))
	if err != nil {
		t.Fatalf("reading accepted_event_types.json: %v", err)
	}
	var accepted []string
	if err := json.Unmarshal(raw, &accepted); err != nil {
		t.Fatalf("unmarshaling accepted_event_types.json: %v", err)
	}
	acceptedSet := make(map[string]bool, len(accepted))
	for _, a := range accepted {
		acceptedSet[a] = true
	}

	var missing []string
	for typ := range found {
		if !acceptedSet[typ] {
			missing = append(missing, typ)
		}
	}
	sort.Strings(missing)

	want := append([]string{}, knownRejectedByPanel...)
	sort.Strings(want)

	if !equalStringSlices(missing, want) {
		t.Fatalf("emitted types rejected by the panel = %v, want %v (knownRejectedByPanel)", missing, want)
	}
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
