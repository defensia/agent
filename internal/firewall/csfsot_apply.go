package firewall

import (
	"context"
	"net/netip"
	"os"
	"sort"
	"strings"
)

// SotApplyResult is the outcome of one applySotPorts/applySotLists call.
type SotApplyResult struct {
	Result        string // applied | unchanged | refused | error | skipped
	Refusals      []SotRefusal
	Err           *SotRefusal // reason reload_failed | rollback_failed | write_failed | backup_failed | csf_not_installed
	Backup        string
	RolledBack    bool
	SelfWriteHash string   // sotHash after a successful write
	Changed       []string // keys ("TCP_IN") or "allow:<v>"/"deny:<v>"
}

// applySotPorts writes a multi-key port change through Phase 15's safe
// path (one backup, one atomic rewrite, one csf -r, rollback on
// failure), guarded end to end: never runs when paused/disabled, never
// touches a key the observation flagged as a problem, never leaves an
// active SSH port closed, and is a no-op when every requested value
// already canonically matches what's on disk.
func applySotPorts(ctx context.Context, want map[string]string, obs sotObservation) SotApplyResult {
	if CSFPaused() {
		return SotApplyResult{Result: "skipped"}
	}

	if csfDisabledProblem(obs.Problems) {
		return SotApplyResult{Result: "refused", Refusals: []SotRefusal{{Reason: "csf_disabled"}}}
	}

	if ref := guardScope(want); ref != nil {
		return SotApplyResult{Result: "refused", Refusals: []SotRefusal{*ref}}
	}

	changed := map[string]string{}
	var refusals []SotRefusal
	for _, key := range sortedKeys(want) {
		raw := want[key]
		if prob := keyProblem(obs.Problems, key); prob != nil {
			refusals = append(refusals, SotRefusal{Reason: prob.Reason, Detail: key})

			continue
		}

		wantCanon, ok := canonPorts(raw)
		if !ok {
			refusals = append(refusals, SotRefusal{Reason: "unparseable", Detail: key})

			continue
		}

		obsCanon, _ := canonPorts(obs.Managed.Ports[key])
		if wantCanon == obsCanon {
			continue
		}

		changed[key] = raw
	}

	if len(changed) == 0 {
		if len(refusals) > 0 {
			return SotApplyResult{Result: "refused", Refusals: refusals}
		}

		return SotApplyResult{Result: "unchanged"}
	}

	csfWriteMu.Lock()
	defer csfWriteMu.Unlock()

	bin := csfBinaryPath()
	if bin == "" {
		return SotApplyResult{Result: "error", Err: &SotRefusal{Reason: "csf_not_installed"}}
	}

	origInfo, err := os.Stat(csfPath("csf.conf"))
	if err != nil {
		return SotApplyResult{Result: "error", Err: &SotRefusal{Reason: "write_failed"}}
	}
	origBytes, err := os.ReadFile(csfPath("csf.conf"))
	if err != nil {
		return SotApplyResult{Result: "error", Err: &SotRefusal{Reason: "write_failed"}}
	}
	conf, _ := parseCSFConf(strings.NewReader(string(origBytes)))

	// Re-observe under the lock: state may have changed since the
	// caller's obs. Guard against the RESULTING port set (fresh observed
	// values merged with the change), not `changed` in isolation.
	fresh, err := observeSot()
	if err != nil {
		return SotApplyResult{Result: "error", Err: &SotRefusal{Reason: "write_failed"}}
	}
	resulting := map[string]string{}
	for k, v := range fresh.Managed.Ports {
		resulting[k] = v
	}
	for k, v := range changed {
		resulting[k] = v
	}
	if ref := guardPorts(ctx, resulting); ref != nil {
		return SotApplyResult{Result: "refused", Refusals: append(refusals, *ref)}
	}

	result := safeConfUpdate(ctx, changed, origBytes, origInfo, conf, bin)

	switch result.Result {
	case "applied":
		selfHash := ""
		if after, err := observeSot(); err == nil {
			selfHash = sotHash(after.Managed)
		}

		return SotApplyResult{
			Result:        "applied",
			Backup:        result.Backup,
			Changed:       sortedKeys(changed),
			SelfWriteHash: selfHash,
		}
	case "failed":
		return SotApplyResult{
			Result:     "error",
			Err:        &SotRefusal{Reason: "reload_failed", Detail: result.Reason},
			Backup:     result.Backup,
			RolledBack: result.RolledBack,
		}
	case "rollback_failed":
		return SotApplyResult{
			Result:     "error",
			Err:        &SotRefusal{Reason: "rollback_failed"},
			Backup:     result.Backup,
			RolledBack: result.RolledBack,
		}
	default: // "rejected": backup_failed | write_failed | key_missing | duplicate_key | ...
		reason := result.Reason
		if reason == "" {
			reason = "write_failed"
		}

		return SotApplyResult{Result: "error", Err: &SotRefusal{Reason: reason}, Backup: result.Backup}
	}
}

// applySotLists reconciles the tagged allow/deny lists: removals before
// additions, allow before deny, each entry applied independently via the
// CSF CLI (csfSotArgv's 4-op allowlist), never touching a foreign entry,
// and guarded against disconnecting an active SSH session or blocking
// the panel's own address.
func applySotLists(ctx context.Context, desired SotManaged, obs sotObservation, panelIP netip.Addr) SotApplyResult {
	if CSFPaused() {
		return SotApplyResult{Result: "skipped"}
	}

	if csfDisabledProblem(obs.Problems) {
		return SotApplyResult{Result: "refused", Refusals: []SotRefusal{{Reason: "csf_disabled"}}}
	}

	bin := csfBinaryPath()
	if bin == "" {
		return SotApplyResult{Result: "error", Err: &SotRefusal{Reason: "csf_not_installed"}}
	}

	sshPorts, _ := sshPortsFn(ctx)
	if len(sshPorts) == 0 {
		sshPorts = []int{22}
	}

	type listOp struct {
		kind, action, value, comment string
	}

	var ops []listOp
	for _, v := range removedValues(obs.Managed.Allow, desired.Allow) {
		ops = append(ops, listOp{"allow", "remove", v, ""})
	}
	for _, v := range removedValues(obs.Managed.Deny, desired.Deny) {
		ops = append(ops, listOp{"deny", "remove", v, ""})
	}
	for _, e := range addedEntries(obs.Managed.Allow, desired.Allow) {
		ops = append(ops, listOp{"allow", "add", e.Value, e.Comment})
	}
	for _, e := range addedEntries(obs.Managed.Deny, desired.Deny) {
		ops = append(ops, listOp{"deny", "add", e.Value, e.Comment})
	}

	if len(ops) == 0 {
		return SotApplyResult{Result: "unchanged"}
	}

	var refusals []SotRefusal
	var changed []string
	applied := false

	for _, o := range ops {
		var refusal *SotRefusal

		switch {
		case o.kind == "allow" && o.action == "remove":
			if obs.ForeignAllow[o.value] {
				refusal = &SotRefusal{Reason: "foreign_entry_same_ip", Detail: o.value}
			} else {
				refusal = guardAllowRemoval(ctx, o.value, sshPorts)
			}
		case o.kind == "deny" && o.action == "remove":
			if obs.ForeignDeny[o.value] {
				refusal = &SotRefusal{Reason: "foreign_entry_same_ip", Detail: o.value}
			}
		case o.kind == "allow" && o.action == "add":
			if obs.ForeignAllow[o.value] {
				refusal = &SotRefusal{Reason: "foreign_entry_same_ip", Detail: o.value}
			} else if obs.ForeignDeny[o.value] {
				refusal = &SotRefusal{Reason: "would_remove_foreign_deny", Detail: o.value}
			}
		case o.kind == "deny" && o.action == "add":
			if obs.ForeignDeny[o.value] {
				refusal = &SotRefusal{Reason: "foreign_entry_same_ip", Detail: o.value}
			} else {
				refusal = guardDenyAdd(ctx, o.value, sshPorts, panelIP)
			}
		}

		if refusal != nil {
			refusals = append(refusals, *refusal)

			continue
		}

		op := o.kind + "_" + o.action
		comment := ""
		if o.action == "add" {
			comment = o.comment
			if comment == "" {
				comment = "defensia:sot"
			}
		}

		argv, err := csfSotArgv(op, o.value, comment)
		if err != nil {
			refusals = append(refusals, SotRefusal{Reason: "forbidden_command", Detail: o.value})

			continue
		}

		out, err := run(ctx, csfExecTimeout, bin, argv...)
		if err != nil {
			if strings.Contains(strings.ToLower(string(out)), "already in") {
				refusals = append(refusals, SotRefusal{Reason: "foreign_entry_same_ip", Detail: o.value})
			} else {
				refusals = append(refusals, SotRefusal{Reason: "agent_error", Detail: truncateStr(string(out), 200)})
			}

			continue
		}

		applied = true
		changed = append(changed, o.kind+":"+o.value)
	}

	result := "refused"
	if applied {
		result = "applied"
	}

	return SotApplyResult{Result: result, Refusals: refusals, Changed: changed}
}

func csfDisabledProblem(problems []SotProblem) bool {
	for _, p := range problems {
		if p.Reason == "csf_disabled" {
			return true
		}
	}

	return false
}

func keyProblem(problems []SotProblem, key string) *SotProblem {
	for _, p := range problems {
		if p.Detail == key && (p.Reason == "duplicate_key" || p.Reason == "unparseable") {
			return &p
		}
	}

	return nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)

	return out
}

// removedValues returns the values present in observed but absent from
// desired, sorted for deterministic ordering.
func removedValues(observed, desired []SotEntry) []string {
	want := map[string]bool{}
	for _, e := range desired {
		want[e.Value] = true
	}

	var out []string
	for _, e := range observed {
		if !want[e.Value] {
			out = append(out, e.Value)
		}
	}
	sort.Strings(out)

	return out
}

// addedEntries returns the entries present in desired but absent from
// observed, sorted by value for deterministic ordering.
func addedEntries(observed, desired []SotEntry) []SotEntry {
	have := map[string]bool{}
	for _, e := range observed {
		have[e.Value] = true
	}

	var out []SotEntry
	for _, e := range desired {
		if !have[e.Value] {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Value < out[j].Value })

	return out
}

func truncateStr(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}

	return s[:max]
}
