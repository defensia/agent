//go:build integration

package firewall

import (
	"context"
	"net/netip"
)

// This file exists ONLY in integration builds (the //go:build tag
// above): `go build ./...` (the production build) never compiles it
// in, and there is no runtime flag or code path in the production
// binary that reaches any of these -- same convention as
// csf_fault_integration.go. Every wrapper here re-observes the live
// managed scope itself (never caches), so a real-VM lab test always
// sees exactly what a real reconcile cycle would see.

// SotObserve reads the managed CSF scope read-only and returns it, its
// canonical hash, and any precheck problems -- the same call the real
// engine makes every cycle (observeSot), exported for lab tests.
func SotObserve() (SotManaged, string, []SotProblem, error) {
	obs, err := observeSot()
	if err != nil {
		return SotManaged{}, "", nil, err
	}

	return obs.Managed, sotHash(obs.Managed), obs.Problems, nil
}

// SotSaveconfNoDrift reports whether two observed scopes are identical
// (diffSot returns no items) -- the lab's saveconf-replay-equals-no-
// drift proof.
func SotSaveconfNoDrift(before, after SotManaged) bool {
	return len(diffSot(before, after)) == 0
}

// SotApplyPorts re-observes the current scope and writes want through
// the real guarded path (applySotPorts), returning a flat result/
// reason/backup triple so the lab test never has to reach into
// SotApplyResult's internals.
func SotApplyPorts(ctx context.Context, want map[string]string) (result, reason, backup string) {
	obs, err := observeSot()
	if err != nil {
		return "error", err.Error(), ""
	}

	res := applySotPorts(ctx, want, obs)

	return res.Result, sotApplyReason(res), res.Backup
}

// SotApplyLists re-observes the current scope and applies desired's
// tagged allow/deny entries through the real guarded path
// (applySotLists). No panel IP is known to the lab (the would_block_panel
// guard is not under test here), so an invalid netip.Addr is passed.
func SotApplyLists(ctx context.Context, desired SotManaged) (result string, refusals []string) {
	obs, err := observeSot()
	if err != nil {
		return "error", []string{err.Error()}
	}

	res := applySotLists(ctx, desired, obs, netip.Addr{})
	for _, r := range res.Refusals {
		refusals = append(refusals, r.Reason)
	}

	return res.Result, refusals
}

func sotApplyReason(res SotApplyResult) string {
	if res.Err != nil {
		return res.Err.Reason
	}
	if len(res.Refusals) > 0 {
		return res.Refusals[0].Reason
	}

	return ""
}

// SotSessionIPs reports the peer IPs of every currently ESTABLISHED SSH
// session on sshPorts, as strings.
func SotSessionIPs(ctx context.Context, sshPorts []int) ([]string, error) {
	addrs, err := sshSessionIPs(ctx, sshPorts)
	if err != nil {
		return nil, err
	}

	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.String()
	}

	return out, nil
}

// SotGuardAllowRemoval reports the refusal reason (empty string when
// none) for removing value from csf.allow right now, given sshPorts --
// the ssh_session_ip guard's real-VM proof. sshPorts is required here
// (unlike the plan's terse pseudo-signature) because the guard itself
// cannot determine whether a removal would cut a live SSH session
// without knowing which ports are SSH.
func SotGuardAllowRemoval(ctx context.Context, value string, sshPorts []int) string {
	r := guardAllowRemoval(ctx, value, sshPorts)
	if r == nil {
		return ""
	}

	return r.Reason
}

// SotCanon returns raw's canonical port-list form (merged, sorted
// intervals). Returns raw unchanged if it does not parse.
func SotCanon(raw string) string {
	canon, ok := canonPorts(raw)
	if !ok {
		return raw
	}

	return canon
}

// SotActiveSSHPorts reports the ports sshd is currently listening on, the
// same detection the engine itself uses to decide which ports the
// ssh_port_in_use guard must never let TCP_IN drop -- exported so a lab
// test can assert TCP_IN's canonical form actually contains every one of
// them without duplicating the detection logic.
func SotActiveSSHPorts(ctx context.Context) []int {
	ports, _ := sshPortsFn(ctx)
	return ports
}
