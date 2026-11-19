package firewall

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strings"

	"github.com/defensia/agent/internal/csfsotwire"
)

// errForbiddenCommand is returned by csfSotArgv for anything outside its
// 4-op allowlist, or for a malformed value/comment — the caller maps it
// to the wire reason "forbidden_command" (CONTRACT §6).
var errForbiddenCommand = errors.New("forbidden_command")

// SotRefusal is the wire shape of a guard refusal (CONTRACT §2 refused[]).
type SotRefusal = csfsotwire.Refusal

// sessionIPsFn is the test seam for sshSessionIPs.
var sessionIPsFn = sshSessionIPs

// sotManagedKeySet is the complete set of csf.conf keys this feature may
// ever touch — anything else is refused with out_of_scope_key before any
// write is even attempted.
var sotManagedKeySet = map[string]bool{
	"TCP_IN": true, "TCP_OUT": true, "UDP_IN": true, "UDP_OUT": true,
	"TCP6_IN": true, "TCP6_OUT": true, "UDP6_IN": true, "UDP6_OUT": true,
}

// guardScope refuses any desired-ports map containing a key outside
// sotManagedKeySet, before anything is read from or written to disk.
func guardScope(want map[string]string) *SotRefusal {
	for key := range want {
		if !sotManagedKeySet[key] {
			return logRefusal(&SotRefusal{Reason: "out_of_scope_key", Detail: key})
		}
	}

	return nil
}

// guardPorts refuses a desired-ports map that would leave any active SSH
// port out of TCP_IN or TCP6_IN (interval-aware: 22 inside "20:30"
// counts as open). An empty/unknown SSH-port answer is treated as [22]
// (never as "nothing to protect").
func guardPorts(ctx context.Context, want map[string]string) *SotRefusal {
	sshPorts, _ := sshPortsFn(ctx)
	if len(sshPorts) == 0 {
		sshPorts = []int{22}
	}

	for _, key := range []string{"TCP_IN", "TCP6_IN"} {
		raw, present := want[key]
		if !present {
			continue
		}

		set, ok := parsePortSet(raw)
		if !ok {
			continue // unparseable is reported elsewhere, not a guard concern
		}
		for _, p := range sshPorts {
			if !set.covers(p) {
				return logRefusal(&SotRefusal{Reason: "ssh_port_in_use", Detail: itoaSafe(p)})
			}
		}
	}

	return nil
}

func itoaSafe(n int) string {
	return fmt.Sprintf("%d", n)
}

// guardAllowRemoval refuses removing an allow entry whose IP/CIDR covers
// the peer IP of a live SSH session. Fails closed: if the session lookup
// itself errors, the removal is refused (detail "unknown") rather than
// risk disconnecting an admin whose session we simply couldn't see.
func guardAllowRemoval(ctx context.Context, value string, sshPorts []int) *SotRefusal {
	sessions, err := sessionIPsFn(ctx, sshPorts)
	if err != nil {
		return logRefusal(&SotRefusal{Reason: "ssh_session_ip", Detail: "unknown"})
	}

	prefix, ok := coveringPrefix(value)
	if !ok {
		return nil
	}
	for _, s := range sessions {
		if prefix.Contains(s) {
			return logRefusal(&SotRefusal{Reason: "ssh_session_ip", Detail: s.String()})
		}
	}

	return nil
}

// guardDenyAdd refuses adding a deny entry that would cover a live SSH
// session IP or the panel/API address itself.
func guardDenyAdd(ctx context.Context, value string, sshPorts []int, panelIP netip.Addr) *SotRefusal {
	prefix, ok := coveringPrefix(value)
	if !ok {
		return nil
	}

	if panelIP.IsValid() && prefix.Contains(panelIP) {
		return logRefusal(&SotRefusal{Reason: "would_block_panel", Detail: value})
	}

	sessions, err := sessionIPsFn(ctx, sshPorts)
	if err != nil {
		return logRefusal(&SotRefusal{Reason: "ssh_session_ip", Detail: "unknown"})
	}
	for _, s := range sessions {
		if prefix.Contains(s) {
			return logRefusal(&SotRefusal{Reason: "ssh_session_ip", Detail: s.String()})
		}
	}

	return nil
}

// coveringPrefix parses value (an IP or CIDR string) into a netip.Prefix
// that Contains() can be checked against; a bare IP becomes a /32 (or
// /128) prefix.
func coveringPrefix(value string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(value); err == nil {
		return p, true
	}
	if a, err := netip.ParseAddr(value); err == nil {
		bits := 32
		if a.Is6() {
			bits = 128
		}
		p, err := a.Prefix(bits)

		return p, err == nil
	}

	return netip.Prefix{}, false
}

// csfSotArgv builds the argv for exactly one of the four CSF list
// operations this feature may ever run, refusing anything else with
// forbidden_command. The comment, when given, must always start with
// "defensia:" (ownership tag) and value must parse as an IP or CIDR.
func csfSotArgv(op, value, comment string) ([]string, error) {
	if _, ok := coveringPrefix(value); !ok {
		return nil, fmt.Errorf("%w: value %q is not a valid IP/CIDR", errForbiddenCommand, value)
	}

	switch op {
	case "allow_add":
		if !strings.HasPrefix(comment, "defensia:") {
			return nil, fmt.Errorf("%w: comment %q does not start with defensia:", errForbiddenCommand, comment)
		}

		return []string{"-a", value, comment}, nil
	case "allow_remove":
		return []string{"-ar", value}, nil
	case "deny_add":
		if !strings.HasPrefix(comment, "defensia:") {
			return nil, fmt.Errorf("%w: comment %q does not start with defensia:", errForbiddenCommand, comment)
		}

		return []string{"-d", value, comment}, nil
	case "deny_remove":
		return []string{"-dr", value}, nil
	default:
		return nil, fmt.Errorf("%w: unknown op %q", errForbiddenCommand, op)
	}
}

func logRefusal(r *SotRefusal) *SotRefusal {
	log.Printf("[csf-sot] refused %s: %s", r.Reason, r.Detail)

	return r
}
