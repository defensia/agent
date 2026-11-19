// Package chart_test guards the Helm chart against the class of mistake that
// made it uninstallable on k3s.
//
// A hostPath volume with `type: Socket` requires the path to exist. kubelet
// cannot create the pod without it, so the pod sits in ContainerCreating
// forever — and an agent that never starts never sends a heartbeat, which means
// the failure leaves no trace in our own telemetry. We would only learn about it
// if the customer wrote in.
//
// The containerd socket was mounted that way unconditionally, with containerd's
// upstream default path hard-coded, while k3s keeps its socket at
// /run/k3s/containerd/containerd.sock and RKE2, MicroK8s and CRI-O differ again.
// The Docker socket immediately above it in the same file already carried a
// comment explaining this exact damage: the lesson had been applied to one of
// the two sockets.
//
// These tests exist because the fix went in without one. A fix with no test that
// reproduces the failure is a conjecture, and this class of bug is invisible in
// production by construction, so the test is the only thing that will catch the
// third socket somebody adds.
package chart_test

import (
	"os"
	"strings"
	"testing"
)

const daemonSet = "../../charts/defensia-agent/templates/daemonset.yaml"

// Every `type: Socket` must sit inside a conditional block. Unguarded, it turns
// a node that keeps its socket elsewhere into a permanently pending pod.
func TestEverySocketMountIsConditional(t *testing.T) {
	for _, line := range unguardedSockets(t, daemonSet) {
		t.Errorf("line %d: `type: Socket` is not inside a conditional block — a node without that exact path will never start the pod", line)
	}
}

// Being inside *some* conditional is not enough: it has to be a flag the
// operator can turn off. A socket guarded by, say, a cluster-name check would
// satisfy the test above and still be unconditional in practice.
func TestEverySocketMountIsGuardedByAnEnabledFlag(t *testing.T) {
	lines := readLines(t, daemonSet)
	depth := 0
	var guards []string

	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "#") {
			continue
		}

		switch {
		case isBlockOpen(line):
			depth++
			guards = append(guards, line)
		case isBlockClose(line):
			if depth > 0 {
				depth--
				guards = guards[:len(guards)-1]
			}
		}

		if !strings.Contains(line, "type: Socket") {
			continue
		}

		if depth == 0 {
			continue // reported by the test above
		}

		enclosing := guards[len(guards)-1]
		if !strings.Contains(enclosing, ".enabled") {
			t.Errorf("line %d: `type: Socket` is guarded by %q, which is not an on/off flag — an operator cannot turn this mount off", i+1, enclosing)
		}
	}
}

// The agent has no CRI client: the only mention of containerd in any Go file
// compares a process name in the malware scanner. So the containerd socket must
// stay off by default — it cost installations and bought nothing. When a reader
// for it lands, this test is the place to record that the default changed on
// purpose.
func TestTheContainerdSocketIsOffByDefault(t *testing.T) {
	block := topLevelBlock(t, "../../charts/defensia-agent/values.yaml", "containerdSocket:")

	if !strings.Contains(block, "enabled: false") {
		t.Errorf("containerdSocket must default to enabled: false while nothing reads the socket; got:\n%s", block)
	}
}

// topLevelBlock returns the lines of one top-level YAML key, ending at the next
// top-level key rather than at the end of the file.
//
// The first version of this ran to the end of the file, so it found an
// `enabled: false` belonging to a later key and passed while the chart was still
// broken — a test that was green for the wrong reason, which is worse than no
// test at all. Caught by reverting the fix and watching which tests failed.
func topLevelBlock(t *testing.T, path, key string) string {
	t.Helper()

	lines := readLines(t, path)
	start := -1

	for i, line := range lines {
		if strings.HasPrefix(line, key) {
			start = i

			break
		}
	}

	if start < 0 {
		t.Fatalf("%s has no top-level %q", path, key)
	}

	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		line := lines[i]
		if line == "" || strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "#") {
			continue
		}
		end = i

		break
	}

	return strings.Join(lines[start:end], "\n")
}

// unguardedSockets returns the 1-based line numbers of `type: Socket`
// declarations that are not inside any conditional block.
func unguardedSockets(t *testing.T, path string) []int {
	t.Helper()

	var out []int
	depth := 0

	for i, raw := range readLines(t, path) {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "#") {
			continue
		}

		switch {
		case isBlockOpen(line):
			depth++
		case isBlockClose(line):
			if depth > 0 {
				depth--
			}
		}

		if strings.Contains(line, "type: Socket") && depth == 0 {
			out = append(out, i+1)
		}
	}

	return out
}

// isBlockOpen reports whether a template line opens a block. `else` is neither
// an open nor a close: it stays at the same depth.
func isBlockOpen(line string) bool {
	if !strings.Contains(line, "{{") {
		return false
	}
	if strings.Contains(line, "else") {
		return false
	}

	return strings.Contains(line, "if ") || strings.Contains(line, "range ") || strings.Contains(line, "with ")
}

func isBlockClose(line string) bool {
	return strings.Contains(line, "{{") && strings.Contains(line, "end")
}

func readLines(t *testing.T, path string) []string {
	t.Helper()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	return strings.Split(string(b), "\n")
}
