package firewall

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func withSessionIPsFn(t *testing.T, fn func(ctx context.Context, sshPorts []int) ([]netip.Addr, error)) {
	t.Helper()
	prev := sessionIPsFn
	sessionIPsFn = fn
	t.Cleanup(func() { sessionIPsFn = prev })
}

func withLookPathMissing(t *testing.T, missing string) {
	t.Helper()
	prev := lookPath
	lookPath = func(name string) (string, error) {
		if name == missing {
			return "", errors.New("not found")
		}
		return prev(name)
	}
	t.Cleanup(func() { lookPath = prev })
}

// withLookPathFound makes lookPath(name) succeed (returning a fake path)
// regardless of what is actually installed on the machine running the
// test — used so tests can exercise the "ss is available" branch on a
// CI/dev box (e.g. this Mac) that has no real ss/sshd binary.
func withLookPathFound(t *testing.T, name, fakePath string) {
	t.Helper()
	prev := lookPath
	lookPath = func(n string) (string, error) {
		if n == name {
			return fakePath, nil
		}
		return prev(n)
	}
	t.Cleanup(func() { lookPath = prev })
}

func TestSSHSessionIPsFromSS(t *testing.T) {
	withLookPathFound(t, "ss", "/usr/sbin/ss")
	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		out := "ESTAB 0 0 10.0.0.5:22 203.0.113.7:51234\n" +
			"ESTAB 0 0 10.0.0.5:22 [::ffff:198.51.100.4]:40000\n" +
			"ESTAB 0 0 10.0.0.5:22 [2001:db8::5]:5555\n"

		return []byte(out), nil
	})

	got, err := sshSessionIPs(context.Background(), []int{22})
	if err != nil {
		t.Fatalf("sshSessionIPs: %v", err)
	}

	want := map[string]bool{"203.0.113.7": true, "198.51.100.4": true, "2001:db8::5": true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %d addrs matching %v", got, len(want), want)
	}
	for _, a := range got {
		if !want[a.String()] {
			t.Errorf("unexpected address %v", a)
		}
	}
}

// TestSSHSessionIPsFromSSNoStateColumn locks in the fix for a real bug
// found live against every CSF VM in the lab (phase 16.1, 2026-11-19):
// `ss -Hnt state established ...` (an explicit state filter) omits the
// State column from its data rows entirely -- unlike the no-filter/-p
// forms TestSSHSessionIPsFromSS's fixture already covered, which do
// include it. The original parser assumed a fixed 5-column layout and a
// hardcoded field index, silently dropping every real row (empty result,
// no error) -- which made guardAllowRemoval/guardDenyAdd see zero live
// sessions and therefore refuse NOTHING, the opposite of fail-closed.
func TestSSHSessionIPsFromSSNoStateColumn(t *testing.T) {
	withLookPathFound(t, "ss", "/usr/sbin/ss")
	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		// No leading state column -- the real format observed on every
		// lab VM (AlmaLinux 8/9/10, Debian 12; iproute2 5.x-6.x) when an
		// explicit `state established` filter is given.
		out := "0      0      192.168.139.130:22 198.51.100.77:53911\n"

		return []byte(out), nil
	})

	got, err := sshSessionIPs(context.Background(), []int{22})
	if err != nil {
		t.Fatalf("sshSessionIPs: %v", err)
	}
	if len(got) != 1 || got[0].String() != "198.51.100.77" {
		t.Fatalf("got %v, want exactly [198.51.100.77]", got)
	}
}

func TestSSHSessionIPsProcFallback(t *testing.T) {
	withLookPathMissing(t, "ss")

	hostTmp := t.TempDir()
	mustMkdirAll(t, filepath.Join(hostTmp, "proc", "net"))
	// Local 127.0.0.1:22 ("0100007F:0016"); peer 203.0.113.7:50000
	// ("077100CB:C350", /proc/net/tcp stores each address as its 4 bytes
	// in reverse order, hex-encoded); state 01 = ESTABLISHED. The second
	// row (state 0A = LISTEN, no peer) must be excluded.
	tcpContent := "sl  local_address rem_address   st\n" +
		" 0: 0100007F:0016 077100CB:C350 01\n" +
		" 1: 0100007F:0016 00000000:0000 0A\n"
	mustWriteFile(t, filepath.Join(hostTmp, "proc", "net", "tcp"), tcpContent)
	mustWriteFile(t, filepath.Join(hostTmp, "proc", "net", "tcp6"), "sl  local_address rem_address   st\n")

	withHostRoot(t, hostTmp)

	got, err := sshSessionIPs(context.Background(), []int{22})
	if err != nil {
		t.Fatalf("sshSessionIPs: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %v, want exactly 1 established peer (LISTEN row must be excluded)", got)
	}
}

func TestSSHSessionIPsError(t *testing.T) {
	withLookPathMissing(t, "ss")
	withHostRoot(t, t.TempDir()) // no /proc/net/tcp{,6} at all -> read error

	_, err := sshSessionIPs(context.Background(), []int{22})
	if err == nil {
		t.Fatal("sshSessionIPs = nil error, want an error when both ss and /proc are unavailable (fail closed)")
	}
}

func mustMkdirAll(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
}

func TestGuardPortsSSH(t *testing.T) {
	cases := []struct {
		name     string
		sshPorts []int
		want     map[string]string
		wantRef  string
	}{
		{"closed", []int{22}, map[string]string{"TCP_IN": "80,443"}, "ssh_port_in_use"},
		{"range_covers", []int{2222}, map[string]string{"TCP_IN": "20:3000"}, ""},
		{"tcp_in_ok_but_tcp6_in_missing", []int{22}, map[string]string{"TCP_IN": "22,80", "TCP6_IN": "80"}, "ssh_port_in_use"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withSSHPortsFn(t, func(ctx context.Context) ([]int, []string) { return c.sshPorts, []string{"config"} })

			ref := guardPorts(context.Background(), c.want)
			if c.wantRef == "" {
				if ref != nil {
					t.Errorf("guardPorts = %+v, want nil", ref)
				}

				return
			}
			if ref == nil || ref.Reason != c.wantRef {
				t.Errorf("guardPorts = %+v, want reason %s", ref, c.wantRef)
			}
		})
	}

	t.Run("empty_sshports_treated_as_22", func(t *testing.T) {
		withSSHPortsFn(t, func(ctx context.Context) ([]int, []string) { return nil, nil })
		ref := guardPorts(context.Background(), map[string]string{"TCP_IN": "80,443"})
		if ref == nil || ref.Reason != "ssh_port_in_use" {
			t.Errorf("guardPorts = %+v, want ssh_port_in_use (empty ssh ports treated as [22])", ref)
		}
	})
}

func TestGuardScope(t *testing.T) {
	ref := guardScope(map[string]string{"TCP_IN": "80", "WEIRD_KEY": "1"})
	if ref == nil || ref.Reason != "out_of_scope_key" || ref.Detail != "WEIRD_KEY" {
		t.Errorf("guardScope = %+v, want out_of_scope_key/WEIRD_KEY", ref)
	}

	if ref := guardScope(map[string]string{"TCP_IN": "80"}); ref != nil {
		t.Errorf("guardScope = %+v, want nil for an in-scope key", ref)
	}
}

func TestGuardAllowRemoval(t *testing.T) {
	withSessionIPsFn(t, func(ctx context.Context, sshPorts []int) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.7")}, nil
	})

	if ref := guardAllowRemoval(context.Background(), "203.0.113.0/24", []int{22}); ref == nil || ref.Reason != "ssh_session_ip" {
		t.Errorf("guardAllowRemoval(203.0.113.0/24) = %+v, want ssh_session_ip", ref)
	}
	if ref := guardAllowRemoval(context.Background(), "192.0.2.1", []int{22}); ref != nil {
		t.Errorf("guardAllowRemoval(192.0.2.1) = %+v, want nil", ref)
	}

	withSessionIPsFn(t, func(ctx context.Context, sshPorts []int) ([]netip.Addr, error) {
		return nil, errors.New("boom")
	})
	ref := guardAllowRemoval(context.Background(), "192.0.2.1", []int{22})
	if ref == nil || ref.Reason != "ssh_session_ip" || ref.Detail != "unknown" {
		t.Errorf("guardAllowRemoval on session-lookup error = %+v, want ssh_session_ip/unknown (fail closed)", ref)
	}
}

func TestGuardDenyAdd(t *testing.T) {
	withSessionIPsFn(t, func(ctx context.Context, sshPorts []int) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.7")}, nil
	})

	panelIP := netip.MustParseAddr("198.51.100.9")

	if ref := guardDenyAdd(context.Background(), "203.0.113.7", []int{22}, panelIP); ref == nil || ref.Reason != "ssh_session_ip" {
		t.Errorf("guardDenyAdd(session ip) = %+v, want ssh_session_ip", ref)
	}
	if ref := guardDenyAdd(context.Background(), "198.51.100.0/24", []int{22}, panelIP); ref == nil || ref.Reason != "would_block_panel" {
		t.Errorf("guardDenyAdd(covers panel) = %+v, want would_block_panel", ref)
	}
	if ref := guardDenyAdd(context.Background(), "192.0.2.1", []int{22}, panelIP); ref != nil {
		t.Errorf("guardDenyAdd(unrelated) = %+v, want nil", ref)
	}
}

func TestArgvAllowlist(t *testing.T) {
	cases := []struct {
		op, value, comment string
		want               []string
		wantErr            bool
	}{
		{"allow_add", "203.0.113.5", "defensia:sot", []string{"-a", "203.0.113.5", "defensia:sot"}, false},
		{"allow_remove", "203.0.113.5", "", []string{"-ar", "203.0.113.5"}, false},
		{"deny_add", "203.0.113.5", "defensia:sot", []string{"-d", "203.0.113.5", "defensia:sot"}, false},
		{"deny_remove", "203.0.113.5", "", []string{"-dr", "203.0.113.5"}, false},
		{"restart", "203.0.113.5", "defensia:sot", nil, true},
		{"allow_add", "203.0.113.5", "not-tagged", nil, true},
		{"allow_add", "not-an-ip", "defensia:sot", nil, true},
	}

	for _, c := range cases {
		got, err := csfSotArgv(c.op, c.value, c.comment)
		if c.wantErr {
			if err == nil {
				t.Errorf("csfSotArgv(%q,%q,%q) = %v, want error", c.op, c.value, c.comment, got)
			}

			continue
		}
		if err != nil {
			t.Errorf("csfSotArgv(%q,%q,%q) error: %v", c.op, c.value, c.comment, err)

			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("csfSotArgv(%q,%q,%q) = %v, want %v", c.op, c.value, c.comment, got, c.want)

			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("csfSotArgv(%q,%q,%q) = %v, want %v", c.op, c.value, c.comment, got, c.want)
			}
		}
	}
}

func TestNoForbiddenFlagsInSource(t *testing.T) {
	forbidden := []string{`"-f"`, `"--flush"`, `"-x"`, `"--disable"`, `"-e"`, `"-ra"`, `"-td"`, `"-tr"`}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "csfsot_") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, f := range forbidden {
			if strings.Contains(string(data), f) {
				t.Errorf("%s contains forbidden flag literal %s", name, f)
			}
		}
	}
}
