package firewall

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func containsInt(list []int, want int) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// TestActiveSSHPortsSshdT proves the primary source: `sshd -T`'s effective
// config dump, including a port the default install doesn't use (2222) and
// the plain default (22) on the same line set.
func TestActiveSSHPortsSshdT(t *testing.T) {
	tmp := t.TempDir()
	withHostRoot(t, tmp)
	withLookPath(t, func(string) (string, error) { return "", exec.ErrNotFound })
	sshdPath := filepath.Join(tmp, "usr/sbin/sshd")
	mustWriteFile(t, sshdPath, "")

	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		if name == sshdPath && len(args) > 0 && args[0] == "-T" {
			return []byte("port 2222\nport 22\nlistenaddress 0.0.0.0:2222\n"), nil
		}
		return nil, errors.New("not stubbed")
	})

	ports, sources := activeSSHPorts(context.Background())

	want := []int{22, 2222}
	if !reflect.DeepEqual(ports, want) {
		t.Fatalf("ports = %v, want %v", ports, want)
	}
	if !containsString(sources, "sshd-T") {
		t.Fatalf("sources = %v, want to include sshd-T", sources)
	}
}

// TestActiveSSHPortsSS proves the `ss -H -ltnp` fallback when sshd -T is
// unavailable, and that a non-sshd listener (nginx on :80) is excluded.
func TestActiveSSHPortsSS(t *testing.T) {
	tmp := t.TempDir()
	withHostRoot(t, tmp)
	withLookPath(t, func(string) (string, error) { return "", exec.ErrNotFound })
	ssPath := filepath.Join(tmp, "usr/sbin/ss")
	mustWriteFile(t, ssPath, "")

	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		if name == ssPath && len(args) >= 2 && args[1] == "-ltnp" {
			return []byte(
				"LISTEN 0 128 0.0.0.0:2200 0.0.0.0:* users:((\"sshd\",pid=812,fd=3))\n" +
					"LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:((\"nginx\",pid=900,fd=6))\n",
			), nil
		}
		return nil, errors.New("not stubbed")
	})

	ports, sources := activeSSHPorts(context.Background())

	if !reflect.DeepEqual(ports, []int{2200}) {
		t.Fatalf("ports = %v, want [2200]", ports)
	}
	if !reflect.DeepEqual(sources, []string{"ss"}) {
		t.Fatalf("sources = %v, want [ss]", sources)
	}
}

// TestActiveSSHPortsEstablished proves the ESTABLISHED-connection source,
// which catches a port sshd is actively serving even if the listen-socket
// view disagrees.
func TestActiveSSHPortsEstablished(t *testing.T) {
	tmp := t.TempDir()
	withHostRoot(t, tmp)
	withLookPath(t, func(string) (string, error) { return "", exec.ErrNotFound })
	ssPath := filepath.Join(tmp, "usr/sbin/ss")
	mustWriteFile(t, ssPath, "")

	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		if name == ssPath && len(args) >= 2 && args[1] == "-tnp" {
			return []byte("ESTAB 0 0 10.0.0.5:2201 203.0.113.9:51000 users:((\"sshd\",pid=900,fd=10))\n"), nil
		}
		return nil, errors.New("not stubbed")
	})

	ports, sources := activeSSHPorts(context.Background())

	if !containsInt(ports, 2201) {
		t.Fatalf("ports = %v, want to include 2201", ports)
	}
	if !containsString(sources, "ss-established") {
		t.Fatalf("sources = %v, want to include ss-established", sources)
	}
}

// TestActiveSSHPortsConfigFallback proves the last-resort direct read of
// sshd_config(.d) when both commands fail/are unavailable.
func TestActiveSSHPortsConfigFallback(t *testing.T) {
	tmp := t.TempDir()
	withHostRoot(t, tmp)
	withLookPath(t, func(string) (string, error) { return "", exec.ErrNotFound })
	mustWriteFile(t, filepath.Join(tmp, "etc/ssh/sshd_config"), "Port 2022\n")
	mustWriteFile(t, filepath.Join(tmp, "etc/ssh/sshd_config.d/10.conf"), "Port 2023\n")

	ports, sources := activeSSHPorts(context.Background())

	want := []int{2022, 2023}
	if !reflect.DeepEqual(ports, want) {
		t.Fatalf("ports = %v, want %v", ports, want)
	}
	if !reflect.DeepEqual(sources, []string{"config"}) {
		t.Fatalf("sources = %v, want [config]", sources)
	}
}

// TestActiveSSHPortsDefault22 proves the guard errs toward refusing: if
// every source finds nothing, port 22 is still treated as potentially
// in use.
func TestActiveSSHPortsDefault22(t *testing.T) {
	tmp := t.TempDir()
	withHostRoot(t, tmp)
	withLookPath(t, func(string) (string, error) { return "", exec.ErrNotFound })

	ports, sources := activeSSHPorts(context.Background())

	if !reflect.DeepEqual(ports, []int{22}) {
		t.Fatalf("ports = %v, want [22]", ports)
	}
	if !reflect.DeepEqual(sources, []string{"default"}) {
		t.Fatalf("sources = %v, want [default]", sources)
	}
}

// TestActiveSSHPortsUnion proves every source is consulted and the result
// is their sorted, deduplicated union — not just the first source to
// answer.
func TestActiveSSHPortsUnion(t *testing.T) {
	tmp := t.TempDir()
	withHostRoot(t, tmp)
	withLookPath(t, func(string) (string, error) { return "", exec.ErrNotFound })
	sshdPath := filepath.Join(tmp, "usr/sbin/sshd")
	ssPath := filepath.Join(tmp, "usr/sbin/ss")
	mustWriteFile(t, sshdPath, "")
	mustWriteFile(t, ssPath, "")
	mustWriteFile(t, filepath.Join(tmp, "etc/ssh/sshd_config"), "Port 40\n")

	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		switch {
		case name == sshdPath && len(args) > 0 && args[0] == "-T":
			return []byte("port 10\n"), nil
		case name == ssPath && len(args) >= 2 && args[1] == "-ltnp":
			return []byte("LISTEN 0 128 0.0.0.0:20 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n"), nil
		case name == ssPath && len(args) >= 2 && args[1] == "-tnp":
			return []byte("ESTAB 0 0 10.0.0.5:30 203.0.113.9:1 users:((\"sshd\",pid=1,fd=3))\n"), nil
		}
		return nil, errors.New("not stubbed")
	})

	ports, sources := activeSSHPorts(context.Background())

	wantPorts := []int{10, 20, 30, 40}
	if !reflect.DeepEqual(ports, wantPorts) {
		t.Fatalf("ports = %v, want %v", ports, wantPorts)
	}
	wantSources := []string{"config", "ss", "ss-established", "sshd-T"}
	if !reflect.DeepEqual(sources, wantSources) {
		t.Fatalf("sources = %v, want %v", sources, wantSources)
	}
}

// TestActiveSSHPortsBinaryLookup proves the hostPath fallback is used (and
// actually executed) when sshd is not on PATH.
func TestActiveSSHPortsBinaryLookup(t *testing.T) {
	tmp := t.TempDir()
	withHostRoot(t, tmp)
	withLookPath(t, func(string) (string, error) { return "", exec.ErrNotFound })
	sshdPath := filepath.Join(tmp, "usr/sbin/sshd")
	mustWriteFile(t, sshdPath, "")

	var executedName string
	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "-T" {
			executedName = name
		}
		return nil, errors.New("not stubbed")
	})

	activeSSHPorts(context.Background())

	if executedName != sshdPath {
		t.Fatalf("executed sshd binary = %q, want %q", executedName, sshdPath)
	}
}
