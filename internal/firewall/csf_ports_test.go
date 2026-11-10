package firewall

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// baseSafePortConf is the fixture csf.conf most SafePort tests start from:
// real-shaped TCP_IN/TCP_OUT/TCP6_IN/TCP6_OUT values (including a range),
// IPV6 off by default, TESTING off, LF_DAEMON on, a full-line comment and a
// trailing-comment line — matching the plan's fixture spec.
const baseSafePortConf = "" +
	"TCP_IN = \"20,21,22,25,80,443,30000:35000\"\n" +
	"TCP_OUT = \"20,21,22,25,53,80,443\"\n" +
	"TCP6_IN = \"20,21,22,25,80,443\"\n" +
	"TCP6_OUT = \"20,21,22,25,53,80,443\"\n" +
	"IPV6 = \"0\"\n" +
	"TESTING = \"0\"\n" +
	"LF_DAEMON = \"1\"\n" +
	"# a comment line\n" +
	"TESTING_INTERVAL = \"5\" # a trailing-comment line\n"

// forbiddenCSFArgs must never appear in any command this package executes
// via run() — flushing, disabling or toggling CSF is never an acceptable
// recovery action, including on the rollback-failed critical path.
var forbiddenCSFArgs = []string{"-f", "--flush", "-x", "--disable", "-e", "--enable", "-ra"}

// requireNeverFlush registers an observer for the rest of the test and
// fails it (in Cleanup, so it still runs even if the test body already
// returned) if ANY command recorded by run() ever contained a forbidden
// arg. Every SafePort test below goes through newSafePortFixture, which
// calls this — the guarantee is checked continuously, not just by the one
// test named for it.
func requireNeverFlush(t *testing.T) {
	t.Helper()
	var bad []string
	restore := ObserveCommands(func(name string, args []string) {
		for _, a := range args {
			for _, forbidden := range forbiddenCSFArgs {
				if a == forbidden {
					bad = append(bad, name+" "+strings.Join(args, " "))
				}
			}
		}
	})
	t.Cleanup(func() {
		restore()
		if len(bad) > 0 {
			t.Errorf("forbidden CSF arg observed in: %v", bad)
		}
	})
}

func withCSFBackupDir(t *testing.T, dir string) {
	t.Helper()
	prev := csfBackupDir
	csfBackupDir = dir
	t.Cleanup(func() { csfBackupDir = prev })
}

func withRestartRetryDelay(t *testing.T, d time.Duration) {
	t.Helper()
	prev := restartRetryDelay
	restartRetryDelay = d
	t.Cleanup(func() { restartRetryDelay = prev })
}

func withLFDPollTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	prev := lfdPollTimeout
	lfdPollTimeout = d
	t.Cleanup(func() { lfdPollTimeout = prev })
}

func withSSHPortsFn(t *testing.T, fn func(ctx context.Context) ([]int, []string)) {
	t.Helper()
	prev := sshPortsFn
	sshPortsFn = fn
	t.Cleanup(func() { sshPortsFn = prev })
}

func withAfterCSFRestartHook(t *testing.T, fn func()) {
	t.Helper()
	prev := afterCSFRestart
	SetAfterCSFRestartHook(fn)
	t.Cleanup(func() { afterCSFRestart = prev })
}

// mustWriteFileMode is mustWriteFile (csf_state_test.go) with an explicit
// mode, needed to prove SafePortChange preserves the original csf.conf
// permission bits.
func mustWriteFileMode(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("Chmod(%s): %v", path, err)
	}
}

// defaultSafePortRunCmd is the default runCmd stub newSafePortFixture
// installs: `csf -r` and `iptables -S LOCALINPUT` both succeed. Individual
// tests override it (via withRunCmd again) when they need a specific
// failure/retry/overlap scenario.
func defaultSafePortRunCmd(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
	if len(args) > 0 && args[0] == "-r" {
		return []byte("ok\n"), nil
	}
	if name == "iptables" {
		return []byte("-N LOCALINPUT\n"), nil
	}
	return nil, errors.New("not stubbed: " + name)
}

// newSafePortFixtureWithConf sets up every seam SafePortChange touches
// (csfDir with the given conf, a fake csf binary resolved via lookPath, a
// scratch backup dir, shortened timers, a no-op SSH-ports stub, a no-op
// afterCSFRestart hook, the never-flush observer and a default successful
// runCmd stub) and returns csfDir.
func newSafePortFixtureWithConf(t *testing.T, conf string) string {
	t.Helper()
	dir := t.TempDir()
	withCSFDir(t, dir)
	withCSFBackupDir(t, t.TempDir())
	withLookPath(t, func(name string) (string, error) {
		if name == "csf" {
			return "/usr/sbin/csf", nil
		}
		return "", exec.ErrNotFound
	})
	withRestartRetryDelay(t, 5*time.Millisecond)
	withLFDPollTimeout(t, 50*time.Millisecond)
	withSSHPortsFn(t, func(ctx context.Context) ([]int, []string) { return nil, nil })
	withAfterCSFRestartHook(t, func() {})
	withRunCmd(t, defaultSafePortRunCmd)
	requireNeverFlush(t)

	mustWriteFileMode(t, filepath.Join(dir, "csf.conf"), conf, 0o640)
	return dir
}

func newSafePortFixture(t *testing.T) string {
	return newSafePortFixtureWithConf(t, baseSafePortConf)
}

// --- validPortList ---------------------------------------------------------

func TestValidPortList(t *testing.T) {
	cases := []struct {
		v    string
		want bool
	}{
		{"", true},
		{"22,80", true},
		{"1:65535", true},
		{"22,22", false},
		{"0", false},
		{"65536", false},
		{"abc", false},
		{"22,,80", false},
		{"80:22", false},
	}
	for _, c := range cases {
		if got := validPortList(c.v); got != c.want {
			t.Errorf("validPortList(%q) = %v, want %v", c.v, got, c.want)
		}
	}
}

// --- rewriteConfKeys --------------------------------------------------------

func TestRewriteConfKeysOnlyTargetLine(t *testing.T) {
	content := []byte(
		"# header comment\n" +
			"TCP_IN = \"20,21,22\"\n" +
			"TCP_OUT = \"20,21,22\" # keep me\n" +
			"LF_DAEMON = \"1\"\n" +
			"# TCP_IN = \"99\"\n",
	)

	t.Run("only target lines change, trailing comment preserved", func(t *testing.T) {
		got, err := rewriteConfKeys(content, map[string]string{
			"TCP_IN":  "20,21,22,8080",
			"TCP_OUT": "20,21,22,8081",
		})
		if err != nil {
			t.Fatalf("rewriteConfKeys: %v", err)
		}
		lines := strings.Split(string(got), "\n")
		want := []string{
			"# header comment",
			`TCP_IN = "20,21,22,8080"`,
			`TCP_OUT = "20,21,22,8081" # keep me`,
			`LF_DAEMON = "1"`,
			`# TCP_IN = "99"`,
			"",
		}
		if !reflect.DeepEqual(lines, want) {
			t.Fatalf("lines = %#v, want %#v", lines, want)
		}
	})

	t.Run("key missing", func(t *testing.T) {
		_, err := rewriteConfKeys(content, map[string]string{"TCP6_IN": "22"})
		if !errors.Is(err, errKeyMissing) {
			t.Fatalf("err = %v, want errKeyMissing", err)
		}
	})

	t.Run("duplicate key", func(t *testing.T) {
		dup := []byte("TCP_IN = \"20\"\nTCP_IN = \"21\"\n")
		_, err := rewriteConfKeys(dup, map[string]string{"TCP_IN": "22"})
		if !errors.Is(err, errDuplicateKey) {
			t.Fatalf("err = %v, want errDuplicateKey", err)
		}
	})
}

// --- SafePortChange: applied / unchanged happy paths -----------------------

func TestSafePortAddApplied(t *testing.T) {
	dir := newSafePortFixture(t)
	drainRefreshCh()

	var restartCalls, chainCalls int32
	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "-r" {
			atomic.AddInt32(&restartCalls, 1)
			return []byte("ok\n"), nil
		}
		if name == "iptables" {
			atomic.AddInt32(&chainCalls, 1)
			return []byte("-N LOCALINPUT\n"), nil
		}
		return nil, errors.New("not stubbed")
	})

	res := SafePortChange(context.Background(), PortChangeRequest{Port: 8080, Direction: "in", Action: "add"}, PortChangeOptions{})
	if res.Result != "applied" {
		t.Fatalf("result = %+v, want applied", res)
	}
	if atomic.LoadInt32(&restartCalls) != 1 {
		t.Fatalf("csf -r called %d times, want 1", restartCalls)
	}
	if atomic.LoadInt32(&chainCalls) == 0 {
		t.Fatalf("iptables -S LOCALINPUT never called")
	}

	got, err := os.ReadFile(filepath.Join(dir, "csf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `TCP_IN = "20,21,22,25,80,443,30000:35000,8080"`) {
		t.Fatalf("csf.conf TCP_IN not updated: %s", got)
	}

	if res.Backup == "" {
		t.Fatalf("Backup path empty")
	}
	info, err := os.Stat(res.Backup)
	if err != nil {
		t.Fatalf("backup file missing: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode = %v, want 0600", info.Mode().Perm())
	}
	backupBytes, err := os.ReadFile(res.Backup)
	if err != nil {
		t.Fatal(err)
	}
	if string(backupBytes) != baseSafePortConf {
		t.Fatalf("backup content mismatch:\n%s", backupBytes)
	}

	select {
	case <-csfRefreshCh:
	default:
		t.Fatalf("RequestCSFRefresh was not triggered")
	}
}

func TestSafePortAddUnchangedNoRestart(t *testing.T) {
	dir := newSafePortFixture(t)
	var restartCalls int32
	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "-r" {
			atomic.AddInt32(&restartCalls, 1)
		}
		return []byte("ok\n"), nil
	})

	for _, port := range []int{80, 31000} {
		res := SafePortChange(context.Background(), PortChangeRequest{Port: port, Direction: "in", Action: "add"}, PortChangeOptions{})
		if res.Result != "unchanged" {
			t.Fatalf("port %d: result = %+v, want unchanged", port, res)
		}
	}
	if atomic.LoadInt32(&restartCalls) != 0 {
		t.Fatalf("csf -r called %d times, want 0", restartCalls)
	}
	got, err := os.ReadFile(filepath.Join(dir, "csf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != baseSafePortConf {
		t.Fatalf("csf.conf modified despite unchanged result")
	}
}

// --- Guards: SSH port, panel port, range -----------------------------------

func TestSafePortRemoveSSHRejected(t *testing.T) {
	cases := []struct {
		name string
		conf string
		port int
	}{
		{"default ssh port 22", baseSafePortConf, 22},
		{
			"custom ssh port 2222",
			strings.Replace(baseSafePortConf,
				`TCP_IN = "20,21,22,25,80,443,30000:35000"`,
				`TCP_IN = "20,21,22,25,80,443,2222,30000:35000"`, 1),
			2222,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := newSafePortFixtureWithConf(t, c.conf)
			withSSHPortsFn(t, func(ctx context.Context) ([]int, []string) {
				return []int{c.port}, []string{"sshd-T"}
			})
			var restartCalls int32
			withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
				if len(args) > 0 && args[0] == "-r" {
					atomic.AddInt32(&restartCalls, 1)
				}
				return []byte("ok\n"), nil
			})

			before, err := os.ReadFile(filepath.Join(dir, "csf.conf"))
			if err != nil {
				t.Fatal(err)
			}
			beforeHash := sha256.Sum256(before)

			res := SafePortChange(context.Background(), PortChangeRequest{Port: c.port, Direction: "in", Action: "remove"}, PortChangeOptions{})
			if res.Result != "rejected" || res.Reason != "ssh_port_in_use" {
				t.Fatalf("result = %+v, want rejected/ssh_port_in_use", res)
			}
			if atomic.LoadInt32(&restartCalls) != 0 {
				t.Fatalf("csf -r called, want 0")
			}
			after, err := os.ReadFile(filepath.Join(dir, "csf.conf"))
			if err != nil {
				t.Fatal(err)
			}
			if sha256.Sum256(after) != beforeHash {
				t.Fatalf("csf.conf modified")
			}
			entries, err := os.ReadDir(csfBackupDir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("backup written (%d files), want none", len(entries))
			}
		})
	}
}

func TestSafePortRemoveInRangeRejected(t *testing.T) {
	newSafePortFixture(t)
	res := SafePortChange(context.Background(), PortChangeRequest{Port: 31000, Direction: "in", Action: "remove"}, PortChangeOptions{})
	if res.Result != "rejected" || res.Reason != "port_in_range" {
		t.Fatalf("result = %+v, want rejected/port_in_range", res)
	}
}

func TestSafePortRemovePanelPortRejected(t *testing.T) {
	newSafePortFixture(t)
	opts := PortChangeOptions{PanelPort: 443}

	res := SafePortChange(context.Background(), PortChangeRequest{Port: 443, Direction: "out", Action: "remove"}, opts)
	if res.Result != "rejected" || res.Reason != "panel_port_in_use" {
		t.Fatalf("remove 443 out: result = %+v, want rejected/panel_port_in_use", res)
	}

	res2 := SafePortChange(context.Background(), PortChangeRequest{Port: 443, Direction: "in", Action: "remove"}, opts)
	if res2.Result != "applied" {
		t.Fatalf("remove 443 in: result = %+v, want applied", res2)
	}
}

// --- IPv6 mirroring ----------------------------------------------------------

func TestSafePortIPv6Mirror(t *testing.T) {
	conf := strings.Replace(baseSafePortConf, `IPV6 = "0"`, `IPV6 = "1"`, 1)
	dir := newSafePortFixtureWithConf(t, conf)

	res := SafePortChange(context.Background(), PortChangeRequest{Port: 8443, Direction: "in", Action: "add"}, PortChangeOptions{})
	if res.Result != "applied" || !res.IPv6Mirrored {
		t.Fatalf("result = %+v, want applied/IPv6Mirrored=true", res)
	}
	got, err := os.ReadFile(filepath.Join(dir, "csf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `TCP_IN = "20,21,22,25,80,443,30000:35000,8443"`) {
		t.Fatalf("TCP_IN not updated: %s", got)
	}
	if !strings.Contains(string(got), `TCP6_IN = "20,21,22,25,80,443,8443"`) {
		t.Fatalf("TCP6_IN not mirrored: %s", got)
	}

	// The SSH guard still fires with IPv6 mirroring in play: it guards the
	// logical port/direction, independent of which key(s) would be touched.
	withSSHPortsFn(t, func(ctx context.Context) ([]int, []string) { return []int{22}, []string{"sshd-T"} })
	res2 := SafePortChange(context.Background(), PortChangeRequest{Port: 22, Direction: "in", Action: "remove"}, PortChangeOptions{})
	if res2.Result != "rejected" || res2.Reason != "ssh_port_in_use" {
		t.Fatalf("remove 22 with ssh guard: result = %+v, want rejected/ssh_port_in_use", res2)
	}

	// IPV6=1 but TCP6_IN key missing -> v4 applied, IPv6Mirrored false, no failure.
	confNoMirror := strings.Replace(conf, `TCP6_IN = "20,21,22,25,80,443"`+"\n", "", 1)
	newSafePortFixtureWithConf(t, confNoMirror)
	res3 := SafePortChange(context.Background(), PortChangeRequest{Port: 9443, Direction: "in", Action: "add"}, PortChangeOptions{})
	if res3.Result != "applied" || res3.IPv6Mirrored {
		t.Fatalf("missing TCP6_IN: result = %+v, want applied/IPv6Mirrored=false", res3)
	}
}

// --- Restart failure / health check / rollback ------------------------------

func TestSafePortRestartFailRollsBack(t *testing.T) {
	dir := newSafePortFixture(t)
	var calls int32
	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "-r" {
			n := atomic.AddInt32(&calls, 1)
			if n == 1 {
				return []byte("*Error* line 12\n"), errors.New("exit status 1")
			}
			return []byte("ok\n"), nil
		}
		if name == "iptables" {
			return []byte("-N LOCALINPUT\n"), nil
		}
		return nil, errors.New("not stubbed")
	})

	res := SafePortChange(context.Background(), PortChangeRequest{Port: 8101, Direction: "in", Action: "add"}, PortChangeOptions{})
	if res.Result != "failed" || res.Reason != "restart_failed" || !res.RolledBack {
		t.Fatalf("result = %+v, want failed/restart_failed/RolledBack=true", res)
	}
	if atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("csf -r called %d times, want 2", calls)
	}
	got, err := os.ReadFile(filepath.Join(dir, "csf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != baseSafePortConf {
		t.Fatalf("csf.conf not restored to original:\n%s", got)
	}
}

func TestSafePortHealthCheckFailRollsBack(t *testing.T) {
	newSafePortFixture(t)
	var iptablesCalls int32
	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "-r" {
			return []byte("ok\n"), nil
		}
		if name == "iptables" {
			n := atomic.AddInt32(&iptablesCalls, 1)
			if n == 1 {
				return nil, errors.New("iptables: chain LOCALINPUT does not exist")
			}
			return []byte("-N LOCALINPUT\n"), nil
		}
		return nil, errors.New("not stubbed")
	})

	res := SafePortChange(context.Background(), PortChangeRequest{Port: 8102, Direction: "in", Action: "add"}, PortChangeOptions{})
	if res.Result != "failed" || res.Reason != "health_check_failed" || !res.RolledBack {
		t.Fatalf("result = %+v, want failed/health_check_failed/RolledBack=true", res)
	}
}

func TestSafePortLFDDiedRollsBack(t *testing.T) {
	newSafePortFixture(t)
	hostTmp := t.TempDir()
	withHostRoot(t, hostTmp)
	withLFDPollTimeout(t, 100*time.Millisecond)

	pidFile := filepath.Join(hostTmp, "var/run/lfd.pid")
	procCmdline := filepath.Join(hostTmp, "proc/4242/cmdline")
	mustWriteFile(t, pidFile, "4242\n")
	mustWriteFile(t, procCmdline, "lfd - sleeping\x00")

	var restartCalls int32
	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "-r" {
			n := atomic.AddInt32(&restartCalls, 1)
			if n == 1 {
				// lfd "dies" as a side effect of the (unhealthy) restart.
				_ = os.Remove(procCmdline)
			} else {
				// the rollback restart brings it back.
				mustWriteFile(t, procCmdline, "lfd - sleeping\x00")
			}
			return []byte("ok\n"), nil
		}
		if name == "iptables" {
			return []byte("-N LOCALINPUT\n"), nil
		}
		return nil, errors.New("not stubbed")
	})

	res := SafePortChange(context.Background(), PortChangeRequest{Port: 8103, Direction: "in", Action: "add"}, PortChangeOptions{})
	if res.Result != "failed" || res.Reason != "lfd_not_running" || !res.RolledBack {
		t.Fatalf("result = %+v, want failed/lfd_not_running/RolledBack=true", res)
	}
}

func TestSafePortTestingModeSkipsLFDAndChain(t *testing.T) {
	conf := strings.Replace(baseSafePortConf, `TESTING = "0"`, `TESTING = "1"`, 1)
	newSafePortFixtureWithConf(t, conf)

	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "-r" {
			return []byte("ok\n"), nil
		}
		if name == "iptables" {
			return nil, errors.New("chain missing")
		}
		if name == "systemctl" {
			return []byte("inactive\n"), nil
		}
		return nil, errors.New("not stubbed")
	})

	res := SafePortChange(context.Background(), PortChangeRequest{Port: 8104, Direction: "in", Action: "add"}, PortChangeOptions{})
	if res.Result != "applied" || !res.TestingMode {
		t.Fatalf("result = %+v, want applied/TestingMode=true", res)
	}
}

func TestSafePortRollbackFailedCritical(t *testing.T) {
	dir := newSafePortFixture(t)
	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "-r" {
			return []byte("*Error* boom\n"), errors.New("exit status 1")
		}
		if name == "iptables" {
			return []byte("-N LOCALINPUT\n"), nil
		}
		return nil, errors.New("not stubbed")
	})

	res := SafePortChange(context.Background(), PortChangeRequest{Port: 8105, Direction: "in", Action: "add"}, PortChangeOptions{})
	if res.Result != "rollback_failed" || res.Reason != "rollback_failed" || res.RolledBack {
		t.Fatalf("result = %+v, want rollback_failed/rollback_failed/RolledBack=false", res)
	}
	got, err := os.ReadFile(filepath.Join(dir, "csf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != baseSafePortConf {
		t.Fatalf("csf.conf not restored to original bytes:\n%s", got)
	}
}

// --- Other guards / rejections ---------------------------------------------

func TestSafePortCSFDisabledRejected(t *testing.T) {
	dir := newSafePortFixture(t)
	mustWriteFile(t, filepath.Join(dir, "csf.disable"), "")
	res := SafePortChange(context.Background(), PortChangeRequest{Port: 8106, Direction: "in", Action: "add"}, PortChangeOptions{})
	if res.Result != "rejected" || res.Reason != "csf_disabled" {
		t.Fatalf("result = %+v, want rejected/csf_disabled", res)
	}
}

func TestSafePortPausedRejected(t *testing.T) {
	newSafePortFixture(t)
	withCollectorMarkers(t)
	if err := SetCSFPaused(true); err != nil {
		t.Fatal(err)
	}
	defer SetCSFPaused(false)

	var calls int32
	restore := ObserveCommands(func(name string, args []string) { atomic.AddInt32(&calls, 1) })
	defer restore()

	res := SafePortChange(context.Background(), PortChangeRequest{Port: 8107, Direction: "in", Action: "add"}, PortChangeOptions{})
	if res.Result != "rejected" || res.Reason != "integration_disabled" {
		t.Fatalf("result = %+v, want rejected/integration_disabled", res)
	}
	if atomic.LoadInt32(&calls) != 0 {
		t.Fatalf("commands observed = %d, want 0", calls)
	}
}

func TestSafePortNotInstalled(t *testing.T) {
	dir := t.TempDir()
	withCSFDir(t, dir)
	withHostRoot(t, t.TempDir())
	withLookPath(t, func(string) (string, error) { return "", exec.ErrNotFound })
	requireNeverFlush(t)

	var calls int32
	restore := ObserveCommands(func(name string, args []string) { atomic.AddInt32(&calls, 1) })
	defer restore()

	res := SafePortChange(context.Background(), PortChangeRequest{Port: 8108, Direction: "in", Action: "add"}, PortChangeOptions{})
	if res.Result != "rejected" || res.Reason != "csf_not_installed" {
		t.Fatalf("result = %+v, want rejected/csf_not_installed", res)
	}
	if atomic.LoadInt32(&calls) != 0 {
		t.Fatalf("commands observed = %d, want 0", calls)
	}
}

func TestSafePortInvalidRequest(t *testing.T) {
	newSafePortFixture(t)
	cases := []PortChangeRequest{
		{Port: 0, Direction: "in", Action: "add"},
		{Port: 70000, Direction: "in", Action: "add"},
		{Port: 8080, Direction: "both", Action: "add"},
		{Port: 8080, Direction: "in", Action: "toggle"},
	}
	for _, req := range cases {
		res := SafePortChange(context.Background(), req, PortChangeOptions{})
		if res.Result != "rejected" || res.Reason != "invalid_request" {
			t.Fatalf("req %+v: result = %+v, want rejected/invalid_request", req, res)
		}
	}
}

func TestSafePortInvalidExistingValue(t *testing.T) {
	conf := strings.Replace(baseSafePortConf,
		`TCP_IN = "20,21,22,25,80,443,30000:35000"`, `TCP_IN = "22,abc"`, 1)
	dir := newSafePortFixtureWithConf(t, conf)
	var restartCalls int32
	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "-r" {
			atomic.AddInt32(&restartCalls, 1)
		}
		return []byte("ok\n"), nil
	})

	res := SafePortChange(context.Background(), PortChangeRequest{Port: 8109, Direction: "in", Action: "add"}, PortChangeOptions{})
	if res.Result != "rejected" || res.Reason != "invalid_existing_value" {
		t.Fatalf("result = %+v, want rejected/invalid_existing_value", res)
	}
	if atomic.LoadInt32(&restartCalls) != 0 {
		t.Fatalf("csf -r called, want 0")
	}
	got, err := os.ReadFile(filepath.Join(dir, "csf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `TCP_IN = "22,abc"`) {
		t.Fatalf("csf.conf modified: %s", got)
	}
}

// --- Backup rotation / atomicity --------------------------------------------

func TestSafePortBackupRotationKeeps5(t *testing.T) {
	newSafePortFixture(t)
	for i := 0; i < 7; i++ {
		res := SafePortChange(context.Background(), PortChangeRequest{Port: 9000 + i, Direction: "in", Action: "add"}, PortChangeOptions{})
		if res.Result != "applied" {
			t.Fatalf("change %d: result = %+v, want applied", i, res)
		}
	}
	entries, err := os.ReadDir(csfBackupDir)
	if err != nil {
		t.Fatal(err)
	}
	var backups []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "csf.conf.") {
			backups = append(backups, e.Name())
		}
	}
	if len(backups) != 5 {
		t.Fatalf("backups = %v (%d files), want 5", backups, len(backups))
	}
}

func TestSafePortPreservesModeAndAtomic(t *testing.T) {
	dir := newSafePortFixture(t)
	if err := os.Chmod(filepath.Join(dir, "csf.conf"), 0o640); err != nil {
		t.Fatal(err)
	}

	res := SafePortChange(context.Background(), PortChangeRequest{Port: 8110, Direction: "in", Action: "add"}, PortChangeOptions{})
	if res.Result != "applied" {
		t.Fatalf("result = %+v, want applied", res)
	}
	info, err := os.Stat(filepath.Join(dir, "csf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v, want 0640", info.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".csf.conf.defensia-") {
			t.Fatalf("leftover temp file: %s", e.Name())
		}
	}
}

func TestSafePortRestartBusyRetry(t *testing.T) {
	newSafePortFixture(t)
	withRestartRetryDelay(t, 5*time.Millisecond)
	var calls int32
	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "-r" {
			n := atomic.AddInt32(&calls, 1)
			if n == 1 {
				return []byte("Error: csf is being restarted, try again in a moment\n"), errors.New("exit status 1")
			}
			return []byte("ok\n"), nil
		}
		if name == "iptables" {
			return []byte("-N LOCALINPUT\n"), nil
		}
		return nil, errors.New("not stubbed")
	})

	res := SafePortChange(context.Background(), PortChangeRequest{Port: 8111, Direction: "in", Action: "add"}, PortChangeOptions{})
	if res.Result != "applied" {
		t.Fatalf("result = %+v, want applied", res)
	}
	if atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("csf -r called %d times, want 2", calls)
	}
}

func TestSafePortMutexSerializes(t *testing.T) {
	newSafePortFixture(t)
	var inFlight, overlap int32
	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "-r" {
			if !atomic.CompareAndSwapInt32(&inFlight, 0, 1) {
				atomic.StoreInt32(&overlap, 1)
			}
			time.Sleep(15 * time.Millisecond)
			atomic.StoreInt32(&inFlight, 0)
			return []byte("ok\n"), nil
		}
		if name == "iptables" {
			return []byte("-N LOCALINPUT\n"), nil
		}
		return nil, errors.New("not stubbed")
	})

	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			SafePortChange(context.Background(), PortChangeRequest{Port: port, Direction: "in", Action: "add"}, PortChangeOptions{})
		}(9100 + i)
	}
	wg.Wait()

	if atomic.LoadInt32(&overlap) != 0 {
		t.Fatal("csf -r calls overlapped across concurrent SafePortChange calls")
	}
}

// --- Legacy wrapper ----------------------------------------------------------

func TestCSFPortActionWrapper(t *testing.T) {
	newSafePortFixture(t)

	if err := CSFPortAction(8112, "in", "add"); err != nil {
		t.Fatalf("CSFPortAction applied: %v", err)
	}

	withSSHPortsFn(t, func(ctx context.Context) ([]int, []string) { return []int{22}, []string{"sshd-T"} })
	err := CSFPortAction(22, "in", "remove")
	if err == nil || !strings.Contains(err.Error(), "ssh_port_in_use") {
		t.Fatalf("CSFPortAction rejected: err = %v, want containing ssh_port_in_use", err)
	}
}

// --- afterCSFRestart reassertion count --------------------------------------

func TestSafePortReassertsDefensiaRules(t *testing.T) {
	t.Run("applied", func(t *testing.T) {
		newSafePortFixture(t)
		var n int32
		withAfterCSFRestartHook(t, func() { atomic.AddInt32(&n, 1) })

		res := SafePortChange(context.Background(), PortChangeRequest{Port: 8120, Direction: "in", Action: "add"}, PortChangeOptions{})
		if res.Result != "applied" {
			t.Fatalf("result = %+v", res)
		}
		if n != 1 {
			t.Fatalf("afterCSFRestart calls = %d, want 1", n)
		}
	})

	t.Run("failed and rolled back", func(t *testing.T) {
		newSafePortFixture(t)
		var n int32
		withAfterCSFRestartHook(t, func() { atomic.AddInt32(&n, 1) })

		var calls int32
		withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
			if len(args) > 0 && args[0] == "-r" {
				c := atomic.AddInt32(&calls, 1)
				if c == 1 {
					return []byte("*Error* boom\n"), errors.New("exit status 1")
				}
				return []byte("ok\n"), nil
			}
			if name == "iptables" {
				return []byte("-N LOCALINPUT\n"), nil
			}
			return nil, errors.New("not stubbed")
		})

		res := SafePortChange(context.Background(), PortChangeRequest{Port: 8121, Direction: "in", Action: "add"}, PortChangeOptions{})
		if res.Result != "failed" || !res.RolledBack {
			t.Fatalf("result = %+v, want failed/RolledBack=true", res)
		}
		if n != 2 {
			t.Fatalf("afterCSFRestart calls = %d, want 2", n)
		}
	})

	t.Run("unchanged", func(t *testing.T) {
		newSafePortFixture(t)
		var n int32
		withAfterCSFRestartHook(t, func() { atomic.AddInt32(&n, 1) })

		res := SafePortChange(context.Background(), PortChangeRequest{Port: 80, Direction: "in", Action: "add"}, PortChangeOptions{})
		if res.Result != "unchanged" {
			t.Fatalf("result = %+v", res)
		}
		if n != 0 {
			t.Fatalf("afterCSFRestart calls = %d, want 0", n)
		}
	})

	t.Run("rejected", func(t *testing.T) {
		newSafePortFixture(t)
		var n int32
		withAfterCSFRestartHook(t, func() { atomic.AddInt32(&n, 1) })

		res := SafePortChange(context.Background(), PortChangeRequest{Port: 0, Direction: "in", Action: "add"}, PortChangeOptions{})
		if res.Result != "rejected" {
			t.Fatalf("result = %+v", res)
		}
		if n != 0 {
			t.Fatalf("afterCSFRestart calls = %d, want 0", n)
		}
	})
}

// --- Never flush -------------------------------------------------------------

func TestSafePortNeverFlush(t *testing.T) {
	newSafePortFixture(t) // registers requireNeverFlush + a default success stub

	// A normal applied change.
	SafePortChange(context.Background(), PortChangeRequest{Port: 8130, Direction: "in", Action: "add"}, PortChangeOptions{})

	// A failed-and-rolled-back change, to exercise the rollback path too.
	var calls int32
	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "-r" {
			c := atomic.AddInt32(&calls, 1)
			if c == 1 {
				return []byte("*Error* boom\n"), errors.New("exit status 1")
			}
			return []byte("ok\n"), nil
		}
		if name == "iptables" {
			return []byte("-N LOCALINPUT\n"), nil
		}
		return nil, errors.New("not stubbed")
	})
	SafePortChange(context.Background(), PortChangeRequest{Port: 8131, Direction: "in", Action: "add"}, PortChangeOptions{})

	// The actual assertion runs in requireNeverFlush's t.Cleanup (shared by
	// every SafePort test), proving the guarantee continuously rather than
	// only here.
}

// TestComputePortChangeStandaloneInsideRange pins the case that shipped broken:
// a port present BOTH as a standalone token and inside a range. Removing the
// token alone leaves the port open via the range, so the change must be
// refused rather than reported as applied.
func TestComputePortChangeStandaloneInsideRange(t *testing.T) {
	const current = "22,80,443,8000:9000,8080"

	newValue, changed, reject := computePortChange(current, 8080, "remove")

	if changed {
		t.Errorf("changed = true, want false: removing the standalone token leaves 8080 open via 8000:9000 (newValue=%q)", newValue)
	}
	if reject != "port_in_range" {
		t.Errorf("rejectReason = %q, want %q", reject, "port_in_range")
	}
	if newValue != current {
		t.Errorf("newValue = %q, want it unchanged (%q)", newValue, current)
	}
}
