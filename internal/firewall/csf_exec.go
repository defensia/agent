package firewall

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"time"
)

// Every command this package runs goes through run(): one place for timeouts,
// grandchild cleanup (perl forks) and test observation. This exists because the
// original csfExec seam called exec.Command directly from inside the heartbeat
// goroutine with no timeout at all — a hung `csf -v` stalled every heartbeat.
var (
	hostRoot = "/" // test seam: fixture trees mirror /usr, /var, /proc, /etc/cron.d

	csfExecTimeout    = 5 * time.Second  // csf -v, rpm -q, systemctl, sshd -T, ss, iptables -S
	csfRestartTimeout = 90 * time.Second // csf -r only (used by plan 05)

	lookPath = exec.LookPath // test seam

	// runCmd is the test seam for run()'s actual execution. Tests replace it to
	// avoid spawning real processes; production always uses realRun.
	runCmd = realRun

	cmdObserver atomic.Pointer[func(name string, args []string)]
)

// realRun executes name with args under a context timeout. The wait delay set
// below bounds how long we wait for the process (and any grandchildren holding
// stdout/stderr open, e.g. perl forks) to exit after the context is cancelled.
func realRun(parent context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, d)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = 2 * time.Second

	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("%s timed out after %s: %w", name, d, ctx.Err())
	}
	return out, err
}

// run is the single choke point every CSF (and related) command in this package
// goes through: it notifies any registered observer, then delegates to runCmd.
func run(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
	if fn := cmdObserver.Load(); fn != nil {
		(*fn)(name, args)
	}
	return runCmd(ctx, d, name, args...)
}

// ObserveCommands registers fn to be called for every command the firewall
// package runs via run(). Used by integration tests to prove no CSF command
// runs (COL-06 / kill switch). Returns restore, which puts back whatever
// observer (if any) was registered before this call.
func ObserveCommands(fn func(name string, args []string)) (restore func()) {
	prev := cmdObserver.Load()
	cmdObserver.Store(&fn)
	return func() {
		cmdObserver.Store(prev)
	}
}

// hostPath joins p onto hostRoot. In production hostRoot is "/", so hostPath is
// a no-op; tests point hostRoot at a temp tree that mirrors the paths this
// package reads (e.g. /usr/sbin/csf, /var/run/lfd.pid).
func hostPath(p string) string {
	return filepath.Join(hostRoot, p)
}

// csfBinaryPath locates the csf binary. Unlike HasCSF's sync.Once, this
// re-checks on every call so the collector notices install/removal without
// requiring an agent restart.
func csfBinaryPath() string {
	if p, err := lookPath("csf"); err == nil {
		return p
	}
	for _, candidate := range []string{"/usr/sbin/csf", "/usr/local/csf/bin/csf"} {
		p := hostPath(candidate)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
