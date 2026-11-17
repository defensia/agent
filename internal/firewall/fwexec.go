package firewall

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// fwRunner executes a firewall CLI (ipset, iptables, ip6tables, nft). stdin may
// be "". Returns combined stdout+stderr. Tests replace fwRun; production uses
// defaultFwRun. Named distinctly from Phase 15's csf_exec.go `run()` choke
// point on purpose — this seam is for ipset/iptables/nft backends, not CSF.
type fwRunner func(ctx context.Context, stdin, name string, args ...string) ([]byte, error)

var (
	fwRun      fwRunner = defaultFwRun
	fwLookPath          = exec.LookPath
)

const (
	fwExecTimeout = 30 * time.Second  // single bans, lists, probes
	fwLongTimeout = 120 * time.Second // batches and country sets
)

func defaultFwRun(ctx context.Context, stdin, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	return cmd.CombinedOutput()
}

// fwExec runs name with args, no stdin, under fwExecTimeout.
func fwExec(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), fwExecTimeout)
	defer cancel()
	return fwRun(ctx, "", name, args...)
}

// fwExecIn runs name with args and stdin, under fwExecTimeout.
func fwExecIn(stdin, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), fwExecTimeout)
	defer cancel()
	return fwRun(ctx, stdin, name, args...)
}

// fwExecLong runs name with args and stdin, under fwLongTimeout (batches,
// country sets — operations that can process thousands of elements).
func fwExecLong(stdin, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), fwLongTimeout)
	defer cancel()
	return fwRun(ctx, stdin, name, args...)
}

// fwOK reports whether name with args exits 0 (replaces the
// `exec.Command(...).Run() == nil` existence checks scattered through
// ipset.go/iptables.go before this seam existed).
func fwOK(name string, args ...string) bool {
	_, err := fwExec(name, args...)
	return err == nil
}
