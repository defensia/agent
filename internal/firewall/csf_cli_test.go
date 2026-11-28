package firewall

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// withCSFRun replaces the csfRun seam for the duration of the test.
func withCSFRun(t *testing.T, fn func(ctx context.Context, bin string, args ...string) ([]byte, int, error)) {
	t.Helper()
	prev := csfRun
	csfRun = fn
	t.Cleanup(func() { csfRun = prev })
}

func newTestCLI(t *testing.T) *csfCLI {
	t.Helper()
	return &csfCLI{bin: "/usr/sbin/csf"}
}

func TestCSFArgvTempDeny(t *testing.T) {
	var gotArgs []string
	withCSFRun(t, func(ctx context.Context, bin string, args ...string) ([]byte, int, error) {
		gotArgs = args
		return []byte("DROP all\ncsf: 203.0.113.7 blocked on port * for 5400 seconds inbound\n"), 0, nil
	})
	c := newTestCLI(t)

	if _, err := c.TempDeny(context.Background(), "203.0.113.7", 90*time.Minute, "brute force -p 22"); err != nil {
		t.Fatalf("TempDeny: %v", err)
	}
	want := []string{"-td", "203.0.113.7", "5400", "defensia:brute_force_p_22"}
	if strings.Join(gotArgs, " ") != strings.Join(want, " ") {
		t.Fatalf("argv = %v, want %v", gotArgs, want)
	}

	if _, err := c.TempDeny(context.Background(), "203.0.113.7", 10*time.Second, ""); err != nil {
		t.Fatalf("TempDeny (short ttl): %v", err)
	}
	if gotArgs[2] != "60" {
		t.Fatalf("ttl 10s -> %q, want clamped to csfMinTTL (60)", gotArgs[2])
	}
	if gotArgs[3] != "defensia:ban" {
		t.Fatalf("empty reason -> %q, want defensia:ban", gotArgs[3])
	}

	if _, err := c.TempDeny(context.Background(), "203.0.113.7", 90*24*time.Hour, ""); err != nil {
		t.Fatalf("TempDeny (long ttl): %v", err)
	}
	if gotArgs[2] != "2592000" {
		t.Fatalf("ttl 90d -> %q, want clamped to csfMaxTTL (2592000)", gotArgs[2])
	}

	longReason := strings.Repeat("x", 200)
	if _, err := c.TempDeny(context.Background(), "203.0.113.7", time.Hour, longReason); err != nil {
		t.Fatalf("TempDeny (long reason): %v", err)
	}
	if len(gotArgs[3]) > len("defensia:")+48 {
		t.Fatalf("comment too long: %q (%d chars)", gotArgs[3], len(gotArgs[3]))
	}
}

func TestCSFArgvRejectsInvalidIP(t *testing.T) {
	called := false
	withCSFRun(t, func(ctx context.Context, bin string, args ...string) ([]byte, int, error) {
		called = true
		return nil, 0, nil
	})
	c := newTestCLI(t)

	for _, bad := range []string{"1.2.3", "", "1.2.3.4 -d out", "::ffff:zz"} {
		called = false
		if _, err := c.TempDeny(context.Background(), bad, time.Hour, "x"); err == nil {
			t.Errorf("TempDeny(%q): want error, got nil", bad)
		}
		if called {
			t.Errorf("TempDeny(%q): runner was called for invalid IP", bad)
		}
	}
}

func TestCSFArgvNeverForbidden(t *testing.T) {
	var seenFlags []string
	withCSFRun(t, func(ctx context.Context, bin string, args ...string) ([]byte, int, error) {
		if len(args) > 0 {
			seenFlags = append(seenFlags, args[0])
		}
		return []byte("csf: v15.00 (generic)\ncsf: 192.0.2.1 blocked on port * for 60 seconds inbound\ncsf: 192.0.2.1 temporary block removed\ncsf: There are no temporary IP allows\n"), 0, nil
	})
	c := newTestCLI(t)
	ctx := context.Background()

	_, _ = c.Version(ctx)
	_ = c.ListTemp(ctx)
	_, _ = c.TempDeny(ctx, "192.0.2.1", time.Hour, "x")
	_, _ = c.TempRemove(ctx, "192.0.2.1")

	allowed := map[string]bool{"-v": true, "-t": true, "-td": true, "-tr": true}
	for _, f := range seenFlags {
		if !allowed[f] {
			t.Errorf("forbidden flag issued: %q", f)
		}
	}
	if len(seenFlags) != 4 {
		t.Fatalf("expected 4 calls, got %d: %v", len(seenFlags), seenFlags)
	}
}

func TestCSFClassifyFixtures(t *testing.T) {
	root := "testdata"
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	checked := 0
	for _, e := range entries {
		if !e.IsDir() || e.Name() == "fakecsf" {
			continue
		}
		dir := filepath.Join(root, e.Name())
		check := func(file string, want CSFResult, classify func(string, int) CSFOutcome) {
			t.Helper()
			path := filepath.Join(dir, file)
			data, err := os.ReadFile(path)
			if err != nil {
				return // not every fork necessarily has every fixture
			}
			exit := extractExit(string(data))
			out := classify(stripExitMarker(string(data)), exit)
			if out.Result != want {
				t.Errorf("%s: classify -> %s (%s), want %s", path, out.Result, out.Reason, want)
			}
			checked++
		}
		check("csf-td-ok.txt", ResultOK, classifyTempDeny)
		check("csf-td-already.txt", ResultBenign, classifyTempDeny)
		check("csf-tr-ok.txt", ResultOK, classifyTempRemove)
		check("csf-tr-notfound.txt", ResultBenign, classifyTempRemove)
		check("csf-tr-empty.txt", ResultBenign, classifyTempRemove)

		vPath := filepath.Join(dir, "csf-v.txt")
		if data, err := os.ReadFile(vPath); err == nil {
			exit := extractExit(string(data))
			out := classifyVersion(stripExitMarker(string(data)), exit)
			if out.Result != ResultOK {
				t.Errorf("%s: Version() -> %s (%s)", vPath, out.Result, out.Reason)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Skip("no testdata fixtures present yet (run lab/csf-bench.sh first)")
	}
}

// stripExitMarker removes the trailing "#exit=N" line lab/csf-bench.sh
// appends to every captured fixture file — a fixture-capture artifact only,
// never part of real `csf` output, so classify* must not see it.
func stripExitMarker(content string) string {
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	for len(lines) > 0 && strings.HasPrefix(lines[len(lines)-1], "#exit=") {
		lines = lines[:len(lines)-1]
	}
	return strings.Join(lines, "\n")
}

// extractExit reads the trailing "#exit=N" line lab/csf-bench.sh appends to
// every captured fixture file.
func extractExit(content string) int {
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.HasPrefix(lines[i], "#exit=") {
			var n int
			fmt.Sscanf(lines[i], "#exit=%d", &n)
			return n
		}
	}
	return 0
}

func TestCSFClassifyUnexpected(t *testing.T) {
	cases := []struct {
		name string
		out  string
		exit int
	}{
		{"empty", "", 0},
		{"binary", "\x00\x01\x02binary", 0},
		{"perl missing", "Perl: command not found", 0},
		{"unknown text", "csf: blocked", 0},
		{"huge", strings.Repeat("A", 70*1024), 0},
		{"ok text but exit 1", "csf: 1.2.3.4 blocked on port * for 60 seconds inbound", 1},
		{"iptables error", "Error: iptables: No chain/target/match by that name.", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := classifyTempDeny(c.out, c.exit)
			if out.Result != ResultUnexpected {
				t.Errorf("classifyTempDeny(%q, %d) = %s, want unexpected", c.name, c.exit, out.Result)
			}
		})
	}
}

func TestCSFRunnerTimeout(t *testing.T) {
	withCSFRun(t, func(ctx context.Context, bin string, args ...string) ([]byte, int, error) {
		select {
		case <-ctx.Done():
			return nil, -1, nil
		case <-time.After(5 * time.Second):
			return []byte("csf: too late"), 0, nil
		}
	})
	c := newTestCLI(t)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	out, err := c.TempDeny(ctx, "192.0.2.1", time.Hour, "x")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("TempDeny: %v", err)
	}
	if out.Result != ResultUnexpected {
		t.Errorf("timeout result = %s, want unexpected", out.Result)
	}
	if elapsed > csfCmdTimeout+time.Second {
		t.Errorf("took %v, want within csfCmdTimeout+1s", elapsed)
	}
}

func TestCSFBinResolution(t *testing.T) {
	tmp := t.TempDir()
	exe := filepath.Join(tmp, "myfakecsf")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("DEFENSIA_CSF_BIN", exe)
	bin, err := resolveCSFBin()
	if err != nil || bin != exe {
		t.Fatalf("resolveCSFBin with override = %q, %v; want %q, nil", bin, err, exe)
	}

	t.Setenv("DEFENSIA_CSF_BIN", "")
	prevLookPath := lookPath
	lookPath = func(string) (string, error) { return "", exec.ErrNotFound }
	t.Cleanup(func() { lookPath = prevLookPath })
	prevHostRoot := hostRoot
	hostRoot = t.TempDir() // no /usr/sbin/csf or /usr/local/csf/bin/csf here
	t.Cleanup(func() { hostRoot = prevHostRoot })

	if _, err := resolveCSFBin(); err != ErrCSFMissing {
		t.Fatalf("resolveCSFBin with nothing available = %v, want ErrCSFMissing", err)
	}
}

func TestFakeCSFScript(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	bin, err := filepath.Abs("testdata/fakecsf/csf")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("fake csf binary missing: %v", err)
	}

	tempban := filepath.Join(t.TempDir(), "csf.tempban")
	logFile := filepath.Join(t.TempDir(), "calls.log")

	run := func(mode string, args ...string) (string, int) {
		cmd := exec.Command(bin, args...)
		cmd.Env = append(os.Environ(), "FAKECSF_MODE="+mode, "FAKECSF_TEMPBAN="+tempban, "FAKECSF_LOG="+logFile)
		out, _ := cmd.CombinedOutput()
		return string(out), cmd.ProcessState.ExitCode()
	}

	out, code := run("ok", "-td", "198.51.100.5", "600", "defensia:test")
	if code != 0 || !strings.Contains(out, "blocked on port") {
		t.Fatalf("ok -td: code=%d out=%q", code, out)
	}
	resultOK := classifyTempDeny(out, code)
	if resultOK.Result != ResultOK {
		t.Fatalf("ok -td classify = %s", resultOK.Result)
	}

	out, code = run("ok", "-tr", "198.51.100.5")
	if code != 0 || !strings.Contains(out, "temporary block removed") {
		t.Fatalf("ok -tr: code=%d out=%q", code, out)
	}

	out, code = run("garbage", "-td", "198.51.100.6", "600", "defensia:test")
	if classifyTempDeny(out, code).Result != ResultUnexpected {
		t.Fatalf("garbage mode not classified unexpected: %q", out)
	}

	data, err := os.ReadFile(logFile)
	if err != nil || len(strings.TrimSpace(string(data))) == 0 {
		t.Fatalf("FAKECSF_LOG not populated: %v", err)
	}
}
