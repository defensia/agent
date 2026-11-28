package firewall

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// This file is the single, audited CSF CLI surface for the ban executor
// (SYNC-02, SYNC-07): the ONLY flags it can ever issue are -v, -t, -td, -tr.
// It builds on the existing run()/csfBinaryPath() choke point from Phase 15
// (csf_exec.go) rather than a second, parallel exec path, so every CSF
// invocation in this package still goes through the one place that bounds
// timeouts and lets tests observe commands (ObserveCommands, used elsewhere
// to prove the kill switch runs zero CSF commands).
//
// Classification regexes below are grounded in REAL output captured from 6
// lab VMs across 4 forks (lab/csf-bench.sh, lab/reports/*-csf-td-bench.md),
// not assumed from documentation. One finding that changed the design from
// the original research assumption: csf -td on a PRIVATE IP (10.0.0.5) is
// NOT refused by stock CSF v15.00 — it bans it like any other IP. "is not a
// valid PUBLIC IP" is a real CSF message (seen in its source), but it is not
// triggered by private ranges on the forks measured here; this layer still
// validates the IP syntactically (net/netip) before exec, which is the part
// that actually matters for SYNC-07 (never exec with a malformed argv).

// CSFResult classifies the outcome of a single CSF CLI invocation.
type CSFResult int

const (
	ResultOK CSFResult = iota
	ResultBenign
	ResultRefused
	ResultUnexpected
)

func (r CSFResult) String() string {
	switch r {
	case ResultOK:
		return "ok"
	case ResultBenign:
		return "benign"
	case ResultRefused:
		return "refused"
	default:
		return "unexpected"
	}
}

// CSFOutcome is the result of one csfCLI call.
type CSFOutcome struct {
	Result   CSFResult
	Reason   string
	Output   string
	ExitCode int
	Duration time.Duration
}

// ErrCSFMissing is returned when no csf binary can be found.
var ErrCSFMissing = errors.New("csf binary not found")

// csfRun is the test seam: production execs via run() (csf_exec.go); tests
// replace it to avoid spawning real processes. Returns combined output, the
// process exit code (0 on success), and a Go error only for seam-level
// failures (binary missing, context deadline) — a nonzero CSF exit code is
// NOT a Go error, it is reported via the returned exit code so classify*
// can decide (some real CSF errors still exit 0).
var csfRun = func(ctx context.Context, bin string, args ...string) ([]byte, int, error) {
	out, err := run(ctx, csfCmdTimeout, bin, args...)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded || strings.Contains(err.Error(), "timed out after") {
			return out, -1, nil // timeout: exit code -1, classified by output size/emptiness below
		}
		var exitErr interface{ ExitCode() int }
		if ok := errorsAsExitCode(err, &exitErr); ok {
			return out, exitErr.ExitCode(), nil
		}
		return out, -1, err
	}
	return out, 0, nil
}

// errorsAsExitCode is a tiny errors.As wrapper kept local so csf_cli.go has
// no import-cycle or extra dependency beyond the standard errors package.
func errorsAsExitCode(err error, target *interface{ ExitCode() int }) bool {
	type exitCoder interface{ ExitCode() int }
	var ec exitCoder
	if e, ok := err.(exitCoder); ok {
		ec = e
		*target = ec
		return true
	}
	return false
}

// resolveCSFBin: DEFENSIA_CSF_BIN (must be absolute + executable, lab/dev
// override only) -> csfBinaryPath()'s own PATH/fallback resolution.
func resolveCSFBin() (string, error) {
	if envBin := os.Getenv("DEFENSIA_CSF_BIN"); envBin != "" {
		if !strings.HasPrefix(envBin, "/") {
			return "", ErrCSFMissing
		}
		if st, err := os.Stat(envBin); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return envBin, nil
		}
		return "", ErrCSFMissing
	}
	if bin := csfBinaryPath(); bin != "" {
		return bin, nil
	}
	return "", ErrCSFMissing
}

// csfCLI is the strict, locked-down CSF command surface: only Version,
// ListTemp, TempDeny and TempRemove ever exec anything.
type csfCLI struct {
	bin string
}

func newCSFCLI() (*csfCLI, error) {
	bin, err := resolveCSFBin()
	if err != nil {
		return nil, err
	}
	return &csfCLI{bin: bin}, nil
}

func (c *csfCLI) exec(ctx context.Context, args ...string) ([]byte, int, time.Duration, error) {
	start := time.Now()
	out, code, err := csfRun(ctx, c.bin, args...)
	return out, code, time.Since(start), err
}

// Version runs `csf -v`.
func (c *csfCLI) Version(ctx context.Context) (string, CSFOutcome) {
	out, code, dur, err := c.exec(ctx, "-v")
	if err != nil {
		return "", CSFOutcome{Result: ResultUnexpected, Reason: "exec_error: " + err.Error(), Duration: dur}
	}
	o := classifyVersion(string(out), code)
	o.Duration = dur
	v := ""
	if o.Result == ResultOK {
		v = extractVersion(string(out))
	}
	return v, o
}

// ListTemp runs `csf -t` — used only as a read-only sanity cross-check,
// never to decide anything by itself.
func (c *csfCLI) ListTemp(ctx context.Context) CSFOutcome {
	out, code, dur, err := c.exec(ctx, "-t")
	if err != nil {
		return CSFOutcome{Result: ResultUnexpected, Reason: "exec_error: " + err.Error(), Duration: dur}
	}
	o := classifyListTemp(string(out), code)
	o.Duration = dur
	return o
}

// TempDeny runs `csf -td <ip> <ttlSeconds> defensia:<reason>`.
func (c *csfCLI) TempDeny(ctx context.Context, ip string, ttl time.Duration, reason string) (CSFOutcome, error) {
	canonIP, err := canonicalIP(ip)
	if err != nil {
		return CSFOutcome{}, err
	}
	comment := "defensia:" + sanitizeReason(reason)
	out, code, dur, rerr := c.exec(ctx, "-td", canonIP, ttlSeconds(ttl), comment)
	if rerr != nil {
		return CSFOutcome{Result: ResultUnexpected, Reason: "exec_error: " + rerr.Error(), Duration: dur}, nil
	}
	o := classifyTempDeny(string(out), code)
	o.Duration = dur
	return o, nil
}

// TempRemove runs `csf -tr <ip>`.
func (c *csfCLI) TempRemove(ctx context.Context, ip string) (CSFOutcome, error) {
	canonIP, err := canonicalIP(ip)
	if err != nil {
		return CSFOutcome{}, err
	}
	out, code, dur, rerr := c.exec(ctx, "-tr", canonIP)
	if rerr != nil {
		return CSFOutcome{Result: ResultUnexpected, Reason: "exec_error: " + rerr.Error(), Duration: dur}, nil
	}
	o := classifyTempRemove(string(out), code)
	o.Duration = dur
	return o, nil
}

// --- Argument sanitizers (run BEFORE any exec; invalid input never execs) ---

func canonicalIP(ip string) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return "", errInvalidIP
	}
	return addr.String(), nil
}

var errInvalidIP = errors.New("invalid IP address")

// ttlSeconds clamps d to [csfMinTTL, csfMaxTTL] and formats it as plain
// integer seconds (CSF's own argv form for -td's TTL argument).
func ttlSeconds(d time.Duration) string {
	if d < csfMinTTL {
		d = csfMinTTL
	}
	if d > csfMaxTTL {
		d = csfMaxTTL
	}
	return strconv.Itoa(int(d / time.Second))
}

var reasonInvalidRune = regexp.MustCompile(`[^a-z0-9]+`)

// sanitizeReason lowercases, maps every run of non [a-z0-9] runes to a
// single underscore, trims leading/trailing underscores, and truncates to
// 48 chars so "defensia:"+reason never exceeds CSF's comment handling.
func sanitizeReason(reason string) string {
	s := strings.ToLower(strings.TrimSpace(reason))
	s = reasonInvalidRune.ReplaceAllString(s, "_")
	s = strings.Trim(s, "_")
	if s == "" {
		return "ban"
	}
	if len(s) > 48 {
		s = strings.Trim(s[:48], "_")
		if s == "" {
			return "ban"
		}
	}
	return s
}

// --- Output classification (pure functions, fixture-tested) -----------------

var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// bannerAllowlist matches benign filler lines real CSF output interleaves
// with the actual result line — confirmed present in the lab fixtures
// (captured 2026-11-25, lab/csf-bench.sh): the live iptables rule echo line
// CSF prints before/after every -td/-tr ("DROP ... -> 0.0.0.0/0", sometimes
// indented, fork-dependent), the trailing allow-list status line CSF always
// appends after -tr regardless of the ban-removal outcome ("There are no
// temporary IP allows" — this is about ALLOW entries, an orthogonal status,
// NOT a signal about the ban itself), blank lines, and the csf -v banner
// lines. Deliberately does NOT include "There are no temporary IP bans" —
// that line IS the semantic Benign signal for an empty tempban list and
// must reach reTempRemoveBenign, not be stripped as filler.
var bannerAllowlist = regexp.MustCompile(
	`^(?:` +
		`ConfigServer Security & Firewall|` +
		`License:.*|` +
		`Channel:.*|` +
		`v\d+\.\d+.*|` +
		`\*WARNING\* URLGET.*|` +
		`\*WARNING\* TESTING mode is enabled.*|` +
		`\s*(DROP|DENY|ACCEPT)\s+all\s+opt.*->.*|` +
		`csf: There are no temporary IP allows|` +
		`\s*` +
		`)$`,
)

var (
	reTempDenyOK       = regexp.MustCompile(`^csf: \S+ blocked on port (\*|\S+) for \d+ seconds (inbound|outbound|in and outbound)`)
	reTempDenyBenign   = regexp.MustCompile(`already (temporarily|permanently) blocked`)
	reTempDenyRefused  = regexp.MustCompile(`is not a valid PUBLIC IP|is one of this servers addresses|IPV6 is not enabled|is already (permanently )?blocked in csf\.deny|deny failed:.*is one of this servers addresses`)
	reTempRemoveOK     = regexp.MustCompile(`temporary block removed`)
	reTempRemoveBenign = regexp.MustCompile(`not found in temporary bans|There are no temporary IP bans`)
	reIptablesError    = regexp.MustCompile(`iptables: |No chain/target/match|Bad rule`)
)

// cleanOutput strips ANSI, rejects non-UTF8/NUL, and splits into non-banner
// lines. ok=false means the output itself is unexpected (binary/garbage).
func cleanOutput(out string) (lines []string, ok bool) {
	if !utf8.ValidString(out) || strings.ContainsRune(out, '\x00') {
		return nil, false
	}
	clean := ansiEscape.ReplaceAllString(out, "")
	for _, line := range strings.Split(clean, "\n") {
		if bannerAllowlist.MatchString(line) {
			continue
		}
		trimmed := strings.TrimRight(line, "\r")
		if trimmed == "" {
			continue
		}
		lines = append(lines, trimmed)
	}
	return lines, true
}

func classifyTempDeny(out string, exit int) CSFOutcome {
	return classifyResult(out, exit, reTempDenyOK, reTempDenyBenign, reTempDenyRefused)
}

func classifyTempRemove(out string, exit int) CSFOutcome {
	return classifyResult(out, exit, reTempRemoveOK, reTempRemoveBenign, nil)
}

func classifyResult(out string, exit int, reOK, reBenign, reRefused *regexp.Regexp) CSFOutcome {
	if len(out) > csfOutputCap {
		return CSFOutcome{Result: ResultUnexpected, Reason: "output_too_large", Output: out[:256], ExitCode: exit}
	}
	lines, ok := cleanOutput(out)
	if !ok {
		return CSFOutcome{Result: ResultUnexpected, Reason: "non_utf8_or_nul_output", Output: out, ExitCode: exit}
	}
	if reIptablesError.MatchString(out) {
		return CSFOutcome{Result: ResultUnexpected, Reason: "iptables_error", Output: out, ExitCode: exit}
	}
	if len(lines) == 0 {
		return CSFOutcome{Result: ResultUnexpected, Reason: "empty_or_banner_only_output", Output: out, ExitCode: exit}
	}
	var sawOK, sawBenign, sawRefused bool
	for _, line := range lines {
		switch {
		case reOK != nil && reOK.MatchString(line):
			sawOK = true
		case reBenign != nil && reBenign.MatchString(line):
			sawBenign = true
		case reRefused != nil && reRefused.MatchString(line):
			sawRefused = true
		default:
			return CSFOutcome{Result: ResultUnexpected, Reason: "unknown_line: " + line, Output: out, ExitCode: exit}
		}
	}
	switch {
	case sawRefused:
		return CSFOutcome{Result: ResultRefused, Output: out, ExitCode: exit}
	case sawOK && exit == 0:
		return CSFOutcome{Result: ResultOK, Output: out, ExitCode: exit}
	case sawBenign && exit == 0:
		return CSFOutcome{Result: ResultBenign, Output: out, ExitCode: exit}
	default:
		// OK/Benign text but non-zero exit is NOT trusted — real success is exit 0.
		return CSFOutcome{Result: ResultUnexpected, Reason: "nonzero_exit", Output: out, ExitCode: exit}
	}
}

func classifyVersion(out string, exit int) CSFOutcome {
	if exit != 0 {
		return CSFOutcome{Result: ResultUnexpected, Reason: "nonzero_exit", Output: out, ExitCode: exit}
	}
	lines, ok := cleanOutput(out)
	if !ok {
		return CSFOutcome{Result: ResultUnexpected, Reason: "non_utf8_or_nul_output", Output: out, ExitCode: exit}
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "csf: v") || regexp.MustCompile(`^v\d+\.\d+`).MatchString(line) {
			return CSFOutcome{Result: ResultOK, Output: out, ExitCode: exit}
		}
	}
	if len(lines) == 0 {
		// version banner lines are themselves allowlisted — an all-banner
		// csf -v output (seen on some forks) is still OK, not unexpected.
		return CSFOutcome{Result: ResultOK, Output: out, ExitCode: exit}
	}
	return CSFOutcome{Result: ResultUnexpected, Reason: "unknown_line: " + lines[0], Output: out, ExitCode: exit}
}

func classifyListTemp(out string, exit int) CSFOutcome {
	if exit != 0 {
		return CSFOutcome{Result: ResultUnexpected, Reason: "nonzero_exit", Output: out, ExitCode: exit}
	}
	// -t's table header/rows are free-form (IP/port/ttl/comment columns);
	// this is a read-only sanity check, not parsed strictly.
	if !utf8.ValidString(out) || strings.ContainsRune(out, '\x00') {
		return CSFOutcome{Result: ResultUnexpected, Reason: "non_utf8_or_nul_output", Output: out, ExitCode: exit}
	}
	return CSFOutcome{Result: ResultOK, Output: out, ExitCode: exit}
}

var reVersionExtract = regexp.MustCompile(`v(\d+\.\d+)`)

func extractVersion(out string) string {
	m := reVersionExtract.FindStringSubmatch(out)
	if len(m) == 2 {
		return m[1]
	}
	return ""
}
