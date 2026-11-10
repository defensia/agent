package firewall

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// SafePortChange (COL-05) replaces the old sed-i + csf -r CSFPortAction with
// a safe, reversible operation: guard -> backup -> Go-side validate ->
// atomic write -> `csf -r` with timeout -> health check -> automatic
// rollback on any failure. The purpose, stated once and binding for every
// branch below: a port button in the panel must never lock a customer out
// of their own machine or leave CSF down. `csf -f` (flush) is NEVER run,
// including on the critical path where rollback itself fails.
type PortChangeRequest struct {
	Port      int
	Direction string // "in" | "out"
	Action    string // "add" | "remove"
}

// PortChangeOptions.PanelPort is the TCP_OUT port the agent's own API
// traffic depends on (derived from server_url by the caller); 0 means "skip
// the guard" (e.g. when the caller doesn't know it).
type PortChangeOptions struct {
	PanelPort int
}

// PortChangeResult.Reason values: "" | invalid_request | csf_not_installed |
// integration_disabled | csf_disabled | ssh_port_in_use | panel_port_in_use |
// port_in_range | key_missing | duplicate_key | invalid_existing_value |
// backup_failed | write_failed | restart_failed | restart_timeout |
// health_check_failed | lfd_not_running | rollback_failed
type PortChangeResult struct {
	Result       string // applied | unchanged | rejected | failed | rollback_failed
	Reason       string
	RolledBack   bool
	Backup       string
	IPv6Mirrored bool
	TestingMode  bool
	Err          error
}

var (
	csfBackupDir      = "/etc/defensia/csf-backups"
	csfBackupKeep     = 5
	restartRetryDelay = 3 * time.Second
	lfdPollTimeout    = 10 * time.Second

	sshPortsFn = activeSSHPorts // test seam

	// csfFaultHook is nil in every production build: only
	// csf_fault_integration.go (which carries //go:build integration and is
	// therefore never compiled into `go build ./...`) can set it, via
	// SetCSFFaultHook. It exists so a real-VM lab test can inject a fault at
	// a named stage ("after_write", "after_rollback_write") to prove
	// rollback actually restores a live CSF install, not just that the code
	// runs.
	csfFaultHook func(stage, confPath string) error

	// csfWriteMu serializes every SafePortChange call end to end (guards
	// through rollback): two concurrent port actions must never run `csf -r`
	// at the same time.
	csfWriteMu sync.Mutex

	// afterCSFRestart re-creates the defensia-bans ipset sets and the
	// iptables DROP rule that point at them (Init is idempotent: it checks
	// before creating/adding) — a CSF restart rebuilds INPUT from csf.conf
	// and silently drops anything CSF itself didn't put there. It is called
	// after EVERY completed `csf -r`, success or failure, because the chain
	// rebuild happens either way. Phase 17 (17-05) switches this default
	// body from Init() to firewall.Ensure() after rebasing onto post-15
	// origin/main — keep the var name, signature and "= func() { Init() }"
	// shape exactly so that switch stays a one-line change.
	afterCSFRestart = func() { Init() }
)

// SetAfterCSFRestartHook lets main (or later phases) extend what runs after
// every CSF restart. It always keeps the re-assertion semantics of the
// default — callers that want to ADD behaviour should call Init() (or its
// Phase 17 successor) themselves inside fn.
func SetAfterCSFRestartHook(fn func()) {
	afterCSFRestart = fn
}

// validPortList validates a csf.conf TCP_IN/TCP_OUT-style value: a
// comma-separated list of ports (1-65535) and/or "a:b" ranges (a<=b, both
// 1-65535), no duplicate tokens, no empty tokens. An empty string is valid
// (an empty port list).
func validPortList(v string) bool {
	if v == "" {
		return true
	}
	seen := map[string]bool{}
	for _, tok := range strings.Split(v, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" || seen[tok] {
			return false
		}
		seen[tok] = true
		lo, hi, isRange := strings.Cut(tok, ":")
		a, err := strconv.Atoi(lo)
		if err != nil || a < 1 || a > 65535 {
			return false
		}
		if isRange {
			b, err := strconv.Atoi(hi)
			if err != nil || b < a || b > 65535 {
				return false
			}
		}
	}
	return true
}

// errKeyMissing/errDuplicateKey are rewriteConfKeys' sentinel errors —
// corresponding to PortChangeResult.Reason "key_missing"/"duplicate_key".
var (
	errKeyMissing   = errors.New("key_missing")
	errDuplicateKey = errors.New("duplicate_key")
)

// confLineFull captures a csf.conf KEY = "value" line's leading whitespace,
// key, "= \"" separator, value, and everything from the closing quote
// onward (including any trailing "# comment") — the four pieces
// rewriteConfKeys needs to change ONLY the value and leave byte-identical
// everything else on the line.
var confLineFull = regexp.MustCompile(`^(\s*)([A-Z0-9_]+)(\s*=\s*")([^"]*)(".*)$`)

// rewriteConfKeys returns content with ONLY the quoted value of each key in
// updates replaced, on that key's single uncommented line — every other
// byte of the file (including other lines' trailing comments) is untouched.
// Returns errKeyMissing if a requested key has no uncommented occurrence,
// errDuplicateKey if it has more than one (both indicate a csf.conf this
// package cannot safely edit).
func rewriteConfKeys(content []byte, updates map[string]string) ([]byte, error) {
	lines := strings.Split(string(content), "\n")

	counts := map[string]int{}
	targetLine := map[string]int{}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		m := confLineFull.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key := m[2]
		if _, want := updates[key]; !want {
			continue
		}
		counts[key]++
		targetLine[key] = i
	}

	for key := range updates {
		switch counts[key] {
		case 0:
			return nil, fmt.Errorf("%s: %w", key, errKeyMissing)
		case 1:
			// exactly one uncommented occurrence: fine.
		default:
			return nil, fmt.Errorf("%s: %w", key, errDuplicateKey)
		}
	}

	for key, newVal := range updates {
		i := targetLine[key]
		m := confLineFull.FindStringSubmatch(lines[i])
		lines[i] = m[1] + m[2] + m[3] + newVal + m[5]
	}

	return []byte(strings.Join(lines, "\n")), nil
}

// rewriteErrReason maps a rewriteConfKeys error to a PortChangeResult.Reason.
func rewriteErrReason(err error) string {
	switch {
	case errors.Is(err, errKeyMissing):
		return "key_missing"
	case errors.Is(err, errDuplicateKey):
		return "duplicate_key"
	default:
		return "write_failed"
	}
}

// portListStatus reports whether port appears as a standalone token in
// value, and/or falls inside one of its "a:b" ranges. A port removal that is
// covered ONLY by a range (inRange && !standalone) cannot be expressed by
// deleting a single token — reason port_in_range.
func portListStatus(value string, port int) (standalone, inRange bool) {
	portStr := strconv.Itoa(port)
	for _, tok := range strings.Split(value, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(tok, ":")
		if !isRange {
			if tok == portStr {
				standalone = true
			}
			continue
		}
		a, erra := strconv.Atoi(lo)
		b, errb := strconv.Atoi(hi)
		if erra == nil && errb == nil && port >= a && port <= b {
			inRange = true
		}
	}
	return
}

// computePortChange computes the new value of a single TCP_IN/TCP_OUT-style
// key for one add/remove request. rejectReason is non-empty only for
// "port_in_range" (remove of a port covered solely by a range).
func computePortChange(current string, port int, action string) (newValue string, changed bool, rejectReason string) {
	standalone, inRange := portListStatus(current, port)

	if action == "add" {
		if standalone || inRange {
			return current, false, ""
		}
		tokens := splitPortTokens(current)
		tokens = append(tokens, strconv.Itoa(port))
		return strings.Join(tokens, ","), true, ""
	}

	// remove
	//
	// A range covering the port wins regardless of a standalone token: dropping
	// "8080" from "8000:9000,8080" leaves the port open via the range, so the
	// only honest answer is to refuse. Reporting "applied" here made every
	// layer agree on the wrong answer — the panel recorded the change and the
	// customer was told a port was closed while it was still reachable.
	if inRange {
		return current, false, "port_in_range"
	}
	if !standalone {
		return current, false, ""
	}
	portStr := strconv.Itoa(port)
	tokens := splitPortTokens(current)
	out := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		if strings.TrimSpace(tok) == portStr {
			continue
		}
		out = append(out, tok)
	}
	return strings.Join(out, ","), true, ""
}

func splitPortTokens(v string) []string {
	if v == "" {
		return nil
	}
	return strings.Split(v, ",")
}

// backupCSFConf writes orig to a new, timestamped file under csfBackupDir
// (mode 0600) and prunes to the csfBackupKeep most recent backups.
func backupCSFConf(orig []byte) (string, error) {
	if err := os.MkdirAll(csfBackupDir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(csfBackupDir, fmt.Sprintf("csf.conf.%d", time.Now().UnixNano()))
	if err := os.WriteFile(path, orig, 0o600); err != nil {
		return "", err
	}
	pruneCSFBackups()
	return path, nil
}

// pruneCSFBackups removes the oldest backups beyond csfBackupKeep. Backup
// filenames are csf.conf.<UnixNano>, which sort lexically the same as
// numerically for timestamps of equal digit length (true within any single
// run of this agent).
func pruneCSFBackups() {
	entries, err := os.ReadDir(csfBackupDir)
	if err != nil {
		return
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "csf.conf.") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) <= csfBackupKeep {
		return
	}
	for _, n := range names[:len(names)-csfBackupKeep] {
		_ = os.Remove(filepath.Join(csfBackupDir, n))
	}
}

// atomicWriteCSFConf writes content to a temp file inside csfDir, copies
// origInfo's permission bits (and best-effort ownership), fsyncs, and
// renames it onto csf.conf — the rename is atomic because the temp file is
// created on the same filesystem (same directory) as the target.
func atomicWriteCSFConf(content []byte, origInfo os.FileInfo) error {
	tmp, err := os.CreateTemp(csfDir, ".csf.conf.defensia-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	success := false
	defer func() {
		if !success {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(origInfo.Mode()); err != nil {
		tmp.Close()
		return err
	}
	if st, ok := origInfo.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(tmpPath, int(st.Uid), int(st.Gid)) // best-effort
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, csfPath("csf.conf")); err != nil {
		return err
	}
	success = true
	return nil
}

// restartCSFWithRetry runs `csf -r` and, if csf reports it is already
// mid-restart ("Error: csf is being restarted, try again in a moment" —
// csf's own lock message), waits restartRetryDelay and retries exactly
// once.
func restartCSFWithRetry(ctx context.Context, bin string) ([]byte, error) {
	out, err := run(ctx, csfRestartTimeout, bin, "-r")
	if strings.Contains(string(out), "csf is being restarted") {
		time.Sleep(restartRetryDelay)
		out, err = run(ctx, csfRestartTimeout, bin, "-r")
	}
	return out, err
}

// restartErrorLineRe matches an error line in csf -r's output: "Error: ...",
// "*Error* ..." or "Oops ...", case-insensitive, at the start of a line.
var restartErrorLineRe = regexp.MustCompile(`(?im)^\s*\*?error\b|^\s*oops\b`)

// healthCheckAfterRestart evaluates every signal SafePortChange watches
// after a `csf -r`: the command's own exit code and output, the LOCALINPUT
// chain (skipped in TESTING mode, where csf's own flush cron makes its
// transient absence expected), and lfd still being alive if it was alive
// before (also skipped in TESTING mode, where lfd never starts).
func healthCheckAfterRestart(ctx context.Context, restartOut []byte, restartErr error, testingMode bool, lfdBefore *bool) (ok bool, reason string) {
	if restartErr != nil {
		if strings.Contains(restartErr.Error(), "timed out") {
			return false, "restart_timeout"
		}
		return false, "restart_failed"
	}
	if restartErrorLineRe.Match(restartOut) {
		return false, "restart_failed"
	}
	if !testingMode {
		if _, err := run(ctx, csfExecTimeout, "iptables", "-S", "LOCALINPUT"); err != nil {
			return false, "health_check_failed"
		}
	}
	if lfdBefore != nil && *lfdBefore {
		if !waitForLFDRunning(ctx) {
			return false, "lfd_not_running"
		}
	}
	return true, ""
}

// waitForLFDRunning polls lfdRunning until it reports true or
// lfdPollTimeout elapses. The poll interval scales with lfdPollTimeout so
// tests that shorten it (to keep the suite fast) still get several polls
// rather than one giant sleep.
func waitForLFDRunning(ctx context.Context) bool {
	interval := lfdPollTimeout / 10
	if interval <= 0 {
		interval = 10 * time.Millisecond
	}
	deadline := time.Now().Add(lfdPollTimeout)
	for {
		if running := lfdRunning(ctx); running != nil && *running {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(interval)
	}
}

// containsPort reports whether port appears in ports.
func containsPort(ports []int, port int) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

// SafePortChange is the single entry point for changing a CSF TCP_IN/
// TCP_OUT port, replacing the old sed -i + csf -r CSFPortAction. See the
// package doc comment above PortChangeRequest for the guarantee this makes.
func SafePortChange(ctx context.Context, req PortChangeRequest, opts PortChangeOptions) PortChangeResult {
	// 1. Validate the request shape before touching anything.
	if req.Port < 1 || req.Port > 65535 ||
		(req.Direction != "in" && req.Direction != "out") ||
		(req.Action != "add" && req.Action != "remove") {
		return PortChangeResult{Result: "rejected", Reason: "invalid_request"}
	}

	// 2. Cheap, no-exec guards, in the order a locked-out customer would
	// want them checked: is the integration even allowed to act at all.
	if CSFPaused() {
		return PortChangeResult{Result: "rejected", Reason: "integration_disabled"}
	}
	bin := csfBinaryPath()
	if bin == "" {
		return PortChangeResult{Result: "rejected", Reason: "csf_not_installed"}
	}
	if _, err := os.Stat(csfPath("csf.disable")); err == nil {
		return PortChangeResult{Result: "rejected", Reason: "csf_disabled"}
	}

	// Everything from here on touches csf.conf and/or runs `csf -r`: only
	// one SafePortChange call may be doing that at a time.
	csfWriteMu.Lock()
	defer csfWriteMu.Unlock()

	origInfo, err := os.Stat(csfPath("csf.conf"))
	if err != nil {
		return PortChangeResult{Result: "rejected", Reason: "write_failed", Err: err}
	}
	origBytes, err := os.ReadFile(csfPath("csf.conf"))
	if err != nil {
		return PortChangeResult{Result: "rejected", Reason: "write_failed", Err: err}
	}
	conf, _ := parseCSFConf(strings.NewReader(string(origBytes)))

	testingMode := conf["TESTING"] == "1"
	ipv6 := conf["IPV6"] == "1"

	primaryKey := map[string]string{"in": "TCP_IN", "out": "TCP_OUT"}[req.Direction]
	mirrorKey := map[string]string{"TCP_IN": "TCP6_IN", "TCP_OUT": "TCP6_OUT"}[primaryKey]

	// 3/4. Validate the existing value(s), then compute what would change.
	type keyChange struct {
		key     string
		newVal  string
		changed bool
	}

	if !validPortList(conf[primaryKey]) {
		return PortChangeResult{Result: "rejected", Reason: "invalid_existing_value", TestingMode: testingMode}
	}
	newVal, changed, rejectReason := computePortChange(conf[primaryKey], req.Port, req.Action)
	if rejectReason != "" {
		return PortChangeResult{Result: "rejected", Reason: rejectReason, TestingMode: testingMode}
	}
	changes := []keyChange{{primaryKey, newVal, changed}}
	anyChanged := changed

	mirrorPresent := false
	mirrorChanged := false
	if ipv6 {
		if mv, ok := conf[mirrorKey]; ok {
			mirrorPresent = true
			if !validPortList(mv) {
				return PortChangeResult{Result: "rejected", Reason: "invalid_existing_value", TestingMode: testingMode}
			}
			mNewVal, mChanged, mReject := computePortChange(mv, req.Port, req.Action)
			if mReject != "" {
				return PortChangeResult{Result: "rejected", Reason: mReject, TestingMode: testingMode}
			}
			changes = append(changes, keyChange{mirrorKey, mNewVal, mChanged})
			mirrorChanged = mChanged
			if mChanged {
				anyChanged = true
			}
		}
	}
	_ = mirrorPresent

	if !anyChanged {
		return PortChangeResult{Result: "unchanged", TestingMode: testingMode}
	}

	// 5. Guards before writing anything: never close the SSH port the
	// agent itself might be reached on, never close the panel's own route.
	if req.Action == "remove" {
		if req.Direction == "in" {
			sshPorts, _ := sshPortsFn(ctx)
			if containsPort(sshPorts, req.Port) {
				return PortChangeResult{Result: "rejected", Reason: "ssh_port_in_use", TestingMode: testingMode}
			}
		} else if req.Direction == "out" && opts.PanelPort != 0 && req.Port == opts.PanelPort {
			return PortChangeResult{Result: "rejected", Reason: "panel_port_in_use", TestingMode: testingMode}
		}
	}

	// 6. Snapshot lfd's state before we touch anything, so the health check
	// can tell "lfd died because of this restart" from "lfd was never
	// running in the first place".
	var lfdBefore *bool
	if !testingMode && conf["LF_DAEMON"] == "1" {
		lfdBefore = lfdRunning(ctx)
	}

	// 7. Backup BEFORE any write.
	backupPath, err := backupCSFConf(origBytes)
	if err != nil {
		return PortChangeResult{Result: "rejected", Reason: "backup_failed", TestingMode: testingMode, Err: err}
	}

	updates := map[string]string{}
	for _, c := range changes {
		if c.changed {
			updates[c.key] = c.newVal
		}
	}

	// 8. Go-side validated, atomic write.
	newBytes, err := rewriteConfKeys(origBytes, updates)
	if err != nil {
		return PortChangeResult{Result: "rejected", Reason: rewriteErrReason(err), Backup: backupPath, TestingMode: testingMode, Err: err}
	}
	if err := atomicWriteCSFConf(newBytes, origInfo); err != nil {
		return PortChangeResult{Result: "rejected", Reason: "write_failed", Backup: backupPath, TestingMode: testingMode, Err: err}
	}
	if csfFaultHook != nil {
		if err := csfFaultHook("after_write", csfPath("csf.conf")); err != nil {
			log.Printf("[csf] fault hook after_write: %v", err)
		}
	}

	// 9. Restart with a timeout, re-assert our own hooks (every csf -r
	// rebuilds INPUT and silently drops them, regardless of whether csf
	// itself ends up healthy), then health-check.
	restartOut, restartErr := restartCSFWithRetry(ctx, bin)
	afterCSFRestart()

	ok, failReason := healthCheckAfterRestart(ctx, restartOut, restartErr, testingMode, lfdBefore)
	if ok {
		RequestCSFRefresh()
		return PortChangeResult{
			Result:       "applied",
			Backup:       backupPath,
			IPv6Mirrored: mirrorChanged,
			TestingMode:  testingMode,
		}
	}

	// 10. Rollback: restore the ORIGINAL bytes, restart again, re-assert our
	// hooks again (that restart rebuilds INPUT too), health-check again.
	// If the rollback write itself fails, csf.conf's on-disk state is
	// unknown — stop immediately rather than restart with no idea what's
	// in the file, and NEVER run `csf -f`.
	if err := atomicWriteCSFConf(origBytes, origInfo); err != nil {
		log.Printf("[csf] CRITICAL rollback write failed; leaving csf.conf as-is and NOT flushing: %v", err)
		return PortChangeResult{
			Result:      "rollback_failed",
			Reason:      "rollback_failed",
			RolledBack:  false,
			Backup:      backupPath,
			TestingMode: testingMode,
			Err:         fmt.Errorf("original restart: %s; rollback write: %w", failReason, err),
		}
	}
	if csfFaultHook != nil {
		if err := csfFaultHook("after_rollback_write", csfPath("csf.conf")); err != nil {
			log.Printf("[csf] fault hook after_rollback_write: %v", err)
		}
	}

	rbOut, rbErr := restartCSFWithRetry(ctx, bin)
	afterCSFRestart()

	if rbOK, _ := healthCheckAfterRestart(ctx, rbOut, rbErr, testingMode, lfdBefore); rbOK {
		return PortChangeResult{
			Result:      "failed",
			Reason:      failReason,
			RolledBack:  true,
			Backup:      backupPath,
			TestingMode: testingMode,
		}
	}

	log.Printf("[csf] CRITICAL rollback failed; leaving csf.conf as restored and NOT flushing")
	var rbErrWrapped error
	if rbErr != nil {
		rbErrWrapped = fmt.Errorf("original restart: %s; rollback restart: %w", failReason, rbErr)
	} else {
		rbErrWrapped = fmt.Errorf("original restart: %s; rollback restart failed health check", failReason)
	}
	return PortChangeResult{
		Result:      "rollback_failed",
		Reason:      "rollback_failed",
		RolledBack:  false,
		Backup:      backupPath,
		TestingMode: testingMode,
		Err:         rbErrWrapped,
	}
}
