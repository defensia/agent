package firewall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSafeConfUpdateExtractionNeutral is a smoke test proving
// safeConfUpdate itself applies a simple single-key change correctly;
// the real behaviour-neutrality proof is that every pre-existing
// TestSafePort*/TestRewriteConfKeys test (run separately, unchanged)
// still passes after the extraction refactor.
func TestSafeConfUpdateExtractionNeutral(t *testing.T) {
	dir := newSafePortFixture(t)

	origBytes, err := os.ReadFile(filepath.Join(dir, "csf.conf"))
	if err != nil {
		t.Fatalf("read csf.conf: %v", err)
	}
	origInfo, _ := os.Stat(filepath.Join(dir, "csf.conf"))
	conf, _ := parseCSFConf(stringsNewReader(string(origBytes)))

	result := safeConfUpdate(context.Background(), map[string]string{"TCP_IN": "22,80,443,8080"}, origBytes, origInfo, conf, "/usr/sbin/csf")
	if result.Result != "applied" {
		t.Fatalf("safeConfUpdate result = %+v, want applied", result)
	}

	after, _ := os.ReadFile(filepath.Join(dir, "csf.conf"))
	if !strings.Contains(string(after), `TCP_IN = "22,80,443,8080"`) {
		t.Errorf("csf.conf after safeConfUpdate does not contain the new TCP_IN value:\n%s", after)
	}
}

func stringsNewReader(s string) *strings.Reader { return strings.NewReader(s) }

func newSotApplyFixture(t *testing.T) string {
	t.Helper()
	dir := newSafePortFixture(t)

	return dir
}

func TestApplySotPortsMultiKey(t *testing.T) {
	dir := newSotApplyFixture(t)

	var restarts int
	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "-r" {
			restarts++

			return []byte("ok\n"), nil
		}
		if name == "iptables" {
			return []byte("-N LOCALINPUT\n"), nil
		}

		return nil, errors.New("not stubbed: " + name)
	})

	obs, err := observeSot()
	if err != nil {
		t.Fatalf("observeSot: %v", err)
	}

	want := map[string]string{
		"TCP_IN":  "22,80,443,9999",
		"TCP_OUT": obs.Managed.Ports["TCP_OUT"],
		"TCP6_IN": "22,80,443,9999",
	}

	result := applySotPorts(context.Background(), want, obs)
	if result.Result != "applied" {
		t.Fatalf("applySotPorts = %+v, want applied", result)
	}
	if result.Backup == "" {
		t.Error("Backup not set")
	}
	if restarts != 1 {
		t.Errorf("restarts = %d, want exactly 1", restarts)
	}

	backups, _ := filepath.Glob(filepath.Join(csfBackupDir, "csf.conf.*"))
	if len(backups) != 1 {
		t.Errorf("backup files = %v, want exactly 1", backups)
	}

	after, _ := os.ReadFile(filepath.Join(dir, "csf.conf"))
	afterVals, _ := parseCSFConf(stringsNewReader(string(after)))
	if afterVals["TCP_IN"] != "22,80,443,9999" || afterVals["TCP6_IN"] != "22,80,443,9999" {
		t.Errorf("after values = %+v, want TCP_IN/TCP6_IN updated", afterVals)
	}
	if afterVals["TCP_OUT"] != obs.Managed.Ports["TCP_OUT"] {
		t.Errorf("TCP_OUT changed unexpectedly: %q -> %q", obs.Managed.Ports["TCP_OUT"], afterVals["TCP_OUT"])
	}

	fresh, err := observeSot()
	if err != nil {
		t.Fatalf("re-observe: %v", err)
	}
	if result.SelfWriteHash != sotHash(fresh.Managed) {
		t.Errorf("SelfWriteHash = %s, want %s", result.SelfWriteHash, sotHash(fresh.Managed))
	}
}

func TestApplySotPortsNoopWhenCanonEqual(t *testing.T) {
	newSotApplyFixture(t)

	var calls int
	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		calls++

		return nil, errors.New("must not be called")
	})

	obs, err := observeSot()
	if err != nil {
		t.Fatalf("observeSot: %v", err)
	}

	// Same set, different order/spacing/duplicate token.
	orig := obs.Managed.Ports["TCP_IN"]
	canon, _ := canonPorts(orig)
	reordered := " " + strings.Join(reverseTokens(strings.Split(canon, ",")), " , ") + " ," + strings.Split(canon, ",")[0]

	result := applySotPorts(context.Background(), map[string]string{"TCP_IN": reordered}, obs)
	if result.Result != "unchanged" {
		t.Fatalf("applySotPorts = %+v, want unchanged", result)
	}
	if calls != 0 {
		t.Errorf("runCmd called %d times, want 0", calls)
	}
}

func reverseTokens(ts []string) []string {
	out := make([]string, len(ts))
	for i, v := range ts {
		out[len(ts)-1-i] = v
	}

	return out
}

func TestApplySotPortsGuardRefusal(t *testing.T) {
	dir := newSotApplyFixture(t)
	withSSHPortsFn(t, func(ctx context.Context) ([]int, []string) { return []int{22}, []string{"config"} })

	confBefore, _ := os.ReadFile(filepath.Join(dir, "csf.conf"))
	hashBefore := sha256Hex(confBefore)
	stBefore, _ := os.Stat(filepath.Join(dir, "csf.conf"))
	mtimeBefore := stBefore.ModTime()

	var calls int
	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		calls++

		return nil, errors.New("must not be called")
	})

	obs, err := observeSot()
	if err != nil {
		t.Fatalf("observeSot: %v", err)
	}

	result := applySotPorts(context.Background(), map[string]string{"TCP_IN": "80,443"}, obs)
	if result.Result != "refused" || len(result.Refusals) == 0 || result.Refusals[0].Reason != "ssh_port_in_use" {
		t.Fatalf("applySotPorts = %+v, want refused/ssh_port_in_use", result)
	}

	confAfter, _ := os.ReadFile(filepath.Join(dir, "csf.conf"))
	if sha256Hex(confAfter) != hashBefore {
		t.Error("csf.conf sha256 changed despite the guard refusal")
	}
	stAfter, _ := os.Stat(filepath.Join(dir, "csf.conf"))
	if !stAfter.ModTime().Equal(mtimeBefore) {
		t.Error("csf.conf mtime changed despite the guard refusal")
	}
	if calls != 0 {
		t.Errorf("runCmd called %d times, want 0", calls)
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)

	return hex.EncodeToString(sum[:])
}

func TestApplySotPortsUnsupportedKey(t *testing.T) {
	newSotApplyFixture(t)
	appendConfLine(t, `TCP_OUT = "20,21,22"`) // genuine duplicate of TCP_OUT

	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		return nil, errors.New("must not be called for the unsupported key alone")
	})

	obs, err := observeSot()
	if err != nil {
		t.Fatalf("observeSot: %v", err)
	}
	if !hasProblem(obs.Problems, "duplicate_key", "TCP_OUT") {
		t.Fatalf("expected a duplicate_key problem for TCP_OUT, got %+v", obs.Problems)
	}

	result := applySotPorts(context.Background(), map[string]string{"TCP_OUT": "22,80"}, obs)
	if result.Result != "refused" || len(result.Refusals) == 0 || result.Refusals[0].Reason != "duplicate_key" {
		t.Fatalf("applySotPorts = %+v, want refused/duplicate_key", result)
	}
}

func TestApplySotPortsRollback(t *testing.T) {
	dir := newSotApplyFixture(t)

	var restartCalls int
	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "-r" {
			restartCalls++
			if restartCalls == 1 {
				return []byte("*Error*: restart failed\n"), errors.New("exit 1")
			}

			return []byte("ok\n"), nil // the rollback restart succeeds
		}
		if name == "iptables" {
			return []byte("-N LOCALINPUT\n"), nil
		}

		return nil, errors.New("not stubbed: " + name)
	})

	confBefore, _ := os.ReadFile(filepath.Join(dir, "csf.conf"))

	obs, err := observeSot()
	if err != nil {
		t.Fatalf("observeSot: %v", err)
	}

	result := applySotPorts(context.Background(), map[string]string{"TCP_IN": "22,80,443,9999"}, obs)
	if result.Result != "error" || result.Err == nil || result.Err.Reason != "reload_failed" || !result.RolledBack {
		t.Fatalf("applySotPorts = %+v, want error/reload_failed with RolledBack", result)
	}

	confAfter, _ := os.ReadFile(filepath.Join(dir, "csf.conf"))
	if string(confAfter) != string(confBefore) {
		t.Error("csf.conf not restored byte-identical after rollback")
	}
}

func TestApplySotPausedOrDisabled(t *testing.T) {
	t.Run("paused", func(t *testing.T) {
		dir := newSotApplyFixture(t)
		withCollectorMarkers(t)
		withCSFPaused(t, true)

		obs, err := observeSot()
		if err != nil {
			t.Fatalf("observeSot: %v", err)
		}
		result := applySotPorts(context.Background(), map[string]string{"TCP_IN": "22,80"}, obs)
		if result.Result != "skipped" {
			t.Errorf("applySotPorts (paused) = %+v, want skipped", result)
		}
		_ = dir
	})

	t.Run("disabled", func(t *testing.T) {
		dir := newSotApplyFixture(t)
		mustWriteFile(t, filepath.Join(dir, "csf.disable"), "")

		obs, err := observeSot()
		if err != nil {
			t.Fatalf("observeSot: %v", err)
		}
		result := applySotPorts(context.Background(), map[string]string{"TCP_IN": "22,80"}, obs)
		if result.Result != "refused" || len(result.Refusals) == 0 || result.Refusals[0].Reason != "csf_disabled" {
			t.Errorf("applySotPorts (disabled) = %+v, want refused/csf_disabled", result)
		}
	})
}

func withCSFPaused(t *testing.T, paused bool) {
	t.Helper()
	_ = SetCSFPaused(paused)
	t.Cleanup(func() { _ = SetCSFPaused(false) })
}

// --- applySotLists -----------------------------------------------------

func TestApplySotListsAddRemove(t *testing.T) {
	dir := newSotApplyFixture(t)
	mustWriteFile(t, filepath.Join(dir, "csf.allow"), "198.51.100.9 # defensia:sot\n")

	withSessionIPsFn(t, func(ctx context.Context, sshPorts []int) ([]netip.Addr, error) {
		return nil, nil // no live SSH sessions -> the allow removal is not blocked
	})

	var gotArgv [][]string
	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		if !strings.HasSuffix(name, "csf") {
			return nil, errors.New("unexpected binary " + name)
		}
		gotArgv = append(gotArgv, append([]string{}, args...))

		return []byte("ok\n"), nil
	})

	obs, err := observeSot()
	if err != nil {
		t.Fatalf("observeSot: %v", err)
	}

	desired := obs.Managed
	desired.Allow = []SotEntry{{Value: "203.0.113.5", Comment: "defensia:sot"}}
	desired.Deny = []SotEntry{}

	result := applySotLists(context.Background(), desired, obs, netip.Addr{})
	if result.Result != "applied" {
		t.Fatalf("applySotLists = %+v, want applied", result)
	}

	if len(gotArgv) != 2 {
		t.Fatalf("commands run = %v, want exactly 2", gotArgv)
	}
	joinArgv := func(a []string) string { return strings.Join(a, " ") }
	found := map[string]bool{}
	for _, a := range gotArgv {
		found[joinArgv(a)] = true
	}
	if !found["-a 203.0.113.5 defensia:sot"] {
		t.Errorf("missing -a 203.0.113.5 defensia:sot in %v", gotArgv)
	}
	if !found["-ar 198.51.100.9"] {
		t.Errorf("missing -ar 198.51.100.9 in %v", gotArgv)
	}
}

// TestApplySotListsRemoveSucceedsDespiteTestingModeExitCode locks in a
// real bug found live against alma8-csf-cwp-orphan (phase 16.1,
// 2026-11-19, TESTING=1): CSF's own `-a`/`-d` skip the iptables step
// entirely under TESTING mode, but `-ar`/`-dr` always attempt the
// iptables removal regardless of TESTING -- failing ("iptables: Bad
// rule...", non-zero exit) against a rule that was never inserted in
// the first place, even though the csf.allow/csf.deny FILE mutation it
// performs first already succeeded. Before this fix, applySotLists
// treated that non-zero exit as agent_error and refused every list
// removal on any fresh (TESTING=1, the default for a week after every
// new CSF install) host -- the opposite of applied.
func TestApplySotListsRemoveSucceedsDespiteTestingModeExitCode(t *testing.T) {
	dir := newSotApplyFixture(t)
	mustWriteFile(t, filepath.Join(dir, "csf.allow"), "198.51.100.9 # defensia:sot\n")

	withSessionIPsFn(t, func(ctx context.Context, sshPorts []int) ([]netip.Addr, error) {
		return nil, nil
	})

	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		if !strings.HasSuffix(name, "csf") {
			return nil, errors.New("unexpected binary " + name)
		}
		// Simulate CSF's real TESTING=1 behaviour: the file mutation
		// already happened by the time this stub runs (same ordering
		// the real csf -ar performs: rewrite the file, THEN attempt the
		// iptables removal), so mirror that here before returning the
		// error.
		if len(args) > 0 && args[0] == "-ar" {
			if err := os.WriteFile(filepath.Join(dir, "csf.allow"), []byte(""), 0o600); err != nil {
				t.Fatalf("simulate csf -ar file mutation: %v", err)
			}

			return []byte("iptables: Bad rule (does a matching rule exist in that chain?).\n"), errors.New("exit status 1")
		}

		return []byte("ok\n"), nil
	})

	obs, err := observeSot()
	if err != nil {
		t.Fatalf("observeSot: %v", err)
	}

	desired := obs.Managed
	desired.Allow = []SotEntry{}

	result := applySotLists(context.Background(), desired, obs, netip.Addr{})
	if result.Result != "applied" {
		t.Fatalf("applySotLists = %+v, want applied (the file-level removal succeeded despite csf -ar's TESTING-mode exit code)", result)
	}
	if len(result.Refusals) != 0 {
		t.Fatalf("applySotLists refusals = %v, want none", result.Refusals)
	}
}

// TestApplySotListsRemoveClearsStaleCSFError locks in a second real bug
// found live against alma8-csf-cwp-orphan alongside the one above: CSF
// latches the benign TESTING-mode -ar/-dr failure into
// /etc/csf/csf.error and refuses EVERY subsequent csf command ("You
// have an unresolved error when starting csf: ...") until that file is
// cleared, confirmed by a second list op in the same lab run failing
// with the identical stale message even though its own removal had
// already genuinely succeeded. The fix must clear csf.error once it has
// confirmed the removal it names actually took effect, so later ops in
// the same reconcile cycle are not poisoned by it.
func TestApplySotListsRemoveClearsStaleCSFError(t *testing.T) {
	dir := newSotApplyFixture(t)
	mustWriteFile(t, filepath.Join(dir, "csf.allow"), "198.51.100.9 # defensia:sot\n")
	errPath := filepath.Join(dir, "csf.error")
	mustWriteFile(t, errPath, "Error: iptables command [/sbin/iptables --wait -v -D ALLOWIN ! -i lo -s 198.51.100.9 -j ACCEPT] failed, at line 3568 in /usr/sbin/csf\n")

	withSessionIPsFn(t, func(ctx context.Context, sshPorts []int) ([]netip.Addr, error) {
		return nil, nil
	})
	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "-ar" {
			if err := os.WriteFile(filepath.Join(dir, "csf.allow"), []byte(""), 0o600); err != nil {
				t.Fatalf("simulate csf -ar file mutation: %v", err)
			}

			return []byte("iptables: Bad rule (does a matching rule exist in that chain?).\n"), errors.New("exit status 1")
		}

		return []byte("ok\n"), nil
	})

	obs, err := observeSot()
	if err != nil {
		t.Fatalf("observeSot: %v", err)
	}
	desired := obs.Managed
	desired.Allow = []SotEntry{}

	result := applySotLists(context.Background(), desired, obs, netip.Addr{})
	if result.Result != "applied" {
		t.Fatalf("applySotLists = %+v, want applied", result)
	}
	if _, err := os.Stat(errPath); !os.IsNotExist(err) {
		t.Fatalf("csf.error still present after a confirmed-successful removal, want it cleared (stat err=%v)", err)
	}
}

// TestApplySotListsRemoveLeavesUnrelatedCSFError proves the clear is
// narrowly scoped: a csf.error that does NOT mention the value just
// removed must survive, because it could be reporting something else
// entirely.
func TestApplySotListsRemoveLeavesUnrelatedCSFError(t *testing.T) {
	dir := newSotApplyFixture(t)
	mustWriteFile(t, filepath.Join(dir, "csf.allow"), "198.51.100.9 # defensia:sot\n")
	errPath := filepath.Join(dir, "csf.error")
	mustWriteFile(t, errPath, "Error: something unrelated and still unresolved\n")

	withSessionIPsFn(t, func(ctx context.Context, sshPorts []int) ([]netip.Addr, error) {
		return nil, nil
	})
	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "-ar" {
			if err := os.WriteFile(filepath.Join(dir, "csf.allow"), []byte(""), 0o600); err != nil {
				t.Fatalf("simulate csf -ar file mutation: %v", err)
			}

			return []byte("iptables: Bad rule (does a matching rule exist in that chain?).\n"), errors.New("exit status 1")
		}

		return []byte("ok\n"), nil
	})

	obs, err := observeSot()
	if err != nil {
		t.Fatalf("observeSot: %v", err)
	}
	desired := obs.Managed
	desired.Allow = []SotEntry{}

	result := applySotLists(context.Background(), desired, obs, netip.Addr{})
	if result.Result != "applied" {
		t.Fatalf("applySotLists = %+v, want applied", result)
	}
	if _, err := os.Stat(errPath); err != nil {
		t.Fatalf("unrelated csf.error was removed, want it left alone: stat err=%v", err)
	}
}

func TestApplySotListsForeignProtection(t *testing.T) {
	dir := newSotApplyFixture(t)
	// 198.51.100.9 has BOTH a tagged line (ours) and a foreign line (someone
	// else's) for the same IP: csf -ar would remove both indiscriminately.
	mustWriteFile(t, filepath.Join(dir, "csf.allow"), "198.51.100.9 # defensia:sot\n198.51.100.9 # lab-panel\n")
	mustWriteFile(t, filepath.Join(dir, "csf.deny"), "203.0.113.5 # abuse\n")

	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		return nil, errors.New("must not run any CSF command for a foreign-protected op")
	})

	obs, err := observeSot()
	if err != nil {
		t.Fatalf("observeSot: %v", err)
	}

	// (a) remove our own tagged 198.51.100.9, but a foreign line for the
	// same IP also exists -> foreign_entry_same_ip, nothing runs.
	desired := obs.Managed
	desired.Allow = []SotEntry{}
	result := applySotLists(context.Background(), desired, obs, netip.Addr{})
	if !hasRefusalReason(result.Refusals, "foreign_entry_same_ip") {
		t.Errorf("remove-foreign result = %+v, want foreign_entry_same_ip", result)
	}

	// (b) add to allow an IP that has a foreign deny line -> would_remove_foreign_deny
	desired2 := obs.Managed
	desired2.Allow = append(append([]SotEntry{}, obs.Managed.Allow...), SotEntry{Value: "203.0.113.5", Comment: "defensia:x"})
	result2 := applySotLists(context.Background(), desired2, obs, netip.Addr{})
	if !hasRefusalReason(result2.Refusals, "would_remove_foreign_deny") {
		t.Errorf("add-over-foreign-deny result = %+v, want would_remove_foreign_deny", result2)
	}
}

func hasRefusalReason(refs []SotRefusal, reason string) bool {
	for _, r := range refs {
		if r.Reason == reason {
			return true
		}
	}

	return false
}

func TestApplySotListsPerEntry(t *testing.T) {
	dir := newSotApplyFixture(t)
	mustWriteFile(t, filepath.Join(dir, "csf.deny"), "")

	// Deny-add is guarded against covering a live SSH session IP
	// (Decision 6); allow-add is not. Use deny entries so the middle one
	// is genuinely expected to be refused.
	withSessionIPsFn(t, func(ctx context.Context, sshPorts []int) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.9")}, nil
	})

	var gotArgv [][]string
	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		gotArgv = append(gotArgv, append([]string{}, args...))

		return []byte("ok\n"), nil
	})

	obs, err := observeSot()
	if err != nil {
		t.Fatalf("observeSot: %v", err)
	}

	desired := obs.Managed
	desired.Deny = []SotEntry{
		{Value: "203.0.113.5", Comment: "defensia:a"},
		{Value: "203.0.113.9", Comment: "defensia:b"}, // blocked: a live SSH session peer
		{Value: "203.0.113.11", Comment: "defensia:c"},
	}

	result := applySotLists(context.Background(), desired, obs, netip.Addr{})
	if len(result.Refusals) != 1 || result.Refusals[0].Reason != "ssh_session_ip" {
		t.Fatalf("result.Refusals = %+v, want exactly 1 ssh_session_ip refusal", result.Refusals)
	}
	if len(gotArgv) != 2 {
		t.Fatalf("commands run = %v, want 2 (the non-refused entries)", gotArgv)
	}
}
