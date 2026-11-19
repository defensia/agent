//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/defensia/agent/internal/firewall"
)

// TestLabSOTObserveReadOnly proves SOT-02's activation promise against a
// real VM: observing the managed scope three times in a row leaves
// csf.conf, csf.allow and csf.deny byte- and mtime-identical, runs zero
// commands, reports no precheck problems, and TCP_IN's canonical form
// already covers every port sshd is actually listening on. Non-CSF VMs:
// not applicable, PASS.
func TestLabSOTObserveReadOnly(t *testing.T) {
	requireRoot(t)
	if requireEnv(t, "LAB_EXPECT_CSF") != "1" {
		return
	}
	ctx := context.Background()

	shaBefore := map[string]string{}
	mtimeBefore := map[string]time.Time{}
	for _, name := range []string{"csf.conf", "csf.allow", "csf.deny"} {
		path := "/etc/csf/" + name
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		sum := sha256.Sum256(data)
		shaBefore[name] = hex.EncodeToString(sum[:])
		mtimeBefore[name] = confMtime(t, path)
	}

	count, _ := countCommands(t)

	var managed firewall.SotManaged
	var problems []firewall.SotProblem
	for i := 0; i < 3; i++ {
		m, _, p, err := firewall.SotObserve()
		if err != nil {
			t.Fatalf("SotObserve (call %d): %v", i, err)
		}
		managed, problems = m, p
	}

	if len(problems) != 0 {
		t.Fatalf("SotObserve problems = %v, want none", problems)
	}
	if got := count(); got != 0 {
		t.Fatalf("SotObserve ran %d commands, want 0", got)
	}

	for _, name := range []string{"csf.conf", "csf.allow", "csf.deny"} {
		path := "/etc/csf/" + name
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != shaBefore[name] {
			t.Fatalf("%s sha256 changed: before=%s after=%s", path, shaBefore[name], got)
		}
		got := confMtime(t, path)
		want := mtimeBefore[name]
		if !got.Equal(want) {
			t.Fatalf("%s mtime changed: before=%v after=%v", path, want, got)
		}
	}

	tcpIn, ok := managed.Ports["TCP_IN"]
	if !ok {
		t.Fatalf("observed scope has no TCP_IN key")
	}
	canon := firewall.SotCanon(tcpIn)
	for _, port := range firewall.SotActiveSSHPorts(ctx) {
		if !canonCoversPort(canon, port) {
			t.Fatalf("TCP_IN canon %q does not cover active SSH port %d", canon, port)
		}
	}
}

// TestLabSOTSaveconfReplay proves a CSF-UI-style saveconf rewrite (every
// line renormalised, nothing else touched) produces zero drift and the
// identical CONTRACT §8 hash, against a real on-disk rewrite rather than
// a mocked one. Non-CSF VMs: not applicable, PASS.
func TestLabSOTSaveconfReplay(t *testing.T) {
	requireRoot(t)
	if requireEnv(t, "LAB_EXPECT_CSF") != "1" {
		return
	}
	snapshotConf(t)

	beforeManaged, beforeHash, _, err := firewall.SotObserve()
	if err != nil {
		t.Fatalf("SotObserve before: %v", err)
	}

	if out, err := sh(t, "bash", "/root/lab-sot/ui-saveconf.sh"); err != nil {
		t.Fatalf("ui-saveconf.sh: %v (%s)", err, out)
	}

	afterManaged, afterHash, _, err := firewall.SotObserve()
	if err != nil {
		t.Fatalf("SotObserve after: %v", err)
	}

	if !firewall.SotSaveconfNoDrift(beforeManaged, afterManaged) {
		t.Fatalf("SotSaveconfNoDrift = false after a plain saveconf replay, want true")
	}
	if afterHash != beforeHash {
		t.Fatalf("hash changed after a plain saveconf replay: before=%s after=%s", beforeHash, afterHash)
	}
}

// TestLabSOTApplyPortsMultiKey proves applySotPorts' guarded multi-key
// write against a real csf.conf: exactly one backup, exactly one `csf
// -r`, only the requested lines change, LOCALINPUT survives, and
// applying the original values back round-trips csf.conf to
// byte-identical. Non-CSF VMs: not applicable, PASS.
func TestLabSOTApplyPortsMultiKey(t *testing.T) {
	requireRoot(t)
	if requireEnv(t, "LAB_EXPECT_CSF") != "1" {
		return
	}
	snapshotConf(t)
	ctx := context.Background()
	_, calls := countCommands(t)

	preSHA := confSHA(t)
	preBytes, err := os.ReadFile(csfConfPath)
	if err != nil {
		t.Fatalf("read %s: %v", csfConfPath, err)
	}

	before, _, _, err := firewall.SotObserve()
	if err != nil {
		t.Fatalf("SotObserve: %v", err)
	}
	origTCPIn := before.Ports["TCP_IN"]
	origTCPOut := before.Ports["TCP_OUT"]

	namesBefore := map[string]bool{}
	if entries, err := os.ReadDir(csfBackupsDir); err == nil {
		for _, e := range entries {
			namesBefore[e.Name()] = true
		}
	}

	want := map[string]string{
		"TCP_IN":  origTCPIn + ",48311",
		"TCP_OUT": origTCPOut + ",48312",
	}
	result, reason, backup := firewall.SotApplyPorts(ctx, want)
	if result != "applied" {
		t.Fatalf("apply TCP_IN+=48311,TCP_OUT+=48312 = %q (%s), want applied", result, reason)
	}
	if backup == "" {
		t.Fatalf("SotApplyPorts applied but returned no backup path")
	}

	// backupCSFConf (internal/firewall/csf_ports.go) prunes to the 5
	// most recent backups, so the directory's total entry COUNT does
	// not reliably go up by one once the cap is already reached --
	// count the entries that are NEW (by name) instead, which is exactly
	// one regardless of whether pruning also fired this time.
	entriesAfter, err := os.ReadDir(csfBackupsDir)
	if err != nil {
		t.Fatalf("read %s: %v", csfBackupsDir, err)
	}
	newCount := 0
	for _, e := range entriesAfter {
		if !namesBefore[e.Name()] {
			newCount++
		}
	}
	if newCount != 1 {
		t.Fatalf("csf-backups has %d new entries, want exactly 1 (before=%d after=%d)", newCount, len(namesBefore), len(entriesAfter))
	}

	afterBytes, err := os.ReadFile(csfConfPath)
	if err != nil {
		t.Fatalf("read %s: %v", csfConfPath, err)
	}
	diffOnlyKeys(t, preBytes, afterBytes, "TCP_IN", "TCP_OUT")

	rCount := 0
	for _, call := range calls() {
		for _, arg := range call {
			if arg == "-r" {
				rCount++
			}
		}
	}
	if rCount != 1 {
		t.Fatalf("observed %d `-r` invocations, want exactly 1: %v", rCount, calls())
	}
	assertNoForbidden(t, calls())

	if !chainPresent(t) {
		t.Fatalf("LOCALINPUT chain missing after the multi-key apply")
	}

	result2, reason2, _ := firewall.SotApplyPorts(ctx, map[string]string{"TCP_IN": origTCPIn, "TCP_OUT": origTCPOut})
	if result2 != "applied" {
		t.Fatalf("restore apply = %q (%s), want applied", result2, reason2)
	}

	if got := confSHA(t); got != preSHA {
		t.Fatalf("csf.conf sha = %s after apply+restore round-trip, want original %s", got, preSHA)
	}
}

// TestLabSOTGuardSSHPort proves guardPorts refuses a TCP_IN value that
// would drop every active SSH port, leaving csf.conf completely
// untouched and never running `csf -r`. Non-CSF VMs: not applicable,
// PASS.
func TestLabSOTGuardSSHPort(t *testing.T) {
	requireRoot(t)
	if requireEnv(t, "LAB_EXPECT_CSF") != "1" {
		return
	}
	snapshotConf(t)
	ctx := context.Background()
	_, calls := countCommands(t)

	preSHA := confSHA(t)
	preMtime := confMtime(t, csfConfPath)

	// A single high port far outside any active SSH port's range -- the
	// agent's own sshPortsFn detection (not a hardcoded 22 assumption)
	// decides what counts as "active" here.
	result, reason, _ := firewall.SotApplyPorts(ctx, map[string]string{"TCP_IN": "48399"})
	if result != "refused" || reason != "ssh_port_in_use" {
		t.Fatalf("apply TCP_IN=48399 (drops every ssh port) = %q (%s), want refused/ssh_port_in_use", result, reason)
	}

	if got := confSHA(t); got != preSHA {
		t.Fatalf("csf.conf sha changed after a refused apply: before=%s after=%s", preSHA, got)
	}
	if got := confMtime(t, csfConfPath); !got.Equal(preMtime) {
		t.Fatalf("csf.conf mtime changed after a refused apply: before=%v after=%v", preMtime, got)
	}
	for _, call := range calls() {
		for _, arg := range call {
			if arg == "-r" {
				t.Fatalf("csf -r observed for a refused apply: %v", call)
			}
		}
	}
}

// TestLabSOTGuardSessionIP proves guardAllowRemoval refuses removing a
// tagged allow entry that covers a real, currently-ESTABLISHED SSH
// session opened from lab-attacker (LAB_SOT_SSH_PEER_IP, opened by
// lab/test.sh via lab/sot/ssh-session.sh), and that the session survives
// the refused attempt. Non-CSF VMs: not applicable, PASS.
func TestLabSOTGuardSessionIP(t *testing.T) {
	requireRoot(t)
	if requireEnv(t, "LAB_EXPECT_CSF") != "1" {
		return
	}
	peer := requireEnv(t, "LAB_SOT_SSH_PEER_IP")
	ctx := context.Background()

	// Registered before backupFile's own cleanup so it runs AFTER the
	// bytes are restored (t.Cleanup is LIFO: last registered runs
	// first) -- csf.allow must be back to its original bytes before
	// `csf -r` reloads from it.
	t.Cleanup(func() { sh(t, "csf", "-r") })
	backupFile(t, csfAllowPath)

	sshPorts := firewall.SotActiveSSHPorts(ctx)
	sessions, err := firewall.SotSessionIPs(ctx, sshPorts)
	if err != nil {
		t.Fatalf("SotSessionIPs: %v", err)
	}
	if !containsStr(sessions, peer) {
		t.Fatalf("SotSessionIPs = %v, want it to contain the lab SSH peer %s", sessions, peer)
	}

	before, _, _, err := firewall.SotObserve()
	if err != nil {
		t.Fatalf("SotObserve before: %v", err)
	}

	value := peer + "/32"
	desiredAdd := before
	desiredAdd.Allow = append(append([]firewall.SotEntry{}, before.Allow...), firewall.SotEntry{Value: value, Comment: "defensia:lab"})

	result, refusals := firewall.SotApplyLists(ctx, desiredAdd)
	if result != "applied" {
		t.Fatalf("add tagged allow %s = %q %v, want applied", value, result, refusals)
	}
	if n := countLinesContaining(t, csfAllowPath, peer); n != 1 {
		t.Fatalf("csf.allow contains %d lines for %s after add, want 1", n, peer)
	}
	if n := countLinesContaining(t, csfAllowPath, "defensia:"); n == 0 {
		t.Fatalf("csf.allow has no defensia: tagged line after add")
	}

	afterAdd, _, _, err := firewall.SotObserve()
	if err != nil {
		t.Fatalf("SotObserve after add: %v", err)
	}

	var kept []firewall.SotEntry
	for _, e := range afterAdd.Allow {
		if e.Value != value {
			kept = append(kept, e)
		}
	}
	desiredRemove := afterAdd
	desiredRemove.Allow = kept

	result2, refusals2 := firewall.SotApplyLists(ctx, desiredRemove)
	if result2 != "refused" || !containsStr(refusals2, "ssh_session_ip") {
		t.Fatalf("remove tagged allow %s (covers a live session) = %q %v, want refused/ssh_session_ip", value, result2, refusals2)
	}
	if n := countLinesContaining(t, csfAllowPath, peer); n != 1 {
		t.Fatalf("csf.allow contains %d lines for %s after a refused removal, want 1 (entry must survive)", n, peer)
	}

	sessionsAfter, err := firewall.SotSessionIPs(ctx, sshPorts)
	if err != nil {
		t.Fatalf("SotSessionIPs after refused removal: %v", err)
	}
	if !containsStr(sessionsAfter, peer) {
		t.Fatalf("SSH session from %s no longer established after a refused removal: %v", peer, sessionsAfter)
	}
}

// TestLabSOTListOps proves applySotLists' guarded tagged add/remove
// round-trips cleanly through the real CSF CLI, and that foreign (un-
// tagged) entries on both lists are never touched: a same-IP tagged add
// over a foreign allow line is refused foreign_entry_same_ip, and an
// allow-add over a foreign deny line is refused would_remove_foreign_deny
// -- in both cases the foreign line survives untouched. Non-CSF VMs: not
// applicable, PASS.
func TestLabSOTListOps(t *testing.T) {
	requireRoot(t)
	if requireEnv(t, "LAB_EXPECT_CSF") != "1" {
		return
	}
	ctx := context.Background()

	t.Cleanup(func() { sh(t, "csf", "-r") })
	backupFile(t, csfAllowPath)
	backupFile(t, csfDenyPath)
	_, calls := countCommands(t)

	const allowIP = "203.0.113.41"
	const denyIP = "198.51.100.41"

	before, _, _, err := firewall.SotObserve()
	if err != nil {
		t.Fatalf("SotObserve: %v", err)
	}

	desiredAdd := before
	desiredAdd.Allow = append(append([]firewall.SotEntry{}, before.Allow...), firewall.SotEntry{Value: allowIP, Comment: "defensia:lab"})
	desiredAdd.Deny = append(append([]firewall.SotEntry{}, before.Deny...), firewall.SotEntry{Value: denyIP, Comment: "defensia:lab"})

	result, refusals := firewall.SotApplyLists(ctx, desiredAdd)
	if result != "applied" {
		t.Fatalf("add tagged allow/deny = %q %v, want applied", result, refusals)
	}
	if n := countLinesContaining(t, csfAllowPath, "defensia:"); n == 0 {
		t.Fatalf("csf.allow has no defensia: tagged line after add")
	}
	if n := countLinesContaining(t, csfDenyPath, "defensia:"); n == 0 {
		t.Fatalf("csf.deny has no defensia: tagged line after add")
	}

	afterAdd, _, _, err := firewall.SotObserve()
	if err != nil {
		t.Fatalf("SotObserve after add: %v", err)
	}

	var keptAllow, keptDeny []firewall.SotEntry
	for _, e := range afterAdd.Allow {
		if e.Value != allowIP {
			keptAllow = append(keptAllow, e)
		}
	}
	for _, e := range afterAdd.Deny {
		if e.Value != denyIP {
			keptDeny = append(keptDeny, e)
		}
	}
	desiredRemove := afterAdd
	desiredRemove.Allow = keptAllow
	desiredRemove.Deny = keptDeny

	result2, refusals2 := firewall.SotApplyLists(ctx, desiredRemove)
	if result2 != "applied" {
		t.Fatalf("remove tagged allow/deny = %q %v, want applied", result2, refusals2)
	}
	if n := countLinesContaining(t, csfAllowPath, allowIP); n != 0 {
		t.Fatalf("csf.allow still contains %s after remove, want 0", allowIP)
	}
	if n := countLinesContaining(t, csfDenyPath, denyIP); n != 0 {
		t.Fatalf("csf.deny still contains %s after remove, want 0", denyIP)
	}

	flags := flagCounts(calls(), "csf")
	for _, want := range []string{"-a", "-ar", "-d", "-dr"} {
		if flags[want] == 0 {
			t.Fatalf("observed calls = %v, want at least one %q", calls(), want)
		}
	}
	for flag := range flags {
		switch flag {
		case "-a", "-ar", "-d", "-dr":
		default:
			t.Fatalf("unexpected csf flag observed during list ops: %q (calls=%v)", flag, calls())
		}
	}
	assertNoForbidden(t, calls())

	// Foreign-ownership protection: a same-IP tagged add over a foreign
	// allow line must be refused, and the foreign line must survive.
	const foreignAllowIP = "203.0.113.42"
	appendRawLine(t, csfAllowPath, foreignAllowIP+" # lab-foreign")

	obsForeignAllow, _, _, err := firewall.SotObserve()
	if err != nil {
		t.Fatalf("SotObserve (foreign allow case): %v", err)
	}
	desiredForeignAllow := obsForeignAllow
	desiredForeignAllow.Allow = append(append([]firewall.SotEntry{}, obsForeignAllow.Allow...), firewall.SotEntry{Value: foreignAllowIP, Comment: "defensia:lab"})

	result3, refusals3 := firewall.SotApplyLists(ctx, desiredForeignAllow)
	if result3 != "refused" || !containsStr(refusals3, "foreign_entry_same_ip") {
		t.Fatalf("tagged add over a foreign allow entry = %q %v, want refused/foreign_entry_same_ip", result3, refusals3)
	}
	if n := countLinesContaining(t, csfAllowPath, foreignAllowIP); n != 1 {
		t.Fatalf("csf.allow contains %d lines for foreign %s, want 1 (untouched)", n, foreignAllowIP)
	}

	// Foreign-ownership protection: an allow-add for an IP the foreign
	// deny list already covers must be refused would_remove_foreign_deny,
	// and csf.deny's foreign line must survive.
	const foreignDenyIP = "203.0.113.43"
	appendRawLine(t, csfDenyPath, foreignDenyIP+" # lab-foreign")

	obsForeignDeny, _, _, err := firewall.SotObserve()
	if err != nil {
		t.Fatalf("SotObserve (foreign deny case): %v", err)
	}
	desiredForeignDeny := obsForeignDeny
	desiredForeignDeny.Allow = append(append([]firewall.SotEntry{}, obsForeignDeny.Allow...), firewall.SotEntry{Value: foreignDenyIP, Comment: "defensia:lab"})

	result4, refusals4 := firewall.SotApplyLists(ctx, desiredForeignDeny)
	if result4 != "refused" || !containsStr(refusals4, "would_remove_foreign_deny") {
		t.Fatalf("allow-add over a foreign deny entry = %q %v, want refused/would_remove_foreign_deny", result4, refusals4)
	}
	if n := countLinesContaining(t, csfDenyPath, foreignDenyIP); n != 1 {
		t.Fatalf("csf.deny contains %d lines for foreign %s, want 1 (untouched)", n, foreignDenyIP)
	}
}

// TestLabSOTNoForbiddenCommands runs a compact, self-contained sequence
// covering both applySotPorts and applySotLists (a guarded port apply +
// restore, then a tagged list add + remove) and asserts that across every
// command either one ever executes, none of them ever carries a
// forbidden CSF flag -- the same real-VM proof csf_ports_test.go already
// gives SafePortChange, extended to the source-of-truth primitives.
// Non-CSF VMs: not applicable, PASS.
func TestLabSOTNoForbiddenCommands(t *testing.T) {
	requireRoot(t)
	if requireEnv(t, "LAB_EXPECT_CSF") != "1" {
		return
	}
	snapshotConf(t)
	t.Cleanup(func() { sh(t, "csf", "-r") })
	backupFile(t, csfAllowPath)

	ctx := context.Background()
	_, calls := countCommands(t)

	before, _, _, err := firewall.SotObserve()
	if err != nil {
		t.Fatalf("SotObserve: %v", err)
	}
	origTCPIn := before.Ports["TCP_IN"]

	result, reason, _ := firewall.SotApplyPorts(ctx, map[string]string{"TCP_IN": origTCPIn + ",48322"})
	if result != "applied" {
		t.Fatalf("apply TCP_IN+=48322 = %q (%s), want applied", result, reason)
	}
	result2, reason2, _ := firewall.SotApplyPorts(ctx, map[string]string{"TCP_IN": origTCPIn})
	if result2 != "applied" {
		t.Fatalf("restore TCP_IN = %q (%s), want applied", result2, reason2)
	}

	const ip = "203.0.113.44"
	afterPorts, _, _, err := firewall.SotObserve()
	if err != nil {
		t.Fatalf("SotObserve: %v", err)
	}
	desiredAdd := afterPorts
	desiredAdd.Allow = append(append([]firewall.SotEntry{}, afterPorts.Allow...), firewall.SotEntry{Value: ip, Comment: "defensia:lab"})
	if result3, refusals3 := firewall.SotApplyLists(ctx, desiredAdd); result3 != "applied" {
		t.Fatalf("add tagged allow %s = %q %v, want applied", ip, result3, refusals3)
	}

	afterAdd, _, _, err := firewall.SotObserve()
	if err != nil {
		t.Fatalf("SotObserve: %v", err)
	}
	var kept []firewall.SotEntry
	for _, e := range afterAdd.Allow {
		if e.Value != ip {
			kept = append(kept, e)
		}
	}
	desiredRemove := afterAdd
	desiredRemove.Allow = kept
	if result4, refusals4 := firewall.SotApplyLists(ctx, desiredRemove); result4 != "applied" {
		t.Fatalf("remove tagged allow %s = %q %v, want applied", ip, result4, refusals4)
	}

	assertNoForbidden(t, calls())
}
