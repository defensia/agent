//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defensia/agent/internal/firewall"
)

// csfWritable reports whether this VM both has CSF installed AND is not in
// TESTING mode (TESTING=1 VMs, e.g. alma8-csf-cwp-orphan, deliberately
// never accept real -td/-tr writes — every ban-sync functional test treats
// that case as its own "unavailable" assertion, not a writable CSF VM).
func csfWritable() bool {
	return isCSFVM() && env("LAB_EXPECT_TESTING") == "0"
}

// stopAgent stops the real defensia-agent systemd service for the duration
// of a test that drives its own in-process firewall.BanManager instead —
// the two must never write csf.tempban/the Defensia backend concurrently.
// Cleanup restarts it via the existing restartAgent helper (lab_fw_daemon_test.go).
//
// "Unit ... not loaded" is not a failure here: it means the unit was never
// registered in this environment at all (the lab/ci/run-csf-container.sh CI
// container only installs CSF itself, never the agent's own systemd unit —
// unlike every OrbStack lab VM, which lab/provision/agent.sh always
// registers) — nothing is running, so there is nothing to stop, and the
// concurrency concern this function exists for is moot. Lab-measured, phase
// 18-12: every TestLabBanSync*/TestLabBanChaos* test hard-failed CI here
// the first time this exact test package ever ran in that container.
func stopAgent(t *testing.T) {
	t.Helper()
	if out, err := sh(t, "systemctl", "stop", "defensia-agent"); err != nil && !strings.Contains(out, "not loaded") {
		t.Fatalf("systemctl stop defensia-agent: %v (%s)", err, out)
	}
	t.Cleanup(func() { restartAgent(t) })
}

// banIPCounter guarantees every IP banIPs hands out is unique for the
// lifetime of this test binary process, seeded from the start time so a
// re-run in the same lab session never collides with a prior run's
// leftover state either.
var banIPCounter atomic.Uint64

func init() {
	banIPCounter.Store(uint64(time.Now().UnixNano()) % 50000)
}

// banIPs returns n unique IPs built from LAB_BAN_PREFIX: a prefix ending in
// 3 dotted segments (e.g. "11.22.0.") gets one more octet appended; a
// prefix ending in 2 (e.g. "11.22.") gets two more octets — matching
// whatever lab/ban-sync.env currently configures.
func banIPs(t *testing.T, n int) []string {
	t.Helper()
	prefix := requireEnv(t, "LAB_BAN_PREFIX")

	segments := strings.Count(prefix, ".")
	remaining := 4 - segments
	if remaining != 1 && remaining != 2 {
		t.Fatalf("banIPs: LAB_BAN_PREFIX %q needs 1 or 2 remaining octets, got %d", prefix, remaining)
	}

	ips := make([]string, 0, n)
	for i := 0; i < n; i++ {
		v := banIPCounter.Add(1)
		var suffix string
		if remaining == 1 {
			suffix = strconv.Itoa(1 + int(v%254))
		} else {
			o3 := 1 + int((v/254)%254)
			o4 := 1 + int(v%254)
			suffix = strconv.Itoa(o3) + "." + strconv.Itoa(o4)
		}
		ips = append(ips, prefix+suffix)
	}
	return ips
}

// tempLine is one parsed csf.tempban row.
type tempLine struct {
	IP      string
	Comment string
}

// readTempban parses /var/lib/csf/csf.tempban directly, under a shared
// flock so a concurrent CSF/lfd rewrite is never observed as torn.
func readTempban(t *testing.T) []tempLine {
	t.Helper()
	const path = "/var/lib/csf/csf.tempban"
	out, err := sh(t, "flock", "-s", path, "-c", "cat "+path)
	if err != nil {
		t.Fatalf("read %s: %v (%s)", path, err, out)
	}

	var lines []tempLine
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		fields := strings.SplitN(l, "|", 6)
		if len(fields) != 6 {
			continue
		}
		lines = append(lines, tempLine{IP: fields[1], Comment: fields[5]})
	}
	return lines
}

// taggedSet/foreignSet split readTempban's result by the "defensia:" tag.
func taggedSet(lines []tempLine) map[string]bool {
	out := map[string]bool{}
	for _, l := range lines {
		if strings.HasPrefix(l.Comment, "defensia:") {
			out[l.IP] = true
		}
	}
	return out
}

func foreignSet(lines []tempLine) map[string]bool {
	out := map[string]bool{}
	for _, l := range lines {
		if !strings.HasPrefix(l.Comment, "defensia:") {
			out[l.IP] = true
		}
	}
	return out
}

// backendMembers reads the Defensia backend's own ban members (ipset,
// nftables or iptables — whichever firewall.Init() selected), via the
// read-only firewall.DefensiaBanMembers() accessor. Never shells out to a
// backend-specific tool directly, so this works identically on
// alma10-noipset (nftables) and every other VM (ipset).
func backendMembers(t *testing.T) map[string]bool {
	t.Helper()
	firewall.Init()
	t.Logf("backendMembers: firewall.Mode() = %s", firewall.Mode())

	v4, v6, err := firewall.DefensiaBanMembers()
	if err != nil {
		t.Fatalf("DefensiaBanMembers: %v", err)
	}
	out := make(map[string]bool, len(v4)+len(v6))
	for _, ip := range v4 {
		out[ip] = true
	}
	for _, ip := range v6 {
		out[ip] = true
	}
	return out
}

// denyinHas reports whether iptables' DENYIN chain currently has a rule
// for ip (works whether DENYIN is fed by ipset, nftables or iptables
// directly — CSF always surfaces its temp bans there).
func denyinHas(t *testing.T, ip string) bool {
	t.Helper()
	out, _ := sh(t, "iptables", "-S", "DENYIN")
	return strings.Contains(out, "-s "+ip+"/32")
}

// csfActiveSince returns CSF's own ActiveEnterTimestampMonotonic — used to
// assert a csf restart did NOT happen (the timestamp is unchanged) across
// a sequence of -td/-tr calls that must never trigger one.
func csfActiveSince(t *testing.T) string {
	t.Helper()
	out, err := sh(t, "systemctl", "show", "csf", "-p", "ActiveEnterTimestampMonotonic", "--value")
	if err != nil {
		t.Fatalf("systemctl show csf: %v", err)
	}
	return out
}

var confKeyRe = regexp.MustCompile(`^([A-Z0-9_]+)\s*=`)

// withCSFConf sets key=value in /etc/csf/csf.conf, runs `csf -r` and
// restarts lfd so it takes effect, reusing csf_helpers_test.go's
// snapshotConf for the backup/restore/health-check half of the contract
// (never duplicating that cleanup logic here).
func withCSFConf(t *testing.T, key, value string) {
	t.Helper()
	snapshotConf(t)

	data, err := os.ReadFile(csfConfPath)
	if err != nil {
		t.Fatalf("read csf.conf: %v", err)
	}

	lines := strings.Split(string(data), "\n")
	found := false
	for i, l := range lines {
		m := confKeyRe.FindStringSubmatch(l)
		if m != nil && m[1] == key {
			lines[i] = fmt.Sprintf(`%s = "%s"`, key, value)
			found = true
		}
	}
	if !found {
		lines = append(lines, fmt.Sprintf(`%s = "%s"`, key, value))
	}

	if err := os.WriteFile(csfConfPath, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatalf("write csf.conf: %v", err)
	}
	if out, err := sh(t, "csf", "-r"); err != nil {
		t.Fatalf("csf -r (withCSFConf %s=%s): %v (%s)", key, value, err, out)
	}

	// csf -r already restarts lfd as part of its own normal operation, but
	// some conf values (e.g. DENY_TEMP_IP_LIMIT) lfd caches at its own
	// startup and does not reliably pick up from that alone — hence the
	// extra, explicit restart below, best-effort only (never t.Fatalf):
	// CSF's lfd has a real, documented refusal mode — "lfd will not run
	// with TESTING enabled in /etc/csf/csf.conf" — it logs that and exits
	// immediately, which is the CORRECT state for TESTING=1 (our own
	// environmentReady() checks conf.Testing before ever caring whether
	// lfd is running at all). Lab-measured, alma9-csf-orig, phase 18-10:
	// a withCSFConf(t, "TESTING", "1") caller that treated this restart as
	// fatal failed the whole test over an lfd exit the test itself wants.
	if out, err := sh(t, "systemctl", "restart", "lfd"); err != nil {
		t.Logf("systemctl restart lfd (withCSFConf %s=%s): %v (%s) — non-fatal, lfd may legitimately refuse to run for this conf value", key, value, err, out)
	}
}

// seedForeign adds ttl-second temp bans with the given (non-"defensia:")
// comment via a real `csf -td`, so tests can assert the executor never
// touches entries it does not own. Cleanup removes them.
func seedForeign(t *testing.T, ips []string, ttl time.Duration, comment string) {
	t.Helper()
	for _, ip := range ips {
		if out, err := sh(t, "csf", "-td", ip, strconv.Itoa(int(ttl.Seconds())), comment); err != nil {
			t.Fatalf("csf -td %s (seedForeign): %v (%s)", ip, err, out)
		}
	}
	t.Cleanup(func() {
		for _, ip := range ips {
			sh(t, "csf", "-tr", ip)
		}
	})
}

// cleanupTagged registers a t.Cleanup that removes every remaining
// "defensia:" csf.tempban entry via `csf -tr` and fails the test if any
// are still present afterwards — every ban-sync test's final safety net,
// independent of whatever the test itself already cleaned up.
func cleanupTagged(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		for ip := range taggedSet(readTempban(t)) {
			sh(t, "csf", "-tr", ip)
		}
		if left := taggedSet(readTempban(t)); len(left) > 0 {
			t.Errorf("cleanupTagged: %d defensia: entries still present: %v", len(left), left)
		}
	})
}

// managerEvents collects every ExecutorEvent a test's BanManager emits,
// mutex-guarded since Emit is always called from the worker goroutine.
type managerEvents struct {
	mu     sync.Mutex
	events []firewall.ExecutorEvent
}

func (e *managerEvents) emit(ev firewall.ExecutorEvent) {
	e.mu.Lock()
	e.events = append(e.events, ev)
	e.mu.Unlock()
}

func (e *managerEvents) all() []firewall.ExecutorEvent {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]firewall.ExecutorEvent, len(e.events))
	copy(out, e.events)
	return out
}

func (e *managerEvents) hasType(t string) bool {
	for _, ev := range e.all() {
		if ev.Type == t {
			return true
		}
	}
	return false
}

// newManager builds a real firewall.BanManager against the real backend
// and (if DEFENSIA_CSF_BIN is set by the caller first) the real or fake
// csf binary, started on a cancellable context cleaned up automatically.
func newManager(t *testing.T, statePath string, mods ...func(*firewall.ManagerOptions)) (*firewall.BanManager, *managerEvents) {
	t.Helper()
	firewall.Init()

	ev := &managerEvents{}
	opts := firewall.ManagerOptions{StatePath: statePath, Emit: ev.emit}
	for _, mod := range mods {
		mod(&opts)
	}

	mgr := firewall.NewBanManager(opts)
	ctx, cancel := context.WithCancel(context.Background())
	mgr.Start(ctx)
	t.Cleanup(cancel)

	return mgr, ev
}

// newManagerStoppable is newManager plus the context's own cancel func,
// for the rare case where a manager must stop BEFORE the enclosing test
// returns — e.g. a parent test that spawns a subtest sharing the same real
// CSF host: a manager's worker goroutine otherwise keeps running (its own
// t.Cleanup only fires once the WHOLE test, including every subtest,
// returns) and its 60s ticker can wake it mid-subtest, tagging every
// "defensia:"-tagged entry it doesn't recognise (including the subtest's
// own, freshly added by a DIFFERENT manager instance) for removal — lab-
// measured, alma9-csf-orig, phase 18-10: a forgotten parent manager wiped
// out a sibling subtest's burst entries in large batches via real -tr
// calls, well before the subtest's own convergence could ever complete.
// cancel is safe to call again at the registered t.Cleanup (a context's
// CancelFunc is idempotent).
func newManagerStoppable(t *testing.T, statePath string, mods ...func(*firewall.ManagerOptions)) (*firewall.BanManager, *managerEvents, context.CancelFunc) {
	t.Helper()
	firewall.Init()

	ev := &managerEvents{}
	opts := firewall.ManagerOptions{StatePath: statePath, Emit: ev.emit}
	for _, mod := range mods {
		mod(&opts)
	}

	mgr := firewall.NewBanManager(opts)
	ctx, cancel := context.WithCancel(context.Background())
	mgr.Start(ctx)
	t.Cleanup(cancel)

	return mgr, ev, cancel
}

// argvLog points DEFENSIA_CSF_BIN at the fake csf binary in passthrough
// mode (every call logged, then forwarded to the real csf binary
// unchanged) so tests can assert exactly which flags were issued without
// losing CSF's real behaviour. t.Setenv restores every var automatically.
func argvLog(t *testing.T) (path string, read func() []string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "csf-argv.log")
	t.Setenv("DEFENSIA_CSF_BIN", "/root/fakecsf/csf")
	t.Setenv("FAKECSF_MODE", "passthrough")
	t.Setenv("FAKECSF_REAL", "/usr/sbin/csf")
	t.Setenv("FAKECSF_LOG", path)

	read = func() []string {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var lines []string
		for _, l := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
			if l != "" {
				lines = append(lines, l)
			}
		}
		return lines
	}
	return path, read
}
