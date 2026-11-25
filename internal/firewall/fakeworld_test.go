package firewall

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeWorld is the shared test harness for executor switching (this plan)
// and the breaker/undo tests (plan 08): a real csf.tempban file backed by a
// Go fake csf runner (so readTempBans()/planCSFPass/migrateToDefensia all
// exercise their real parsing/classification code), a Defensia "backend"
// (banMembersFn/banIPForFn/unbanIPFn) backed by a plain map, and an ordered
// log of every operation either side issued.
type fakeWorld struct {
	t       *testing.T
	confDir string
	varDir  string

	mu             sync.Mutex
	entries        map[string]tempEntry // ip -> entry; Ours/foreign both live here
	backendMembers map[string]bool
	extraForeign   map[string]bool
	opsLog         []string

	// banIPForErr/unbanErr let a test force a specific error for a specific
	// IP (or "*" for every IP) from the Defensia-backend fakes.
	banIPForErr map[string]error
	unbanErr    map[string]error

	clock time.Time
}

type tempEntry struct {
	ttl     time.Duration
	comment string
	ours    bool
}

// newFakeWorld installs every seam this plan's and plan 08's tests need and
// restores them all at t.Cleanup. The clock starts at time.Now() and is
// exposed via w.now/w.advance for deterministic TTL/eviction tests.
func newFakeWorld(t *testing.T) *fakeWorld {
	t.Helper()
	w := &fakeWorld{
		t: t, entries: map[string]tempEntry{}, backendMembers: map[string]bool{},
		banIPForErr: map[string]error{}, unbanErr: map[string]error{},
		clock: time.Now(),
	}

	w.confDir = t.TempDir()
	w.varDir = t.TempDir()
	oldConfDir, oldVarDir := csfDir, csfVarDir
	csfDir, csfVarDir = w.confDir, w.varDir
	t.Cleanup(func() { csfDir, csfVarDir = oldConfDir, oldVarDir })

	w.writeConf(map[string]string{"LF_DAEMON": "1"})
	w.flush()

	origRun := csfRun
	csfRun = w.csfRunFake
	t.Cleanup(func() { csfRun = origRun })

	origMembers, origBanIPFor, origUnban := banMembersFn, banIPForFn, unbanIPFn
	banMembersFn = w.membersFake
	banIPForFn = w.banIPForFake
	unbanIPFn = w.unbanFake
	t.Cleanup(func() { banMembersFn, banIPForFn, unbanIPFn = origMembers, origBanIPFor, origUnban })

	return w
}

func (w *fakeWorld) now() time.Time { return w.clock }

func (w *fakeWorld) writeConf(kv map[string]string) {
	w.t.Helper()
	var sb strings.Builder
	for k, v := range kv {
		sb.WriteString(k + ` = "` + v + "\"\n")
	}
	if err := os.WriteFile(filepath.Join(w.confDir, "csf.conf"), []byte(sb.String()), 0o644); err != nil {
		w.t.Fatal(err)
	}
}

// seedTemp replaces the whole tempban file content with the given entries
// (ip -> {ttl, comment, ours}) and flushes it to disk.
func (w *fakeWorld) seedTemp(entries map[string]tempEntry) {
	w.mu.Lock()
	w.entries = entries
	w.mu.Unlock()
	w.flush()
}

func (w *fakeWorld) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()

	var lines []string
	for ip, e := range w.entries {
		lines = append(lines, fmt.Sprintf("%d|%s|*|inout|%d|%s", w.clock.Unix(), ip, int(e.ttl/time.Second), e.comment))
	}
	// extraForeign: a synthetic, permanent foreign (non-"ours") row for an
	// IP that also has/had an "ours" entry — used to reproduce the real
	// "an IP with both an Ours and a foreign entry" conflict case, which a
	// single-entry-per-IP map otherwise can't represent.
	for ip := range w.extraForeign {
		lines = append(lines, fmt.Sprintf("%d|%s|*|inout|%d|lfd", w.clock.Unix(), ip, int(time.Hour/time.Second)))
	}
	content := strings.Join(lines, "\n")
	if len(lines) > 0 {
		content += "\n"
	}
	if err := os.WriteFile(filepath.Join(w.varDir, "csf.tempban"), []byte(content), 0o644); err != nil {
		w.t.Fatal(err)
	}
}

// setExtraForeign marks (or unmarks) ip as always having a co-existing
// foreign entry, re-flushing immediately.
func (w *fakeWorld) setExtraForeign(ip string, has bool) {
	w.mu.Lock()
	if w.extraForeign == nil {
		w.extraForeign = map[string]bool{}
	}
	if has {
		w.extraForeign[ip] = true
	} else {
		delete(w.extraForeign, ip)
	}
	w.mu.Unlock()
	w.flush()
}

func (w *fakeWorld) record(op string) {
	w.mu.Lock()
	w.opsLog = append(w.opsLog, op)
	w.mu.Unlock()
}

// --- CSF side (csfRun fake: -td/-tr/-v/-t) ---------------------------------

func (w *fakeWorld) csfRunFake(ctx context.Context, bin string, args ...string) ([]byte, int, error) {
	if len(args) == 0 {
		return nil, 0, nil
	}

	switch args[0] {
	case "-td":
		ip, ttlStr, comment := args[1], args[2], args[3]
		ttlSec, _ := strconv.Atoi(ttlStr)

		w.mu.Lock()
		_, already := w.entries[ip]
		if already {
			w.mu.Unlock()
			w.record("td-already:" + ip)
			return []byte("csf: " + ip + " already temporarily blocked\n"), 0, nil
		}
		w.entries[ip] = tempEntry{ttl: time.Duration(ttlSec) * time.Second, comment: comment, ours: strings.HasPrefix(comment, "defensia:")}
		w.mu.Unlock()
		w.flush()
		w.record("td:" + ip)
		return []byte("csf: " + ip + " blocked on port * for " + ttlStr + " seconds inbound\n"), 0, nil

	case "-tr":
		ip := args[1]
		w.mu.Lock()
		_, ok := w.entries[ip]
		if !ok {
			w.mu.Unlock()
			w.record("tr-notfound:" + ip)
			return []byte("csf: " + ip + " not found in temporary bans\n"), 0, nil
		}
		delete(w.entries, ip)
		w.mu.Unlock()
		w.flush()
		w.record("tr:" + ip)
		return []byte("csf: temporary block removed\n"), 0, nil

	case "-v":
		return []byte("csf: v15.00 (generic)\n"), 0, nil

	case "-t":
		return []byte("csf: no temporary IP bans set\n"), 0, nil
	}

	return nil, 0, nil
}

// --- Defensia backend side (banMembersFn/banIPForFn/unbanIPFn) ------------

func (w *fakeWorld) membersFake() map[string]bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make(map[string]bool, len(w.backendMembers))
	for ip, v := range w.backendMembers {
		out[ip] = v
	}
	return out
}

func (w *fakeWorld) banIPForFake(ip string, ttl time.Duration) error {
	w.mu.Lock()
	err := w.banIPForErr[ip]
	if err == nil {
		err = w.banIPForErr["*"]
	}
	w.mu.Unlock()

	w.record(fmt.Sprintf("banipfor:%s:%s", ip, ttl))
	if err != nil {
		return err
	}

	w.mu.Lock()
	w.backendMembers[ip] = true
	w.mu.Unlock()
	return nil
}

func (w *fakeWorld) unbanFake(ip string) error {
	w.mu.Lock()
	err := w.unbanErr[ip]
	if err == nil {
		err = w.unbanErr["*"]
	}
	w.mu.Unlock()

	w.record("unban:" + ip)
	if err != nil {
		return err
	}

	w.mu.Lock()
	delete(w.backendMembers, ip)
	w.mu.Unlock()
	return nil
}

// --- Introspection for tests -----------------------------------------------

func (w *fakeWorld) tagged() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []string
	for ip, e := range w.entries {
		if e.ours {
			out = append(out, ip)
		}
	}
	return out
}

func (w *fakeWorld) foreign() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []string
	for ip, e := range w.entries {
		if !e.ours {
			out = append(out, ip)
		}
	}
	return out
}

func (w *fakeWorld) members() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]string, 0, len(w.backendMembers))
	for ip := range w.backendMembers {
		out = append(out, ip)
	}
	return out
}

func (w *fakeWorld) ops() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]string, len(w.opsLog))
	copy(out, w.opsLog)
	return out
}

func (w *fakeWorld) isTagged(ip string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	e, ok := w.entries[ip]
	return ok && e.ours
}

func (w *fakeWorld) isMember(ip string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.backendMembers[ip]
}

// assertNoGap fails the test if any desired IP is protected by neither the
// Defensia backend nor a tagged CSF temp ban — the one invariant every
// switch direction must hold at every point in time.
func (w *fakeWorld) assertNoGap(desired []DesiredBan) {
	w.t.Helper()
	for _, d := range desired {
		if !w.isMember(d.IP) && !w.isTagged(d.IP) {
			w.t.Errorf("gap: %s is protected by neither the Defensia backend nor a tagged CSF entry", d.IP)
		}
	}
}

func TestFakeWorldInvariants(t *testing.T) {
	w := newFakeWorld(t)
	w.seedTemp(map[string]tempEntry{
		"203.0.113.1": {ttl: time.Hour, comment: "defensia:r", ours: true},
		"203.0.113.2": {ttl: time.Hour, comment: "lfd", ours: false},
	})

	if got := w.tagged(); len(got) != 1 || got[0] != "203.0.113.1" {
		t.Errorf("tagged() = %v, want [203.0.113.1]", got)
	}
	if got := w.foreign(); len(got) != 1 || got[0] != "203.0.113.2" {
		t.Errorf("foreign() = %v, want [203.0.113.2]", got)
	}

	if err := w.banIPForFake("203.0.113.3", time.Hour); err != nil {
		t.Fatalf("banIPForFake: %v", err)
	}
	if !w.isMember("203.0.113.3") {
		t.Error("203.0.113.3 should be a member after banIPForFake")
	}
	if err := w.unbanFake("203.0.113.3"); err != nil {
		t.Fatalf("unbanFake: %v", err)
	}
	if w.isMember("203.0.113.3") {
		t.Error("203.0.113.3 should not be a member after unbanFake")
	}

	ctx := context.Background()
	if _, _, err := csfRun(ctx, "csf", "-td", "203.0.113.4", "3600", "defensia:x"); err != nil {
		t.Fatalf("csfRunFake -td: %v", err)
	}
	if !w.isTagged("203.0.113.4") {
		t.Error("203.0.113.4 should be tagged after -td")
	}
	if _, _, err := csfRun(ctx, "csf", "-tr", "203.0.113.4"); err != nil {
		t.Fatalf("csfRunFake -tr: %v", err)
	}
	if w.isTagged("203.0.113.4") {
		t.Error("203.0.113.4 should not be tagged after -tr")
	}

	ops := w.ops()
	if len(ops) == 0 {
		t.Error("ops() should have recorded the operations above")
	}

	w.backendMembers["203.0.113.1"] = true
	w.assertNoGap([]DesiredBan{{IP: "203.0.113.1"}}) // member OR tagged -> no failure
}
