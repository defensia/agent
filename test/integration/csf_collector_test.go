//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/defensia/agent/internal/firewall"
)

// TestLabCSFCollectorFork asserts firewall.CollectCSF's evidence-based fork
// detection against the REAL fork installed in this VM — never the
// installer id (lab/matrix.sh's vm_fork), which is a different axis: the
// detector must never read `csf -v`'s own panel-name suffix as evidence
// (see internal/firewall/csf_fork.go's forkEnv doc comment), only the
// evidence this VM's real CSF install genuinely exposes. On a non-CSF VM
// this is not applicable and returns — a PASS, never a SKIP.
func TestLabCSFCollectorFork(t *testing.T) {
	requireRoot(t)
	if requireEnv(t, "LAB_EXPECT_CSF") != "1" {
		return
	}

	s := firewall.CollectCSF(context.Background())
	if s == nil {
		t.Fatalf("firewall.CollectCSF() = nil, want a snapshot (LAB_EXPECT_CSF=1)")
	}

	wantFork := requireEnv(t, "LAB_EXPECT_CSF_FORK")
	if s.Fork != wantFork {
		t.Fatalf("CollectCSF().Fork = %q, want %q (evidence: %v)", s.Fork, wantFork, s.ForkEvidence)
	}

	wantVersion := requireEnv(t, "LAB_EXPECT_CSF_VERSION")
	if s.Version != wantVersion {
		t.Fatalf("CollectCSF().Version = %q, want %q", s.Version, wantVersion)
	}

	if len(s.ForkEvidence) < 1 {
		t.Fatalf("CollectCSF().ForkEvidence is empty, want >= 1 entry")
	}
	t.Logf("fork=%s version=%s evidence=%v", s.Fork, s.Version, s.ForkEvidence)
}

// TestLabCSFCollectorState asserts the real TESTING/lfd/downloadservers
// facts CollectCSF reports against this VM's real csf.conf and real lfd
// process — the exact thing 15-05-SUMMARY.md flagged as "apply/rollback
// algorithm untested on real VMs" for the sibling collector path.
func TestLabCSFCollectorState(t *testing.T) {
	requireRoot(t)
	if requireEnv(t, "LAB_EXPECT_CSF") != "1" {
		return
	}

	s := firewall.CollectCSF(context.Background())
	if s == nil {
		t.Fatalf("firewall.CollectCSF() = nil, want a snapshot")
	}

	wantTesting := requireEnv(t, "LAB_EXPECT_TESTING") == "1"
	if s.Testing == nil {
		t.Fatalf("CollectCSF().Testing = nil, want non-nil (%v)", wantTesting)
	}
	if *s.Testing != wantTesting {
		t.Fatalf("CollectCSF().Testing = %v, want %v", *s.Testing, wantTesting)
	}

	wantLFDRunning := requireEnv(t, "LAB_EXPECT_LFD") == "active"
	if s.LFDRunning == nil {
		t.Fatalf("CollectCSF().LFDRunning = nil, want non-nil (%v)", wantLFDRunning)
	}
	if *s.LFDRunning != wantLFDRunning {
		t.Fatalf("CollectCSF().LFDRunning = %v, want %v", *s.LFDRunning, wantLFDRunning)
	}

	if s.LFDaemon == nil {
		t.Fatalf("CollectCSF().LFDaemon = nil, want non-nil")
	}

	if s.DenyIPLimit == nil {
		t.Fatalf("CollectCSF().DenyIPLimit = nil, want non-nil")
	}

	wantDL := requireEnv(t, "LAB_EXPECT_DL_CONFIGSERVER") == "1"
	gotDL := false
	for _, d := range s.DownloadServers {
		if strings.Contains(d, "configserver.com") {
			gotDL = true
			break
		}
	}
	if gotDL != wantDL {
		t.Fatalf("DownloadServers contains an active configserver.com line = %v, want %v (servers: %v)", gotDL, wantDL, s.DownloadServers)
	}
}

// TestLabCSFCollectorBounded proves the two timing guarantees
// 15-02-SUMMARY.md claims against stubs actually hold against a real csf
// binary: a single CollectCSF pass completes well inside the lab's own
// per-VM budget, and once a background collector is running,
// CurrentCSFSnapshot() is a true atomic-load (sub-50ms) even while that
// collector is mid-pass.
func TestLabCSFCollectorBounded(t *testing.T) {
	requireRoot(t)
	if requireEnv(t, "LAB_EXPECT_CSF") != "1" {
		return
	}

	start := time.Now()
	s := firewall.CollectCSF(context.Background())
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("CollectCSF() took %s, want < 20s", elapsed)
	}
	if s == nil {
		t.Fatalf("CollectCSF() = nil")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	firewall.StartCSFCollector(ctx, 5*time.Minute)

	deadline := time.Now().Add(5 * time.Second)
	for firewall.CurrentCSFSnapshot() == nil && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if firewall.CurrentCSFSnapshot() == nil {
		t.Fatalf("CurrentCSFSnapshot() still nil 5s after StartCSFCollector")
	}

	for i := 0; i < 50; i++ {
		callStart := time.Now()
		_ = firewall.CurrentCSFSnapshot()
		if d := time.Since(callStart); d > 50*time.Millisecond {
			t.Fatalf("CurrentCSFSnapshot() call %d took %s, want < 50ms", i, d)
		}
	}
}

// TestLabCSFListsCap proves readCSFLists' cap/hash contract (15-02) against
// a real, large csf.deny on disk: 1000-entry cap, correct uncapped Total,
// Truncated, both "advanced" and "include" kinds surviving the cap (by
// being placed first), and a hash that actually changes. backupFile
// restores csf.deny's original bytes afterward — this test only ever
// READS through CSF's own list files, it never runs csf -r.
func TestLabCSFListsCap(t *testing.T) {
	requireRoot(t)
	if requireEnv(t, "LAB_EXPECT_CSF") != "1" {
		return
	}

	const denyPath = "/etc/csf/csf.deny"
	const includePath = "/etc/csf/lab-include.deny"

	orig := backupFile(t, denyPath)

	var beforeHash string
	if before := firewall.CollectCSF(context.Background()); before != nil {
		beforeHash = before.ListsHash
	}

	if err := os.WriteFile(includePath, []byte("# lab integration test include file\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", includePath, err)
	}
	t.Cleanup(func() {
		if err := os.Remove(includePath); err != nil && !os.IsNotExist(err) {
			t.Errorf("cleanup: remove %s: %v", includePath, err)
		}
	})

	// The two special lines go FIRST so they land inside the 1000-entry cap
	// readCSFList applies — TEST-NET-2 (198.51.100.0/24) for the advanced
	// line, documentation-only ranges for the 5000-line bulk fill
	// (198.18.0.0/15 is IANA-reserved for benchmarking, never a real host).
	var b strings.Builder
	b.WriteString("tcp|in|d=22|s=198.51.100.7 # lab-adv\n")
	b.WriteString("Include /etc/csf/lab-include.deny\n")
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(&b, "198.18.%d.%d # lab-bulk\n", i/250, i%250+1)
	}
	b.Write(orig)

	if err := os.WriteFile(denyPath, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write %s: %v", denyPath, err)
	}

	after := firewall.CollectCSF(context.Background())
	if after == nil {
		t.Fatalf("CollectCSF() = nil after appending to csf.deny")
	}
	if after.Deny.Total < 5002 {
		t.Fatalf("Deny.Total = %d, want >= 5002", after.Deny.Total)
	}
	if len(after.Deny.Entries) != 1000 {
		t.Fatalf("len(Deny.Entries) = %d, want 1000", len(after.Deny.Entries))
	}
	if !after.Deny.Truncated {
		t.Fatalf("Deny.Truncated = false, want true")
	}

	kinds := map[string]bool{}
	for _, e := range after.Deny.Entries {
		kinds[e.Kind] = true
	}
	if !kinds["advanced"] {
		t.Fatalf("no 'advanced'-kind entry survived the 1000-entry cap (kinds seen: %v)", kinds)
	}
	if !kinds["include"] {
		t.Fatalf("no 'include'-kind entry survived the 1000-entry cap (kinds seen: %v)", kinds)
	}

	if after.ListsHash == beforeHash {
		t.Fatalf("ListsHash unchanged after appending 5000+ deny entries (before=%s after=%s)", beforeHash, after.ListsHash)
	}
}

// TestLabNoCSFNoExec proves COL-06 against a real absent-CSF VM
// (debian12-nocsf): CollectCSF must run ZERO commands and leave no seen
// marker. On a CSF VM this is not applicable (there IS something to
// collect) and the test only proves CollectCSF actually returns something
// — both branches PASS, never SKIP.
func TestLabNoCSFNoExec(t *testing.T) {
	requireRoot(t)
	if requireEnv(t, "LAB_EXPECT_CSF") != "1" {
		count, _ := countCommands(t)
		s := firewall.CollectCSF(context.Background())
		if s != nil {
			t.Fatalf("CollectCSF() = %+v on a no-CSF VM, want nil", s)
		}
		if n := count(); n != 0 {
			t.Fatalf("CollectCSF() ran %d commands on a no-CSF VM, want 0", n)
		}
		if _, err := os.Stat("/etc/defensia/csf-seen"); err == nil {
			t.Fatalf("/etc/defensia/csf-seen exists on a no-CSF VM, want absent")
		}
		return
	}

	s := firewall.CollectCSF(context.Background())
	if s == nil {
		t.Fatalf("CollectCSF() = nil on a CSF VM, want a snapshot")
	}
}

// TestLabCSFPauseStopsExec proves the kill switch against a real CSF
// install: paused -> CollectCSF and SafePortChange both run zero commands
// and the marker file is written/kept; resumed -> both work again. The
// running defensia-agent systemd service only reads this marker at
// startup (15-11-SUMMARY.md), so this test's own SetCSFPaused calls never
// actually pause that separate process — only this test binary's own
// in-process state, which is exactly what it exercises.
func TestLabCSFPauseStopsExec(t *testing.T) {
	requireRoot(t)
	if requireEnv(t, "LAB_EXPECT_CSF") != "1" {
		return
	}

	t.Cleanup(func() {
		if err := firewall.SetCSFPaused(false); err != nil {
			t.Errorf("cleanup: SetCSFPaused(false): %v", err)
		}
		_ = os.Remove("/etc/defensia/csf-paused")
	})

	if err := firewall.SetCSFPaused(true); err != nil {
		t.Fatalf("SetCSFPaused(true): %v", err)
	}
	if _, err := os.Stat("/etc/defensia/csf-paused"); err != nil {
		t.Fatalf("stat /etc/defensia/csf-paused: %v, want present after pause", err)
	}

	count, _ := countCommands(t)

	if s := firewall.CollectCSF(context.Background()); s != nil {
		t.Fatalf("CollectCSF() = %+v while paused, want nil", s)
	}
	if n := count(); n != 0 {
		t.Fatalf("CollectCSF() ran %d commands while paused, want 0", n)
	}

	res := firewall.SafePortChange(context.Background(), firewall.PortChangeRequest{
		Port: 48212, Direction: "in", Action: "add",
	}, firewall.PortChangeOptions{})
	if res.Result != "rejected" || res.Reason != "integration_disabled" {
		t.Fatalf("SafePortChange while paused = %+v, want rejected/integration_disabled", res)
	}
	if n := count(); n != 0 {
		t.Fatalf("SafePortChange ran %d commands while paused, want 0", n)
	}

	if _, err := os.Stat("/etc/defensia/csf-paused"); err != nil {
		t.Fatalf("stat /etc/defensia/csf-paused: %v, want still present", err)
	}

	if err := firewall.SetCSFPaused(false); err != nil {
		t.Fatalf("SetCSFPaused(false): %v", err)
	}
	if s := firewall.CollectCSF(context.Background()); s == nil {
		t.Fatalf("CollectCSF() = nil after resume, want a snapshot")
	}
	if n := count(); n == 0 {
		t.Fatalf("no commands ran after resume, want > 0")
	}
}
