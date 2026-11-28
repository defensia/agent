package firewall

import (
	"context"
	"errors"
	"testing"
	"time"
)

// withManagerSeams swaps the executor_ipset.go seams for in-memory fakes and
// restores the real Phase 17 functions at test cleanup.
func withManagerSeams(t *testing.T) (applyCalls *[][]BanEntry, cleanupCalls *[]struct{ active, rules map[string]bool }) {
	t.Helper()
	var apply [][]BanEntry
	var cleanup []struct{ active, rules map[string]bool }

	origApply := applyBanEntriesFn
	origCleanup := cleanupStaleBansFn
	applyBanEntriesFn = func(entries []BanEntry) int {
		apply = append(apply, entries)
		return len(entries)
	}
	cleanupStaleBansFn = func(active, rules map[string]bool) int {
		cleanup = append(cleanup, struct{ active, rules map[string]bool }{active, rules})
		return len(active)
	}
	t.Cleanup(func() {
		applyBanEntriesFn = origApply
		cleanupStaleBansFn = origCleanup
	})
	return &apply, &cleanup
}

func TestManagerDefensiaModeGolden(t *testing.T) {
	applyCalls, cleanupCalls := withManagerSeams(t)
	m := NewBanManager(ManagerOptions{StatePath: t.TempDir() + "/ban_executor.json"})

	in := SyncInput{
		Bans: []DesiredBan{
			{IP: "203.0.113.1", TTL: 2 * time.Hour},
			{IP: "203.0.113.2", TTL: 0},
			{IP: "203.0.113.3", TTL: 30 * time.Minute},
		},
		ActiveRuleIPs: map[string]bool{"203.0.113.9": true},
	}
	res := m.ApplySync(in)

	if len(*applyCalls) != 1 {
		t.Fatalf("applyBanEntriesFn called %d times, want 1", len(*applyCalls))
	}
	want := []BanEntry{{IP: "203.0.113.1", TTL: 2 * time.Hour}, {IP: "203.0.113.2", TTL: 0}, {IP: "203.0.113.3", TTL: 30 * time.Minute}}
	got := (*applyCalls)[0]
	if len(got) != len(want) {
		t.Fatalf("entries = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entries[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
	if len(*cleanupCalls) != 1 {
		t.Fatalf("cleanupStaleBansFn called %d times, want 1", len(*cleanupCalls))
	}
	call := (*cleanupCalls)[0]
	for _, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		if !call.active[ip] {
			t.Errorf("cleanup active set missing %s", ip)
		}
	}
	if !call.rules["203.0.113.9"] {
		t.Error("cleanup rules set missing 203.0.113.9")
	}
	if res.Applied != 3 || res.Cleaned != 3 {
		t.Errorf("result = %+v, want Applied 3 Cleaned 3", res)
	}

	// MonitorMode: applyBanEntriesFn NOT called, cleanupStaleBansFn still called.
	applyCalls2, cleanupCalls2 := withManagerSeams(t)
	m.ApplySync(SyncInput{Bans: in.Bans, MonitorMode: true})
	if len(*applyCalls2) != 0 {
		t.Errorf("MonitorMode: applyBanEntriesFn called %d times, want 0", len(*applyCalls2))
	}
	if len(*cleanupCalls2) != 1 {
		t.Errorf("MonitorMode: cleanupStaleBansFn called %d times, want 1", len(*cleanupCalls2))
	}
}

func TestManagerDefensiaGoldenPerBackend(t *testing.T) {
	nftVersionFn := func(c fakeCall) ([]byte, error) {
		if c.Name == "nft" && len(c.Args) > 0 && c.Args[0] == "--version" {
			return []byte("nftables v1.0.6 (Lester Gooch #5)"), nil
		}
		return []byte{}, nil
	}
	backends := []struct {
		name string
		bins []string
		fn   func(fakeCall) ([]byte, error)
	}{
		{"ipset", []string{"ipset", "iptables", "ip6tables"}, nil},
		{"nftables", []string{"nft"}, nftVersionFn},
		{"iptables", []string{"iptables"}, nil},
		{"none", nil, nil},
	}
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			f := withFakeFW(t, b.bins, b.fn)
			Reselect()
			if got := Mode(); got != b.name {
				t.Fatalf("Mode() = %q, want %q", got, b.name)
			}
			f.Clear()

			m := NewBanManager(ManagerOptions{StatePath: t.TempDir() + "/ban_executor.json"})
			in := SyncInput{Bans: []DesiredBan{{IP: "203.0.113.50", TTL: time.Hour}}}
			res := m.ApplySync(in)

			direct := ApplyBanEntries([]BanEntry{{IP: "203.0.113.50", TTL: time.Hour}})

			if b.name == "none" {
				if res.Applied != 0 {
					t.Errorf("none backend: Applied = %d, want 0", res.Applied)
				}
			} else if res.Applied != 1 {
				t.Errorf("%s backend: Applied = %d, want 1 (direct=%d)", b.name, res.Applied, direct)
			}
		})
	}
}

func TestManagerNeverEnsures(t *testing.T) {
	withManagerSeams(t)
	f := withFakeFW(t, []string{"ipset", "iptables", "ip6tables"}, nil)
	Reselect()
	genBefore := Generation()
	f.Clear()

	m := NewBanManager(ManagerOptions{StatePath: t.TempDir() + "/ban_executor.json"})
	m.ApplySync(SyncInput{Bans: []DesiredBan{{IP: "203.0.113.60"}}})

	if Generation() != genBefore {
		t.Errorf("Generation changed from %d to %d — ApplySync must never Ensure/Reselect", genBefore, Generation())
	}
	for _, c := range f.Calls() {
		if c.Name == "ipset" && len(c.Args) > 0 && c.Args[0] == "create" {
			t.Errorf("unexpected Ensure-like call recorded: %s", c.Argv())
		}
	}
}

func TestManagerDefensiaBanUnban(t *testing.T) {
	origBan := banIPFn
	origUnban := unbanIPFn
	var banned, unbanned []string
	banIPFn = func(ip string) error { banned = append(banned, ip); return nil }
	unbanIPFn = func(ip string) error { unbanned = append(unbanned, ip); return nil }
	t.Cleanup(func() { banIPFn = origBan; unbanIPFn = origUnban })

	m := NewBanManager(ManagerOptions{StatePath: t.TempDir() + "/ban_executor.json"})
	if err := m.Ban("203.0.113.70", "brute_force"); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if len(banned) != 1 || banned[0] != "203.0.113.70" {
		t.Errorf("banIPFn calls = %v, want [203.0.113.70]", banned)
	}
	if err := m.Unban("203.0.113.70"); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	if len(unbanned) != 1 || unbanned[0] != "203.0.113.70" {
		t.Errorf("unbanIPFn calls = %v, want [203.0.113.70]", unbanned)
	}

	banIPFn = func(ip string) error { return ErrNoBackend }
	if err := m.Ban("203.0.113.71", "x"); !errors.Is(err, ErrNoBackend) {
		t.Errorf("Ban error = %v, want ErrNoBackend", err)
	}
}

func TestManagerCSFBanGuardedSync(t *testing.T) {
	resetGuardStateForManagerTest(t)
	SetWhitelist([]string{"203.0.113.80"}, nil)

	// Worker never started (HasCSF false in this test env), so Ban falls back
	// to the real Defensia BanIP/BanIPFor path — which already has admitBan
	// wired in since 18-04, so the guard must still refuse the whitelisted
	// IP before it ever reaches a backend, with no double-checking needed
	// in BanManager itself for the defensia path.
	f := withFakeFW(t, []string{"ipset", "iptables", "ip6tables"}, nil)
	Reselect()
	f.Clear()

	m := NewBanManager(ManagerOptions{StatePath: t.TempDir() + "/ban_executor.json"})
	m.ApplySync(SyncInput{Executor: "csf"}) // sets lastMode=csf, csf worker nil (Start not called)
	f.Clear()

	if err := m.Ban("203.0.113.80", "x"); !errors.Is(err, ErrProtectedIP) {
		t.Errorf("Ban(whitelisted) = %v, want ErrProtectedIP", err)
	}
	if len(f.Calls()) != 0 {
		t.Errorf("no firewall command should have been issued for a protected IP, got %v", f.Calls())
	}

	if err := m.Ban("203.0.113.81", "x"); err != nil {
		t.Errorf("Ban(normal) = %v, want nil", err)
	}
	if len(f.Calls()) == 0 {
		t.Error("expected a firewall command for the non-protected IP")
	}
}

func resetGuardStateForManagerTest(t *testing.T) {
	t.Helper()
	guardMu.Lock()
	guardWhitelist = nil
	guardMu.Unlock()
	t.Cleanup(func() { SetWhitelist(nil, nil) })
}

func TestManagerStatusNilWithoutCSF(t *testing.T) {
	prev := guardHasCSF
	guardHasCSF = func() bool { return false }
	t.Cleanup(func() { guardHasCSF = prev })

	m := NewBanManager(ManagerOptions{StatePath: t.TempDir() + "/ban_executor.json"})
	if s := m.Status(); s != nil {
		t.Errorf("Status() = %+v, want nil", s)
	}
}

func TestManagerUnknownExecutorIsDefensia(t *testing.T) {
	withManagerSeams(t)
	m := NewBanManager(ManagerOptions{StatePath: t.TempDir() + "/ban_executor.json"})
	res := m.ApplySync(SyncInput{Executor: "iptables", Bans: []DesiredBan{{IP: "203.0.113.90"}}})
	if res.Applied != 1 {
		t.Errorf("unknown executor should fall back to defensia path, Applied = %d", res.Applied)
	}
}

func TestManagerStartIsIdempotent(t *testing.T) {
	prev := guardHasCSF
	guardHasCSF = func() bool { return false }
	t.Cleanup(func() { guardHasCSF = prev })

	m := NewBanManager(ManagerOptions{StatePath: t.TempDir() + "/ban_executor.json"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)
	m.Start(ctx) // must not panic or double-start
}

func TestStartupUsesPersistedMode(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/ban_executor.json"
	if err := saveBanState(path, banState{Mode: "csf"}); err != nil {
		t.Fatal(err)
	}

	m := NewBanManager(ManagerOptions{StatePath: path})
	// Before any ApplySync call, the manager's effective mode must already
	// reflect the persisted state — Ban()'s dispatch (csfMode := m.lastMode
	// == "csf") relies on this being right immediately after construction,
	// not only after the first sync.
	if m.lastMode != "csf" {
		t.Errorf("lastMode = %q, want csf (from persisted state)", m.lastMode)
	}

	// With a real worker up (fake CSF binary, no real exec), Ban() goes to
	// the CSF executor, not banIPFn.
	origBan := banIPFn
	var fallbackCalled bool
	banIPFn = func(ip string) error { fallbackCalled = true; return nil }
	t.Cleanup(func() { banIPFn = origBan })

	execFakeEnv(t)
	withExecRun(t, func(args []string) (string, int) { return "", 0 })

	prevHasCSF := guardHasCSF
	guardHasCSF = func() bool { return true }
	t.Cleanup(func() { guardHasCSF = prevHasCSF })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)

	if err := m.Ban("203.0.113.95", "x"); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if fallbackCalled {
		t.Error("banIPFn (defensia path) should not have been used; persisted mode is csf")
	}
}

func TestStartupEmergencyPersistedDefensia(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/ban_executor.json"
	if err := saveBanState(path, banState{Mode: "defensia"}); err != nil {
		t.Fatal(err)
	}

	origBan := banIPFn
	var banned []string
	banIPFn = func(ip string) error { banned = append(banned, ip); return nil }
	t.Cleanup(func() { banIPFn = origBan })

	calls := withExecRun(t, func(args []string) (string, int) { return "", 0 })

	m := NewBanManager(ManagerOptions{StatePath: path})
	if err := m.Ban("203.0.113.96", "x"); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if len(banned) != 1 || banned[0] != "203.0.113.96" {
		t.Errorf("banIPFn calls = %v, want [203.0.113.96]", banned)
	}
	if len(*calls) != 0 {
		t.Errorf("expected zero csf runner calls, got %v", *calls)
	}
}
