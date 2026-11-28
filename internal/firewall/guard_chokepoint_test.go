package firewall

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func alwaysOK(c fakeCall) ([]byte, error) { return []byte{}, nil }

// forceBackend configures the fake FW + env var so current() resolves to
// name ("ipset", "nftables" or "iptables") the next time it is called, and
// resets package ban-selection + guard state so each subtest starts clean.
func forceBackend(t *testing.T, name string) *fakeFW {
	t.Helper()
	resetBackendState()
	resetGuardState(t)

	var bins []string
	var fn func(c fakeCall) ([]byte, error)
	switch name {
	case "ipset":
		bins = []string{"ipset", "iptables", "ip6tables"}
		fn = alwaysOK
	case "nftables":
		bins = []string{"nft"}
		fn = nftVersionOKFn(nil)
	case "iptables":
		bins = []string{"iptables", "ip6tables"}
		fn = alwaysOK
	default:
		t.Fatalf("unknown backend %q", name)
	}

	f := withFakeFW(t, bins, fn)
	t.Setenv("DEFENSIA_FIREWALL_BACKEND", name)
	t.Cleanup(resetBackendState)

	return f
}

func callsContain(calls []fakeCall, needle string) bool {
	for _, c := range calls {
		if strings.Contains(c.Argv(), needle) || strings.Contains(c.Stdin, needle) {
			return true
		}
	}

	return false
}

func TestGuardBanIP(t *testing.T) {
	for _, backend := range []string{"ipset", "nftables", "iptables"} {
		t.Run(backend, func(t *testing.T) {
			f := forceBackend(t, backend)
			SetWhitelist([]string{"203.0.113.5"}, nil)

			err := BanIP("203.0.113.5")
			if !errors.Is(err, ErrProtectedIP) {
				t.Fatalf("err = %v, want ErrProtectedIP", err)
			}
			if !strings.Contains(err.Error(), "protected IP (whitelist)") {
				t.Errorf("err message = %q, want it to mention protected IP (whitelist)", err.Error())
			}
			if callsContain(f.Calls(), "203.0.113.5") {
				t.Errorf("a call recorded the protected IP: %v", argvList(f.Calls()))
			}

			if err := BanIP("203.0.113.6"); err != nil {
				t.Fatalf("BanIP of a non-protected IP: %v", err)
			}
			if !callsContain(f.Calls(), "203.0.113.6") {
				t.Errorf("non-protected IP never reached the backend: %v", argvList(f.Calls()))
			}
		})
	}
}

func TestGuardBanIPFor(t *testing.T) {
	for _, backend := range []string{"ipset", "nftables", "iptables"} {
		t.Run(backend, func(t *testing.T) {
			dir := t.TempDir()
			oldCsfDir := csfDir
			csfDir = dir
			t.Cleanup(func() { csfDir = oldCsfDir })

			f := forceBackend(t, backend)
			guardHasCSF = func() bool { return true }
			writeCSFList(t, dir, "csf.allow", []string{"198.51.100.1"})
			writeCSFList(t, dir, "csf.ignore", nil)

			err := BanIPFor("198.51.100.1", time.Hour)
			if !errors.Is(err, ErrProtectedIP) {
				t.Fatalf("err = %v, want ErrProtectedIP", err)
			}
			if !strings.Contains(err.Error(), "csf_allow") {
				t.Errorf("err = %q, want reason csf_allow", err.Error())
			}
			if callsContain(f.Calls(), "198.51.100.1") {
				t.Errorf("a call recorded the csf.allow IP: %v", argvList(f.Calls()))
			}
			if backend == "nftables" {
				for _, c := range f.Calls() {
					if c.Name == "nft" && strings.Contains(c.Stdin, "198.51.100.1") {
						t.Fatalf("nft received the protected IP (priority -10 lockout case): %q", c.Stdin)
					}
				}
			}
		})
	}
}

func TestGuardApplyBans(t *testing.T) {
	for _, backend := range []string{"ipset", "nftables", "iptables"} {
		t.Run(backend, func(t *testing.T) {
			dir := t.TempDir()
			oldCsfDir := csfDir
			csfDir = dir
			t.Cleanup(func() { csfDir = oldCsfDir })

			f := forceBackend(t, backend)
			guardHasCSF = func() bool { return true }
			writeCSFList(t, dir, "csf.allow", []string{"198.51.100.1"})
			writeCSFList(t, dir, "csf.ignore", nil)
			SetWhitelist([]string{"203.0.113.5"}, nil)

			n := ApplyBans([]string{"203.0.113.5", "203.0.113.6", "198.51.100.1"})
			if n != 1 {
				t.Fatalf("ApplyBans returned %d, want 1", n)
			}
			if callsContain(f.Calls(), "203.0.113.5") || callsContain(f.Calls(), "198.51.100.1") {
				t.Errorf("a protected IP reached the backend: %v", argvList(f.Calls()))
			}
			if !callsContain(f.Calls(), "203.0.113.6") {
				t.Errorf("the non-protected IP never reached the backend: %v", argvList(f.Calls()))
			}
		})
	}
}

func TestGuardApplyBanEntries(t *testing.T) {
	for _, backend := range []string{"ipset", "nftables", "iptables"} {
		t.Run(backend, func(t *testing.T) {
			dir := t.TempDir()
			oldCsfDir := csfDir
			csfDir = dir
			t.Cleanup(func() { csfDir = oldCsfDir })

			f := forceBackend(t, backend)
			guardHasCSF = func() bool { return true }
			writeCSFList(t, dir, "csf.allow", []string{"198.51.100.1"})
			writeCSFList(t, dir, "csf.ignore", nil)
			SetWhitelist([]string{"203.0.113.5"}, nil)

			n := ApplyBanEntries([]BanEntry{
				{IP: "203.0.113.5", TTL: time.Hour},
				{IP: "203.0.113.6", TTL: time.Hour},
				{IP: "198.51.100.1", TTL: 0},
			})
			if n != 1 {
				t.Fatalf("ApplyBanEntries returned %d, want 1", n)
			}
			if callsContain(f.Calls(), "203.0.113.5") || callsContain(f.Calls(), "198.51.100.1") {
				t.Errorf("a protected IP reached the backend: %v", argvList(f.Calls()))
			}
			if !callsContain(f.Calls(), "203.0.113.6") {
				t.Errorf("the non-protected IP never reached the backend: %v", argvList(f.Calls()))
			}
			if backend == "nftables" && !callsContain(f.Calls(), "timeout 3600s") {
				t.Errorf("TTL not carried through on nftables: %v", argvList(f.Calls()))
			}
		})
	}
}

func TestGuardNoneBackend(t *testing.T) {
	resetBackendState()
	resetGuardState(t)
	t.Setenv("DEFENSIA_FIREWALL_BACKEND", "none")
	t.Cleanup(resetBackendState)

	SetWhitelist([]string{"203.0.113.5"}, nil)

	before := NotAppliedBans()
	err := BanIP("203.0.113.5")
	if !errors.Is(err, ErrProtectedIP) {
		t.Fatalf("err = %v, want ErrProtectedIP (not ErrNoBackend)", err)
	}
	if NotAppliedBans() != before {
		t.Errorf("NotAppliedBans changed for a protected IP on none backend: %d -> %d", before, NotAppliedBans())
	}

	err2 := BanIP("203.0.113.6")
	if !errors.Is(err2, ErrNoBackend) {
		t.Fatalf("err = %v, want ErrNoBackend for a normal IP with no backend", err2)
	}
	if NotAppliedBans() != before+1 {
		t.Errorf("NotAppliedBans = %d, want %d", NotAppliedBans(), before+1)
	}
}

func TestGuardSafeIPFirst(t *testing.T) {
	forceBackend(t, "ipset")

	err := BanIP("127.0.0.1")
	if err == nil || !strings.Contains(err.Error(), "refusing to ban safe IP") {
		t.Fatalf("err = %v, want Phase 17's safe-IP refusal (isSafeIP runs before the guard)", err)
	}
	if errors.Is(err, ErrProtectedIP) {
		t.Error("safe-IP refusal should not be ErrProtectedIP — that's Phase 17's own pre-existing error")
	}
}

func TestSkipCallbackRateLimited(t *testing.T) {
	forceBackend(t, "ipset")

	var calls []string
	SetBanSkippedHandler(func(ip, reason, path string) {
		calls = append(calls, ip+"|"+reason+"|"+path)
	})
	t.Cleanup(func() { SetBanSkippedHandler(nil) })

	fixedNow := time.Now()
	oldNow := guardNow
	guardNow = func() time.Time { return fixedNow }
	t.Cleanup(func() { guardNow = oldNow })

	SetWhitelist([]string{"203.0.113.5"}, nil)

	for i := 0; i < 5; i++ {
		_ = BanIP("203.0.113.5")
	}
	if len(calls) != 1 {
		t.Fatalf("handler called %d times within the window, want 1 (deduped)", len(calls))
	}
	if calls[0] != "203.0.113.5|whitelist|ban_ip" {
		t.Errorf("call = %q", calls[0])
	}

	guardNow = func() time.Time { return fixedNow.Add(2 * time.Hour) }
	_ = BanIP("203.0.113.5")
	if len(calls) != 2 {
		t.Fatalf("handler not called again after the window: %d calls", len(calls))
	}

	// Dedup key is ip+reason (not ip+reason+path), matching this package's
	// own notifyBanSkipped — a second distinct window is needed to see the
	// ApplyBans path reported, not just a different call site in the same
	// window as the BanIP call above.
	guardNow = func() time.Time { return fixedNow.Add(4 * time.Hour) }
	_ = ApplyBans([]string{"203.0.113.5"})
	if len(calls) != 3 || !strings.HasSuffix(calls[2], "|apply_ban_entries") {
		t.Errorf("ApplyBans path not reported correctly: %v", calls)
	}
}

func TestUnbanAndCleanupNotGuarded(t *testing.T) {
	f := forceBackend(t, "ipset")
	SetWhitelist([]string{"203.0.113.5"}, nil)

	if err := UnbanIP("203.0.113.5"); err != nil {
		t.Fatalf("UnbanIP of a whitelisted IP must still reach the backend: %v", err)
	}
	if !callsContain(f.Calls(), "203.0.113.5") {
		t.Error("UnbanIP never reached the backend — removal must always be possible")
	}

	CleanupStaleBans(map[string]bool{}, nil)
}

// TestChokePointIsUnique proves a Backend's Ban/BanBatch, reached through a
// variable assigned from current() (the real shape in backend.go:
// `b := current(); ...; b.Ban(...)` / `b.BanBatch(...)` — current().Ban(
// inline never appears literally, see this plan's own SUMMARY deviation
// note), each appear exactly once in the non-test source of package
// firewall — so no future executor code path can reach a backend's Ban
// without going through the guard.
func TestChokePointIsUnique(t *testing.T) {
	fset := token.NewFileSet()
	banCalls := 0
	batchCalls := 0

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(".", name)
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}

		ast.Inspect(file, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}

			// Identifiers assigned directly from a current() call, within
			// this one function body (backend.go never aliases current()
			// across function boundaries).
			currentVars := map[string]bool{}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				assign, ok := n.(*ast.AssignStmt)
				if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
					return true
				}
				ident, ok := assign.Lhs[0].(*ast.Ident)
				if !ok {
					return true
				}
				call, ok := assign.Rhs[0].(*ast.CallExpr)
				if !ok {
					return true
				}
				fnIdent, ok := call.Fun.(*ast.Ident)
				if ok && fnIdent.Name == "current" {
					currentVars[ident.Name] = true
				}

				return true
			})

			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}

				// Either the inline current().Ban(...) shape, or a prior
				// b := current() variable.
				isCurrentReceiver := false
				if recvCall, ok := sel.X.(*ast.CallExpr); ok {
					if recvIdent, ok := recvCall.Fun.(*ast.Ident); ok && recvIdent.Name == "current" {
						isCurrentReceiver = true
					}
				} else if recvIdent, ok := sel.X.(*ast.Ident); ok && currentVars[recvIdent.Name] {
					isCurrentReceiver = true
				}
				if !isCurrentReceiver {
					return true
				}

				switch sel.Sel.Name {
				case "Ban":
					banCalls++
				case "BanBatch":
					batchCalls++
				}

				return true
			})

			return true
		})
	}

	if banCalls != 1 {
		t.Errorf("Ban( on a current()-derived receiver appears %d times in non-test source, want 1", banCalls)
	}
	if batchCalls != 1 {
		t.Errorf("BanBatch( on a current()-derived receiver appears %d times in non-test source, want 1", batchCalls)
	}
}

func TestPhase17ParityUnaffectedByGuard(t *testing.T) {
	resetGuardState(t)
	// Default guard state (no whitelist, no CSF, no sessions) must not
	// change any Phase 17 backend behaviour byte-for-byte. The real parity
	// suites (TestIpsetParityInit etc.) already run in this package with
	// the guard compiled in; this is a direct smoke check that a plain ban
	// with nothing configured still reaches the backend unmodified.
	f := forceBackend(t, "ipset")
	if err := BanIP("203.0.113.50"); err != nil {
		t.Fatalf("BanIP with empty guard state: %v", err)
	}
	if !callsContain(f.Calls(), "203.0.113.50") {
		t.Error("ban did not reach the backend with empty guard state")
	}
}
