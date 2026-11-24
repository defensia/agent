package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defensia/agent/internal/csfsotwire"
)

func TestObserveFixtures(t *testing.T) {
	for _, name := range fixtureDirs {
		t.Run(name, func(t *testing.T) {
			dir := copyFixture(t, name)

			obs, err := observeSot()
			if err != nil {
				t.Fatalf("observeSot: %v", err)
			}
			if len(obs.Problems) != 0 {
				t.Fatalf("Problems = %+v, want none", obs.Problems)
			}

			vals, _ := parseCSFConf(mustOpen(t, filepath.Join(dir, "csf.conf")))
			for _, key := range sotPortKeys {
				want, present := vals[key]
				got, inScope := obs.Managed.Ports[key]
				if present {
					if !inScope || got != want {
						t.Errorf("Ports[%s] = %q (inScope=%v), want %q", key, got, inScope, want)
					}
				} else if inScope {
					t.Errorf("Ports[%s] unexpectedly in scope", key)
				}
			}
			if obs.IPv6 {
				for _, key := range sotPortKeys6 {
					want, present := vals[key]
					got, inScope := obs.Managed.Ports[key]
					if present {
						if !inScope || got != want {
							t.Errorf("Ports[%s] = %q (inScope=%v), want %q", key, got, inScope, want)
						}
					} else if inScope {
						t.Errorf("Ports[%s] unexpectedly in scope", key)
					}
				}
			} else {
				for _, key := range sotPortKeys6 {
					if _, inScope := obs.Managed.Ports[key]; inScope {
						t.Errorf("Ports[%s] in scope but IPV6 is off", key)
					}
				}
			}
		})
	}
}

func mustOpen(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { f.Close() })

	return f
}

func TestObserveReadOnly(t *testing.T) {
	dir := copyFixture(t, "aetherinox-15.10")

	var calls int
	restore := ObserveCommands(func(name string, args []string) { calls++ })
	defer restore()

	hashBefore := map[string]string{}
	mtimeBefore := map[string]time.Time{}
	for _, f := range []string{"csf.conf", "csf.allow", "csf.deny"} {
		hashBefore[f] = sha256File(t, filepath.Join(dir, f))
		st, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatalf("stat %s: %v", f, err)
		}
		mtimeBefore[f] = st.ModTime()
	}

	for i := 0; i < 3; i++ {
		if _, err := observeSot(); err != nil {
			t.Fatalf("observeSot call %d: %v", i, err)
		}
	}

	if calls != 0 {
		t.Errorf("ObserveCommands fired %d times, want 0 (observeSot must never exec)", calls)
	}
	for _, f := range []string{"csf.conf", "csf.allow", "csf.deny"} {
		if got := sha256File(t, filepath.Join(dir, f)); got != hashBefore[f] {
			t.Errorf("%s sha256 changed: %s -> %s", f, hashBefore[f], got)
		}
		st, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatalf("stat %s: %v", f, err)
		}
		if !st.ModTime().Equal(mtimeBefore[f]) {
			t.Errorf("%s mtime changed: %v -> %v", f, mtimeBefore[f], st.ModTime())
		}
	}
}

func sha256File(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(data)

	return hex.EncodeToString(sum[:])
}

func TestObserveIPv6Scope(t *testing.T) {
	t.Run("IPV6_off", func(t *testing.T) {
		copyFixture(t, "aetherinox-15.10")
		writeConfKey(t, "IPV6", "0")

		obs, err := observeSot()
		if err != nil {
			t.Fatalf("observeSot: %v", err)
		}
		if obs.IPv6 {
			t.Error("IPv6 = true, want false")
		}
		for _, key := range sotPortKeys6 {
			if _, ok := obs.Managed.Ports[key]; ok {
				t.Errorf("Ports[%s] in scope with IPV6=0", key)
			}
		}
	})

	t.Run("IPV6_on_TCP6_IN_present", func(t *testing.T) {
		copyFixture(t, "aetherinox-15.10")
		writeConfKey(t, "IPV6", "1")
		writeConfKey(t, "TCP6_IN", "22,443")

		obs, err := observeSot()
		if err != nil {
			t.Fatalf("observeSot: %v", err)
		}
		if !obs.IPv6 {
			t.Fatal("IPv6 = false, want true")
		}
		if got, ok := obs.Managed.Ports["TCP6_IN"]; !ok || got != "22,443" {
			t.Errorf("Ports[TCP6_IN] = %q (ok=%v), want 22,443", got, ok)
		}
	})

	t.Run("IPV6_on_UDP6_OUT_absent", func(t *testing.T) {
		dir := copyFixture(t, "aetherinox-15.10")
		writeConfKey(t, "IPV6", "1")
		removeConfKey(t, dir, "UDP6_OUT")

		obs, err := observeSot()
		if err != nil {
			t.Fatalf("observeSot: %v", err)
		}
		if _, ok := obs.Managed.Ports["UDP6_OUT"]; ok {
			t.Error("Ports[UDP6_OUT] in scope despite being absent from the file")
		}
		for _, p := range obs.Problems {
			if p.Reason != "" && p.Detail == "UDP6_OUT" {
				t.Errorf("unexpected problem for an absent (not malformed) key: %+v", p)
			}
		}
	})
}

func removeConfKey(t *testing.T, dir, key string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "csf.conf"))
	if err != nil {
		t.Fatalf("read csf.conf: %v", err)
	}

	lines := strings.Split(string(data), "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		m := confKeyLine.FindStringSubmatch(line)
		if m != nil && m[1] == key {
			continue
		}
		out = append(out, line)
	}

	if err := os.WriteFile(filepath.Join(dir, "csf.conf"), []byte(strings.Join(out, "\n")), 0o644); err != nil {
		t.Fatalf("write csf.conf: %v", err)
	}
}

func TestObserveProblems(t *testing.T) {
	t.Run("duplicate_key", func(t *testing.T) {
		copyFixture(t, "aetherinox-15.10")
		appendConfLine(t, `TCP_IN = "22,80"`)

		obs, err := observeSot()
		if err != nil {
			t.Fatalf("observeSot: %v", err)
		}
		if !hasProblem(obs.Problems, "duplicate_key", "TCP_IN") {
			t.Errorf("Problems = %+v, want duplicate_key/TCP_IN", obs.Problems)
		}
		if _, ok := obs.Managed.Ports["TCP_IN"]; ok {
			t.Error("duplicate key TCP_IN must not be written into Managed.Ports")
		}
	})

	t.Run("unparseable", func(t *testing.T) {
		copyFixture(t, "aetherinox-15.10")
		writeConfKey(t, "TCP_OUT", "22,abc")

		obs, err := observeSot()
		if err != nil {
			t.Fatalf("observeSot: %v", err)
		}
		if !hasProblem(obs.Problems, "unparseable", "TCP_OUT") {
			t.Errorf("Problems = %+v, want unparseable/TCP_OUT", obs.Problems)
		}
	})

	t.Run("csf_disabled", func(t *testing.T) {
		dir := copyFixture(t, "aetherinox-15.10")
		if err := os.WriteFile(filepath.Join(dir, "csf.disable"), nil, 0o644); err != nil {
			t.Fatalf("write csf.disable: %v", err)
		}

		obs, err := observeSot()
		if err != nil {
			t.Fatalf("observeSot: %v", err)
		}
		if !hasProblem(obs.Problems, "csf_disabled", "") {
			t.Errorf("Problems = %+v, want csf_disabled", obs.Problems)
		}
	})

	t.Run("commented_duplicate_not_a_duplicate", func(t *testing.T) {
		copyFixture(t, "aetherinox-15.10")
		appendConfLine(t, `# TCP_IN = "22,80"`)

		obs, err := observeSot()
		if err != nil {
			t.Fatalf("observeSot: %v", err)
		}
		if hasProblem(obs.Problems, "duplicate_key", "TCP_IN") {
			t.Errorf("Problems = %+v, a commented-out duplicate must not count", obs.Problems)
		}
	})
}

func hasProblem(problems []csfsotwire.Problem, reason, detail string) bool {
	for _, p := range problems {
		if p.Reason == reason && p.Detail == detail {
			return true
		}
	}

	return false
}

func TestObserveTaggedEntries(t *testing.T) {
	dir := copyFixture(t, "aetherinox-15.10")

	allowLines := "\n" +
		"203.0.113.5 # defensia:sot - Mon Nov  4 10:00:00 2026\n" +
		"192.0.2.10 # lab-panel\n" +
		"198.51.100.0/24 # defensia:tpl-web\n" +
		`tcp|in|d=22|s=203.0.113.9 # defensia:x` + "\n"

	f, err := os.OpenFile(filepath.Join(dir, "csf.allow"), os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open csf.allow: %v", err)
	}
	if _, err := f.WriteString(allowLines); err != nil {
		t.Fatalf("append csf.allow: %v", err)
	}
	f.Close()

	obs, err := observeSot()
	if err != nil {
		t.Fatalf("observeSot: %v", err)
	}

	if len(obs.Managed.Allow) != 2 {
		t.Fatalf("Allow = %+v, want 2 tagged entries", obs.Managed.Allow)
	}
	byValue := map[string]string{}
	for _, e := range obs.Managed.Allow {
		byValue[e.Value] = e.Comment
	}
	if c, ok := byValue["203.0.113.5"]; !ok || c != "defensia:sot" {
		t.Errorf("Allow[203.0.113.5].Comment = %q (ok=%v), want defensia:sot (date stripped)", c, ok)
	}
	if c, ok := byValue["198.51.100.0/24"]; !ok || c != "defensia:tpl-web" {
		t.Errorf("Allow[198.51.100.0/24].Comment = %q (ok=%v), want defensia:tpl-web", c, ok)
	}

	if !obs.ForeignAllow["192.0.2.10"] {
		t.Error("ForeignAllow must contain the non-tagged 192.0.2.10 entry")
	}
	if obs.ForeignAllow["203.0.113.9"] {
		t.Error("an advanced filter line must never be treated as a managed or foreign plain entry")
	}
}

func TestSaveconfReplayNoDrift(t *testing.T) {
	for _, name := range fixtureDirs {
		t.Run(name, func(t *testing.T) {
			dir := copyFixture(t, name)

			before, err := observeSot()
			if err != nil {
				t.Fatalf("observeSot (before): %v", err)
			}
			hashBefore := sotHash(before.Managed)

			confPath := filepath.Join(dir, "csf.conf")
			raw, err := os.ReadFile(confPath)
			if err != nil {
				t.Fatalf("read csf.conf: %v", err)
			}
			if err := os.WriteFile(confPath, saveconfReplay(raw), 0o644); err != nil {
				t.Fatalf("write replayed csf.conf: %v", err)
			}

			after, err := observeSot()
			if err != nil {
				t.Fatalf("observeSot (after): %v", err)
			}
			hashAfter := sotHash(after.Managed)

			if hashBefore != hashAfter {
				t.Errorf("hash changed after a saveconf replay: %s -> %s", hashBefore, hashAfter)
			}
			if drift := diffSot(before.Managed, after.Managed); len(drift) != 0 {
				t.Errorf("diffSot after replay = %+v, want none", drift)
			}
		})
	}
}

func TestReorderNoDrift(t *testing.T) {
	copyFixture(t, "aetherinox-15.10")

	writeConfKey(t, "TCP_IN", "22,80,443")
	before, err := observeSot()
	if err != nil {
		t.Fatalf("observeSot (before): %v", err)
	}

	writeConfKey(t, "TCP_IN", " 443 , 22 , 22 , 80 ")
	after, err := observeSot()
	if err != nil {
		t.Fatalf("observeSot (after): %v", err)
	}

	if sotHash(before.Managed) != sotHash(after.Managed) {
		t.Errorf("hash changed after reordering+spacing+duplicate token: %s -> %s",
			sotHash(before.Managed), sotHash(after.Managed))
	}
	if drift := diffSot(before.Managed, after.Managed); len(drift) != 0 {
		t.Errorf("diffSot after reorder = %+v, want none", drift)
	}
}

func TestDiffSot(t *testing.T) {
	desired := csfsotwire.Managed{
		Ports: map[string]string{"TCP_IN": "21,22"},
		Allow: []csfsotwire.Entry{{Value: "203.0.113.5", Comment: "defensia:sot"}},
		Deny:  []csfsotwire.Entry{},
	}
	observed := csfsotwire.Managed{
		Ports: map[string]string{"TCP_IN": "22,8080"},
		Allow: []csfsotwire.Entry{},
		Deny:  []csfsotwire.Entry{{Value: "198.51.100.9", Comment: "defensia:blk"}},
	}

	drift := diffSot(desired, observed)
	if len(drift) != 3 {
		t.Fatalf("diffSot = %+v, want 3 items", drift)
	}
	if drift[0].Kind != "port" || drift[0].Key != "TCP_IN" {
		t.Errorf("drift[0] = %+v, want kind=port key=TCP_IN", drift[0])
	}
	assertStrSlice(t, "drift[0].Added", drift[0].Added, []string{"8080"})
	assertStrSlice(t, "drift[0].Removed", drift[0].Removed, []string{"21"})

	if drift[1].Kind != "allow" || drift[1].Value != "203.0.113.5" || drift[1].Change != "removed" {
		t.Errorf("drift[1] = %+v, want kind=allow value=203.0.113.5 change=removed", drift[1])
	}
	if drift[2].Kind != "deny" || drift[2].Value != "198.51.100.9" || drift[2].Change != "added" {
		t.Errorf("drift[2] = %+v, want kind=deny value=198.51.100.9 change=added", drift[2])
	}
}

func TestSotHashContract(t *testing.T) {
	m := csfsotwire.Managed{
		Ports: map[string]string{"TCP_IN": "22,80,443"},
		Allow: []csfsotwire.Entry{{Value: "203.0.113.5"}},
		Deny:  []csfsotwire.Entry{},
	}

	want := sha256.Sum256([]byte(`{"allow":["203.0.113.5"],"deny":[],"ports":{"TCP_IN":"22,80,443"}}`))
	if got := sotHash(m); got != hex.EncodeToString(want[:]) {
		t.Errorf("sotHash = %s, want %s", got, hex.EncodeToString(want[:]))
	}
}

func TestFingerprint(t *testing.T) {
	dir := copyFixture(t, "aetherinox-15.10")

	fp1 := sotFingerprint()
	fp2 := sotFingerprint()
	if fp1 != fp2 {
		t.Errorf("fingerprint changed with no file change: %s -> %s", fp1, fp2)
	}

	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(filepath.Join(dir, "csf.deny"), future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	fp3 := sotFingerprint()
	if fp1 == fp3 {
		t.Error("fingerprint unchanged after touching csf.deny's mtime")
	}
}
