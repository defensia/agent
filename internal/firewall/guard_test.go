package firewall

import (
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func resetGuardState(t *testing.T) {
	t.Helper()
	guardMu.Lock()
	guardWhitelist = nil
	guardCSFAllow = nil
	guardCSFIgnore = nil
	guardCSFMtimes = map[string]time.Time{}
	guardCSFCheckedAt = time.Time{}
	guardMu.Unlock()

	prevHasCSF := guardHasCSF
	guardHasCSF = func() bool { return false }

	prevSSH := activeSSHSessionIPs
	activeSSHSessionIPs = func() []netip.Addr { return nil }
	sshSessionCacheMu.Lock()
	sshSessionCacheAt = time.Time{}
	sshSessionCacheData = nil
	sshSessionCacheMu.Unlock()

	t.Cleanup(func() {
		guardHasCSF = prevHasCSF
		activeSSHSessionIPs = prevSSH
		SetWhitelist(nil, nil)
	})
}

func TestGuardWhitelist(t *testing.T) {
	resetGuardState(t)
	SetWhitelist([]string{"203.0.113.5"}, []string{"198.51.100.0/24", "2001:db8::/32", "bogus"})

	if ok, reason := guardCheck("203.0.113.5"); ok || reason != "whitelist" {
		t.Errorf("203.0.113.5: ok=%v reason=%q, want false/whitelist", ok, reason)
	}
	if ok, reason := guardCheck("198.51.100.77"); ok || reason != "whitelist" {
		t.Errorf("198.51.100.77: ok=%v reason=%q, want false/whitelist", ok, reason)
	}
	if ok, reason := guardCheck("2001:db8::9"); ok || reason != "whitelist" {
		t.Errorf("2001:db8::9: ok=%v reason=%q, want false/whitelist", ok, reason)
	}
	if ok, _ := guardCheck("203.0.113.6"); !ok {
		t.Error("203.0.113.6 should be allowed")
	}
}

func writeCSFList(t *testing.T, dir, name string, lines []string) {
	t.Helper()
	content := ""
	for _, l := range lines {
		content += l + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestGuardCSFAllow(t *testing.T) {
	resetGuardState(t)
	dir := t.TempDir()
	oldCsfDir := csfDir
	csfDir = dir
	t.Cleanup(func() { csfDir = oldCsfDir })
	guardHasCSF = func() bool { return true }

	extraDir := t.TempDir()
	writeCSFList(t, extraDir, "extra.allow", []string{"203.0.113.99"})

	writeCSFList(t, dir, "csf.allow", []string{
		"203.0.113.10 # admin",
		"198.51.100.0/28",
		"tcp|in|d=22|s=192.0.2.44",
		"tcp|in|d=22|s=192.0.2.128/25",
		"Include " + filepath.Join(extraDir, "extra.allow"),
		"u=1000",
		"host.example.com",
	})
	writeCSFList(t, dir, "csf.ignore", nil)

	for _, ip := range []string{"203.0.113.10", "198.51.100.1", "192.0.2.44", "192.0.2.200", "203.0.113.99"} {
		if ok, reason := guardCheck(ip); ok || reason != "csf_allow" {
			t.Errorf("%s: ok=%v reason=%q, want false/csf_allow", ip, ok, reason)
		}
	}
	if ok, _ := guardCheck("203.0.113.11"); !ok {
		t.Error("203.0.113.11 should be allowed")
	}
}

func TestGuardCSFIgnore(t *testing.T) {
	resetGuardState(t)
	dir := t.TempDir()
	oldCsfDir := csfDir
	csfDir = dir
	t.Cleanup(func() { csfDir = oldCsfDir })
	guardHasCSF = func() bool { return true }

	writeCSFList(t, dir, "csf.allow", nil)
	writeCSFList(t, dir, "csf.ignore", []string{"203.0.113.20", "2001:db8:1::/48"})

	if ok, reason := guardCheck("203.0.113.20"); ok || reason != "csf_ignore" {
		t.Errorf("ok=%v reason=%q", ok, reason)
	}
	if ok, reason := guardCheck("2001:db8:1::5"); ok || reason != "csf_ignore" {
		t.Errorf("ok=%v reason=%q", ok, reason)
	}
}

func TestGuardIncludeLoop(t *testing.T) {
	resetGuardState(t)
	dir := t.TempDir()
	oldCsfDir := csfDir
	csfDir = dir
	t.Cleanup(func() { csfDir = oldCsfDir })
	guardHasCSF = func() bool { return true }

	fileA := filepath.Join(dir, "a.allow")
	fileB := filepath.Join(dir, "b.allow")
	writeCSFList(t, dir, "csf.allow", []string{"Include " + fileA})
	if err := os.WriteFile(fileA, []byte("Include "+fileB+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fileB, []byte("Include "+fileA+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeCSFList(t, dir, "csf.ignore", nil)

	done := make(chan bool)
	go func() {
		guardCheck("203.0.113.1")
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("guardCheck did not terminate — Include cycle not guarded")
	}
}

func TestGuardReloadByMtime(t *testing.T) {
	resetGuardState(t)
	guardListRefreshEvery = 0 // for the test, re-check every call
	t.Cleanup(func() { guardListRefreshEvery = 5 * time.Second })

	dir := t.TempDir()
	oldCsfDir := csfDir
	csfDir = dir
	t.Cleanup(func() { csfDir = oldCsfDir })
	guardHasCSF = func() bool { return true }

	writeCSFList(t, dir, "csf.allow", []string{"203.0.113.1"})
	writeCSFList(t, dir, "csf.ignore", nil)

	if ok, _ := guardCheck("203.0.113.2"); !ok {
		t.Fatal("203.0.113.2 should be allowed before the edit")
	}

	time.Sleep(10 * time.Millisecond) // ensure a distinguishable mtime
	writeCSFList(t, dir, "csf.allow", []string{"203.0.113.1", "203.0.113.2"})

	if ok, reason := guardCheck("203.0.113.2"); ok || reason != "csf_allow" {
		t.Errorf("after edit: ok=%v reason=%q, want false/csf_allow", ok, reason)
	}
}

func TestGuardNoCSF(t *testing.T) {
	resetGuardState(t)
	guardHasCSF = func() bool { return false }
	SetWhitelist([]string{"203.0.113.5"}, nil)

	if ok, reason := guardCheck("203.0.113.5"); ok || reason != "whitelist" {
		t.Errorf("whitelist should still be enforced: ok=%v reason=%q", ok, reason)
	}
	if ok, _ := guardCheck("203.0.113.6"); !ok {
		t.Error("203.0.113.6 should be allowed")
	}
}

func TestGuardSSHSessions(t *testing.T) {
	resetGuardState(t)
	calls := 0
	activeSSHSessionIPs = func() []netip.Addr {
		calls++

		return []netip.Addr{netip.MustParseAddr("192.0.2.200")}
	}

	if ok, reason := guardCheck("192.0.2.200"); ok || reason != "ssh_session" {
		t.Errorf("ok=%v reason=%q, want false/ssh_session", ok, reason)
	}
	guardCheck("192.0.2.201")
	guardCheck("192.0.2.202")
	if calls != 1 {
		t.Errorf("activeSSHSessionIPs called %d times, want 1 (10s cache)", calls)
	}
}

// buildUtmpRecord builds one 384-byte utmp record for tests.
func buildUtmpRecord(utType int16, host string, v4 []byte, v6 []byte) []byte {
	rec := make([]byte, utmpRecordSize)
	binary.LittleEndian.PutUint16(rec[0:2], uint16(utType))
	if host != "" {
		copy(rec[utmpHostOffset:utmpHostOffset+utmpHostLen], host)
	}
	if v4 != nil {
		copy(rec[utmpAddrV6Offset:utmpAddrV6Offset+4], v4)
	}
	if v6 != nil {
		copy(rec[utmpAddrV6Offset:utmpAddrV6Offset+16], v6)
	}

	return rec
}

func TestParseUtmp(t *testing.T) {
	var buf []byte
	// USER_PROCESS with ut_addr_v6 = 203.0.113.50 (IPv4-in-word0)
	buf = append(buf, buildUtmpRecord(utmpUserProcess, "", []byte{203, 0, 113, 50}, nil)...)
	// DEAD_PROCESS with 198.51.100.1 — must be ignored
	buf = append(buf, buildUtmpRecord(8, "", []byte{198, 51, 100, 1}, nil)...)
	// USER_PROCESS with host "2001:db8::7" and zero addr
	buf = append(buf, buildUtmpRecord(utmpUserProcess, "2001:db8::7", nil, nil)...)

	addrs := parseUtmp(buf)
	if len(addrs) != 2 {
		t.Fatalf("got %d addrs, want 2: %v", len(addrs), addrs)
	}
	if addrs[0].String() != "203.0.113.50" {
		t.Errorf("addrs[0] = %s, want 203.0.113.50", addrs[0])
	}
	if addrs[1].String() != "2001:db8::7" {
		t.Errorf("addrs[1] = %s, want 2001:db8::7", addrs[1])
	}

	// Truncated buffer: partial trailing record must be ignored, not panic.
	truncated := buf[:len(buf)-10]
	addrs2 := parseUtmp(truncated)
	if len(addrs2) != 1 {
		t.Errorf("truncated buffer: got %d addrs, want 1 (last partial record dropped)", len(addrs2))
	}
}

func TestGuardSafeIP(t *testing.T) {
	resetGuardState(t)
	AddProtectedIPs("192.0.2.123")
	t.Cleanup(func() { delete(protectedIPs, "192.0.2.123") })

	for _, ip := range []string{"10.0.0.1", "127.0.0.1", "192.0.2.123"} {
		if ok, reason := guardCheck(ip); ok || reason != "safe" {
			t.Errorf("%s: ok=%v reason=%q, want false/safe", ip, ok, reason)
		}
	}
	if ok, reason := guardCheck("nonsense"); ok || reason != "invalid" {
		t.Errorf("nonsense: ok=%v reason=%q, want false/invalid", ok, reason)
	}
}

func TestGuardReasonOrder(t *testing.T) {
	resetGuardState(t)
	dir := t.TempDir()
	oldCsfDir := csfDir
	csfDir = dir
	t.Cleanup(func() { csfDir = oldCsfDir })
	guardHasCSF = func() bool { return true }

	writeCSFList(t, dir, "csf.allow", []string{"203.0.113.50"})
	writeCSFList(t, dir, "csf.ignore", nil)
	SetWhitelist([]string{"203.0.113.50"}, nil)

	if ok, reason := guardCheck("203.0.113.50"); ok || reason != "whitelist" {
		t.Errorf("ok=%v reason=%q, want false/whitelist (first match wins)", ok, reason)
	}
}
