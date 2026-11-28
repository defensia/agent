package firewall

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseTempBans(t *testing.T) {
	for _, fork := range []string{"original-15.00", "aetherinox-15.10", "sentinel-15.13", "directadmin-15.12", "cwp-orphan-15.00"} {
		data, err := os.ReadFile(filepath.Join("testdata", fork, "csf-tempban.txt"))
		if err != nil {
			t.Fatalf("%s: %v", fork, err)
		}
		list := parseTempBans(strings.NewReader(string(data)))
		if len(list.Entries) == 0 {
			t.Errorf("%s: no entries parsed from real fixture", fork)
		}
		if list.Malformed != 0 {
			t.Errorf("%s: %d malformed lines in a real fixture", fork, list.Malformed)
		}
	}

	line := "1730700000|203.0.113.7||in|86400|defensia:brute_force"
	list := parseTempBans(strings.NewReader(line))
	if len(list.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(list.Entries))
	}
	e := list.Entries[0]
	if e.Added != 1730700000 || e.IP != "203.0.113.7" || e.Dir != "in" || e.TTL != 86400*time.Second || e.Comment != "defensia:brute_force" {
		t.Errorf("unexpected entry: %+v", e)
	}
	if !e.Ours {
		t.Error("Ours should be true for a defensia: comment")
	}
	if !e.ExpiresAt.Equal(time.Unix(1730700000, 0).Add(86400 * time.Second)) {
		t.Errorf("ExpiresAt = %v", e.ExpiresAt)
	}

	pipeComment := "1730700000|203.0.113.7||in|86400|defensia:x|y"
	list2 := parseTempBans(strings.NewReader(pipeComment))
	if list2.Entries[0].Comment != "defensia:x|y" {
		t.Errorf("comment with pipe not kept whole: %q", list2.Entries[0].Comment)
	}

	notOurs := "1730700000|203.0.113.8||in|86400|lfd: (sshd) failed"
	list3 := parseTempBans(strings.NewReader(notOurs))
	if list3.Entries[0].Ours {
		t.Error("lfd comment should not be Ours")
	}

	garbage := parseTempBans(strings.NewReader("garbage"))
	if len(garbage.Entries) != 0 || garbage.Malformed != 1 {
		t.Errorf("garbage line: entries=%d malformed=%d", len(garbage.Entries), garbage.Malformed)
	}

	empty := parseTempBans(strings.NewReader(""))
	if len(empty.Entries) != 0 || empty.Malformed != 0 {
		t.Errorf("empty file: entries=%d malformed=%d", len(empty.Entries), empty.Malformed)
	}
}

func TestParseTempBansIPv6(t *testing.T) {
	line := "1730700000|2001:db8::1||in|3600|defensia:x"
	list := parseTempBans(strings.NewReader(line))
	if list.Entries[0].IP != "2001:db8::1" {
		t.Errorf("IP = %q", list.Entries[0].IP)
	}

	line2 := "1730700000|2001:0db8::0001||in|3600|defensia:x"
	list2 := parseTempBans(strings.NewReader(line2))
	if list2.Entries[0].IP != "2001:db8::1" {
		t.Errorf("non-canonical IPv6 not canonicalised: %q", list2.Entries[0].IP)
	}
}

func TestReadTempBansMissingFile(t *testing.T) {
	old := csfVarDir
	csfVarDir = t.TempDir()
	t.Cleanup(func() { csfVarDir = old })

	list, err := readTempBans()
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if list.Entries != nil {
		t.Errorf("entries = %v, want nil", list.Entries)
	}
	if list.Exists {
		t.Error("Exists = true, want false")
	}
}

func TestCSFBanConf(t *testing.T) {
	old := csfDir
	dir := t.TempDir()
	csfDir = dir
	t.Cleanup(func() { csfDir = old })

	conf := `DENY_TEMP_IP_LIMIT = "100"
IPV6 = "1"
TESTING = "0"
LF_DAEMON = "1"
# IPV6 = "0"
`
	if err := os.WriteFile(filepath.Join(dir, "csf.conf"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := readCSFBanConf()
	if err != nil {
		t.Fatal(err)
	}
	if got.TempLimit != 100 {
		t.Errorf("TempLimit = %d, want 100", got.TempLimit)
	}
	if !got.IPv6 || got.Testing || !got.LFDaemon {
		t.Errorf("IPv6/Testing/LFDaemon = %v/%v/%v", got.IPv6, got.Testing, got.LFDaemon)
	}

	conf2 := `DENY_TEMP_IP_LIMIT="250"`
	if err := os.WriteFile(filepath.Join(dir, "csf.conf"), []byte(conf2), 0o644); err != nil {
		t.Fatal(err)
	}
	got2, err := readCSFBanConf()
	if err != nil {
		t.Fatal(err)
	}
	if got2.TempLimit != 250 {
		t.Errorf("TempLimit (no-space form) = %d, want 250", got2.TempLimit)
	}

	conf3 := `IPV6 = "1"`
	if err := os.WriteFile(filepath.Join(dir, "csf.conf"), []byte(conf3), 0o644); err != nil {
		t.Fatal(err)
	}
	got3, err := readCSFBanConf()
	if err != nil {
		t.Fatal(err)
	}
	if got3.TempLimit != -1 {
		t.Errorf("missing DENY_TEMP_IP_LIMIT -> TempLimit = %d, want -1 (unknown)", got3.TempLimit)
	}
	if got3.Found["DENY_TEMP_IP_LIMIT"] {
		t.Error("Found[DENY_TEMP_IP_LIMIT] should be false")
	}
}

func TestReadTempBansErrorIsWrapped(t *testing.T) {
	if !errors.Is(ErrTempBanBusy, ErrTempBanBusy) {
		t.Fatal("sanity: ErrTempBanBusy should be comparable with errors.Is")
	}
}
