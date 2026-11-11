package geoip

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewWithoutADatabaseDisablesLookupsWithoutFailing(t *testing.T) {
	l := New(filepath.Join(t.TempDir(), "missing.mmdb"))
	if ok, _ := l.Loaded(); ok {
		t.Fatal("Loaded() = true with no file")
	}
	if cc := l.Country("8.8.8.8"); cc != "" {
		t.Fatalf("Country = %q, want empty", cc)
	}
	if _, err := l.ExtractCIDRs("US"); err == nil {
		t.Fatal("ExtractCIDRs must fail without a database")
	}
}

func TestReloadRejectsAFileThatIsNotADatabase(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.mmdb")
	if err := os.WriteFile(bad, []byte("not an mmdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	l := New(filepath.Join(t.TempDir(), "missing.mmdb"))
	if err := l.Reload(bad); err == nil {
		t.Fatal("Reload accepted a corrupt file")
	}
	if ok, _ := l.Loaded(); ok {
		t.Fatal("a failed Reload must not mark the lookup as loaded")
	}
}

// With PROBE_DB pointing at a real country database (e.g. DB-IP lite), check
// Reload end to end, including the US set size that overflowed maxelem 131072.
func TestReloadWithARealDatabase(t *testing.T) {
	p := os.Getenv("PROBE_DB")
	if p == "" {
		t.Skip("set PROBE_DB to a country .mmdb to run")
	}
	l := New(filepath.Join(t.TempDir(), "missing.mmdb"))
	if err := l.Reload(p); err != nil {
		t.Fatal(err)
	}
	if ok, path := l.Loaded(); !ok || path != p {
		t.Fatalf("Loaded() = %v %q", ok, path)
	}
	if cc := l.Country("8.8.8.8"); cc != "US" {
		t.Fatalf("8.8.8.8 -> %q, want US", cc)
	}
	us, err := l.ExtractCIDRs("US")
	if err != nil || len(us) == 0 {
		t.Fatalf("US CIDRs: %d, %v", len(us), err)
	}
	if len(us) > 262144 {
		t.Fatalf("US has %d networks, more than the ipset maxelem of 262144", len(us))
	}
}
