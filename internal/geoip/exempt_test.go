package geoip

import (
	"os"
	"testing"
)

func TestExemptRangesAreNeverReportedBlocked(t *testing.T) {
	l := &Lookup{}
	l.SetBlocked([]string{"GB", "US"})
	l.SetExempt([]string{"172.64.0.0/13", "66.249.64.0/27", "not-a-cidr", " 141.101.64.0/18 "})

	cases := []struct {
		cc, ip string
		want   bool
	}{
		{"GB", "172.71.241.110", false}, // Cloudflare edge geolocated to GB
		{"GB", "141.101.98.67", false},  // Cloudflare, range given with spaces
		{"US", "66.249.64.5", false},    // Googlebot
		{"US", "203.0.113.9", true},     // ordinary US address
		{"GB", "198.51.100.1", true},    // ordinary GB address
		{"FR", "172.71.241.110", false}, // country not blocked at all
	}
	for _, c := range cases {
		if got := l.blockedFor(c.cc, c.ip); got != c.want {
			t.Errorf("blockedFor(%s, %s) = %v, want %v", c.cc, c.ip, got, c.want)
		}
	}
}

func TestSetExemptReplacesThePreviousList(t *testing.T) {
	l := &Lookup{}
	l.SetBlocked([]string{"GB"})
	l.SetExempt([]string{"172.64.0.0/13"})
	l.SetExempt(nil)

	if !l.blockedFor("GB", "172.71.241.110") {
		t.Fatal("an emptied exempt list must not keep exempting the old ranges")
	}
}

// With PROBE_DB set, check against real geolocation that the Cloudflare edges
// seen banned in production resolve to a blocked country yet are not blocked.
func TestExemptCloudflareEdgeWithARealDatabase(t *testing.T) {
	p := os.Getenv("PROBE_DB")
	if p == "" {
		t.Skip("set PROBE_DB to a country .mmdb to run")
	}
	l := New(p)
	cc := l.Country("172.71.241.110")
	if cc == "" {
		t.Fatal("no country for a Cloudflare edge")
	}
	l.SetBlocked([]string{cc})
	if _, blocked := l.IsBlocked("172.71.241.110"); !blocked {
		t.Fatalf("precondition: edge in blocked %s must be blocked before exemptions", cc)
	}
	l.SetExempt([]string{"172.64.0.0/13"})
	if _, blocked := l.IsBlocked("172.71.241.110"); blocked {
		t.Fatalf("Cloudflare edge in %s still blocked after exempting 172.64.0.0/13", cc)
	}
}
