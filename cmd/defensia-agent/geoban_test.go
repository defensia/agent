package main

import (
	"path/filepath"
	"testing"

	"github.com/defensia/agent/internal/firewall"
	"github.com/defensia/agent/internal/geoip"
)

// Without a country database nothing can be attributed to a country, so the
// per-IP geoblock ban must stay silent rather than guess.
func TestGeoBanReasonWithoutDatabaseNeverBans(t *testing.T) {
	geo := geoip.New(filepath.Join(t.TempDir(), "missing.mmdb"))
	geo.SetBlocked([]string{"US"})
	gb := firewall.NewGeoBlocker(func(string) ([]string, error) { return nil, nil }, "")

	if r := geoBanReason(geo, gb, "8.8.8.8"); r != "" {
		t.Fatalf("geoBanReason = %q, want no ban", r)
	}
}
