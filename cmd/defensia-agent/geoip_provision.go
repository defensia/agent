package main

import (
	"log"
	"os"
	"strings"
	"time"

	"github.com/defensia/agent/internal/api"
	"github.com/defensia/agent/internal/firewall"
	"github.com/defensia/agent/internal/geoip"
)

const (
	geoipRefreshEvery = 7 * 24 * time.Hour
	geoipRetryEvery   = time.Hour
)

// provisionGeoIP keeps the panel-served country database on disk and loaded.
// A hand-installed MaxMind file takes precedence and is never replaced.
func provisionGeoIP(c *api.Client, geo *geoip.Lookup, gb *firewall.GeoBlocker) {
	etagPath := geoip.ProvisionedDBPath + ".etag"

	for {
		loaded, path := geo.Loaded()
		if loaded && path != geoip.ProvisionedDBPath {
			return
		}

		etag := ""
		if loaded {
			if b, err := os.ReadFile(etagPath); err == nil {
				etag = strings.TrimSpace(string(b))
			}
		}

		newETag, changed, err := c.DownloadGeoIPDB(geoip.ProvisionedDBPath, etag)
		switch {
		case err != nil:
			log.Printf("[geoip] could not fetch the country database from the panel: %v", err)
		case changed:
			if err := geo.Reload(geoip.ProvisionedDBPath); err != nil {
				log.Printf("[geoip] downloaded database does not open: %v", err)
				break
			}
			_ = os.WriteFile(etagPath, []byte(newETag), 0o644)
			// Reload every country set from the new data on the next sync
			gb.Invalidate()
		}

		wait := geoipRefreshEvery
		if ok, _ := geo.Loaded(); !ok {
			wait = geoipRetryEvery
		}
		time.Sleep(wait)
	}
}
