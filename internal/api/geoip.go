package api

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// geoipMinBytes rejects truncated or error-page downloads; the country
// database is several megabytes.
const geoipMinBytes = 1 << 20

// DownloadGeoIPDB fetches the country database the panel serves to agents and
// writes it to dest atomically. etag is the value from the previous download
// (empty on first run); when the panel answers 304 the file is left alone and
// changed is false.
func (c *Client) DownloadGeoIPDB(dest, etag string) (newETag string, changed bool, err error) {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+"/api/v1/agent/geoip-db", nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Authorization", "Bearer "+c.token)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	// The shared client times out after 15s, too short for a multi-megabyte
	// body on a slow link.
	hc := &http.Client{Timeout: 3 * time.Minute, Transport: c.httpClient.Transport}
	resp, err := hc.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return etag, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", false, &HTTPError{Status: resp.StatusCode, Body: string(b)}
	}

	tmp, err := os.CreateTemp(filepath.Dir(dest), ".geoip-*.tmp")
	if err != nil {
		return "", false, err
	}
	defer os.Remove(tmp.Name()) // no-op once renamed

	n, err := io.Copy(tmp, resp.Body)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", false, err
	}
	if n < geoipMinBytes {
		return "", false, fmt.Errorf("geoip download too small (%d bytes)", n)
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return "", false, err
	}
	if err := os.Rename(tmp.Name(), dest); err != nil {
		return "", false, err
	}

	return strings.TrimSpace(resp.Header.Get("ETag")), true, nil
}
