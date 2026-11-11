package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func geoipServer(t *testing.T, body []byte, etag string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/geoip-db" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.Write(body)
	}))
}

func TestDownloadGeoIPDBWritesAndHonoursETag(t *testing.T) {
	body := bytes.Repeat([]byte{0xAB}, geoipMinBytes+10)
	srv := geoipServer(t, body, `"v1"`)
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "geoip-country.mmdb")
	c := New(srv.URL, "tok")

	tag, changed, err := c.DownloadGeoIPDB(dest, "")
	if err != nil || !changed || tag != `"v1"` {
		t.Fatalf("first download: tag=%q changed=%v err=%v", tag, changed, err)
	}
	got, _ := os.ReadFile(dest)
	if !bytes.Equal(got, body) {
		t.Fatal("file content differs from what the panel served")
	}

	tag, changed, err = c.DownloadGeoIPDB(dest, `"v1"`)
	if err != nil || changed || tag != `"v1"` {
		t.Fatalf("304: tag=%q changed=%v err=%v", tag, changed, err)
	}
}

func TestDownloadGeoIPDBRejectsATruncatedBody(t *testing.T) {
	srv := geoipServer(t, []byte("<html>error</html>"), `"v1"`)
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "geoip-country.mmdb")
	if err := os.WriteFile(dest, []byte("previous"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, _, err := New(srv.URL, "tok").DownloadGeoIPDB(dest, ""); err == nil {
		t.Fatal("expected an error for a body smaller than a real database")
	}
	if got, _ := os.ReadFile(dest); string(got) != "previous" {
		t.Fatal("a failed download must leave the existing file untouched")
	}
}

func TestDownloadGeoIPDBReportsAuthFailure(t *testing.T) {
	srv := geoipServer(t, nil, `"v1"`)
	defer srv.Close()

	_, _, err := New(srv.URL, "wrong").DownloadGeoIPDB(filepath.Join(t.TempDir(), "x.mmdb"), "")
	if he, ok := err.(*HTTPError); !ok || he.Status != http.StatusUnauthorized {
		t.Fatalf("err = %v, want HTTPError 401", err)
	}
}
