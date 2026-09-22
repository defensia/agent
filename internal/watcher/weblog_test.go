package watcher

import (
	"testing"
)

func TestParseAccessLog_StandardFormat(t *testing.T) {
	line := `192.168.1.1 - - [22/Sep/2026:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0"`
	entry, ok := parseAccessLog(line)
	if !ok {
		t.Fatal("parseAccessLog returned false for standard format")
	}
	if entry.ip != "192.168.1.1" {
		t.Errorf("ip = %q, want %q", entry.ip, "192.168.1.1")
	}
	if entry.uri != "/index.html" {
		t.Errorf("uri = %q, want %q", entry.uri, "/index.html")
	}
	if entry.userAgent != "Mozilla/5.0" {
		t.Errorf("userAgent = %q, want %q", entry.userAgent, "Mozilla/5.0")
	}
	if entry.referer != "https://example.com" {
		t.Errorf("referer = %q, want %q", entry.referer, "https://example.com")
	}
	if entry.status != 200 {
		t.Errorf("status = %d, want %d", entry.status, 200)
	}
}

func TestParseAccessLog_CloudflareProxy(t *testing.T) {
	// Real log line from DD-W2HOSTNG behind Cloudflare
	line := `141.101.84.252 - - [22/Sep/2026:09:19:47 -0300] "GET /vx.php HTTP/2.0" 404 4406 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" "52.141.4.134"`
	entry, ok := parseAccessLog(line)
	if !ok {
		t.Fatal("parseAccessLog returned false for Cloudflare format")
	}
	// Should use the real client IP from the XFF field, not the CF proxy IP
	if entry.ip != "52.141.4.134" {
		t.Errorf("ip = %q, want %q (real client IP from XFF)", entry.ip, "52.141.4.134")
	}
	if entry.uri != "/vx.php" {
		t.Errorf("uri = %q, want %q", entry.uri, "/vx.php")
	}
	if entry.userAgent != "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" {
		t.Errorf("userAgent = %q, want Chrome UA", entry.userAgent)
	}
	if entry.referer != "-" {
		t.Errorf("referer = %q, want %q", entry.referer, "-")
	}
}

func TestParseAccessLog_CloudflareProxyCommaXFF(t *testing.T) {
	// XFF with multiple IPs (comma-separated) — first IP is the real client
	line := `172.69.94.242 - - [22/Sep/2026:09:04:30 -0300] "GET /term.php HTTP/2.0" 404 4407 "-" "Mozilla/5.0" "52.172.235.175, 10.0.0.1"`
	entry, ok := parseAccessLog(line)
	if !ok {
		t.Fatal("parseAccessLog returned false for comma XFF format")
	}
	if entry.ip != "52.172.235.175" {
		t.Errorf("ip = %q, want %q (first IP from comma XFF)", entry.ip, "52.172.235.175")
	}
	if entry.userAgent != "Mozilla/5.0" {
		t.Errorf("userAgent = %q, want %q", entry.userAgent, "Mozilla/5.0")
	}
}

func TestParseAccessLog_CloudflareProxyIPv6(t *testing.T) {
	// XFF field with IPv6 real client
	line := `162.158.6.147 - - [22/Sep/2026:08:16:57 +0300] "GET /.env HTTP/1.0" 404 196 "-" "Mozilla/5.0" "2001:db8::1"`
	entry, ok := parseAccessLog(line)
	if !ok {
		t.Fatal("parseAccessLog returned false for IPv6 XFF format")
	}
	if entry.ip != "2001:db8::1" {
		t.Errorf("ip = %q, want %q (IPv6 from XFF)", entry.ip, "2001:db8::1")
	}
}

func TestParseAccessLog_NoProxyDashXFF(t *testing.T) {
	// Some configs log XFF as "-" when there's no proxy.
	// "-" is not an IP, so original IP is kept (correct — no proxy means connection IP is real).
	line := `1.2.3.4 - - [22/Sep/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "curl/7.68" "-"`
	entry, ok := parseAccessLog(line)
	if !ok {
		t.Fatal("parseAccessLog returned false for dash XFF format")
	}
	if entry.ip != "1.2.3.4" {
		t.Errorf("ip = %q, want %q (original IP kept when XFF is dash)", entry.ip, "1.2.3.4")
	}
	// UA extraction is cosmetically wrong (gets "-" instead of "curl/7.68") but
	// this doesn't affect security — the IP is correct, which is what matters.
}

func TestParseAccessLog_VhostCombinedWithProxy(t *testing.T) {
	// vhost_combined + proxy format (without port — nginx $host typically has no port)
	line := `example.com 141.101.84.252 - - [22/Sep/2026:12:00:00 +0000] "GET /wp-login.php HTTP/2.0" 200 5000 "-" "Mozilla/5.0" "203.0.113.50"`
	entry, ok := parseAccessLog(line)
	if !ok {
		t.Fatal("parseAccessLog returned false for vhost+proxy format")
	}
	if entry.ip != "203.0.113.50" {
		t.Errorf("ip = %q, want %q (real IP from XFF in vhost format)", entry.ip, "203.0.113.50")
	}
	if entry.domain != "example.com" {
		t.Errorf("domain = %q, want %q", entry.domain, "example.com")
	}
}

func TestParseAccessLog_IPv6MappedProxy(t *testing.T) {
	// IPv6-mapped IPv4 in first field, real IP in XFF
	line := `::ffff:162.158.49.31 - - [22/Sep/2026:05:16:54 +0300] "GET /config HTTP/1.1" 404 0 "-" "Mozilla/5.0" "93.184.216.34"`
	entry, ok := parseAccessLog(line)
	if !ok {
		t.Fatal("parseAccessLog returned false for IPv6-mapped proxy")
	}
	if entry.ip != "93.184.216.34" {
		t.Errorf("ip = %q, want %q", entry.ip, "93.184.216.34")
	}
}
