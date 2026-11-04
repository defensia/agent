package watcher

import "testing"

func TestClientIPFromXFF(t *testing.T) {
	cases := []struct {
		name    string
		peer    string
		xff     string
		want    string
		wantXFF bool
	}{
		// A client connecting directly writes whatever it likes in the header.
		{"direct client forging google dns", "217.60.241.20", "8.8.8.8", "217.60.241.20", false},
		{"direct client forging loopback", "34.141.129.46", "127.0.0.1", "34.141.129.46", false},
		{"direct client forging a chain", "34.141.129.46", "1.1.1.1, 9.9.9.9", "34.141.129.46", false},

		// Behind Cloudflare the header is read, rightmost untrusted entry first.
		{"cloudflare single", "141.101.84.252", "52.141.4.134", "52.141.4.134", true},
		{"cloudflare with client-supplied prefix", "172.69.94.242", "8.8.8.8, 52.172.235.175", "52.172.235.175", true},
		{"cloudflare ipv6 client", "162.158.6.147", "2001:db8::1", "2001:db8::1", true},
		{"cloudflare mapped peer", "::ffff:162.158.49.31", "93.184.216.34", "93.184.216.34", true},

		// A local reverse proxy (nginx in front of Apache, Docker bridge).
		{"loopback proxy", "127.0.0.1", "203.0.113.50", "203.0.113.50", true},
		{"private proxy skips inner hops", "10.0.0.5", "203.0.113.50, 10.0.0.1", "203.0.113.50", true},
		{"every hop trusted", "10.0.0.5", "192.168.1.10, 10.0.0.1", "192.168.1.10", true},

		// An entry that is not an address means the chain cannot be read.
		{"junk left of the client is never reached", "10.0.0.5", "unknown, 203.0.113.50", "203.0.113.50", true},
		{"garbage rightmost keeps peer", "10.0.0.5", "203.0.113.50, unknown", "10.0.0.5", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, gotXFF := clientIPFromXFF(c.peer, c.xff)
			if got != c.want || gotXFF != c.wantXFF {
				t.Errorf("clientIPFromXFF(%q, %q) = (%q, %v), want (%q, %v)",
					c.peer, c.xff, got, gotXFF, c.want, c.wantXFF)
			}
		})
	}
}

func TestParseAccessLog_ForgedXFFFromDirectClient(t *testing.T) {
	// The line that had a server ban 8.8.8.8: a scanner connecting directly and
	// sending its own X-Forwarded-For. The scanner is the one to attribute it to.
	line := `217.60.241.20 - - [29/Oct/2026:05:58:14 -0300] "HEAD /react-app/.env.production HTTP/1.1" 404 0 "https://example.com.br/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36" "8.8.8.8"`
	entry, ok := parseAccessLog(line)
	if !ok {
		t.Fatal("parseAccessLog returned false")
	}
	if entry.ip != "217.60.241.20" {
		t.Errorf("ip = %q, want the connecting peer 217.60.241.20, not the forged XFF", entry.ip)
	}
	if entry.xffDetected {
		t.Error("xffDetected = true for a direct client; it would mark the server as behind a proxy")
	}
	// The 4-field format is still recognised, so the UA is not mistaken for the XFF.
	if entry.userAgent != "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36" {
		t.Errorf("userAgent = %q", entry.userAgent)
	}
	if entry.referer != "https://example.com.br/" {
		t.Errorf("referer = %q", entry.referer)
	}
}

func TestIsTrustedProxy(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1":            true,
		"::1":                  true,
		"10.1.2.3":             true,
		"172.17.0.1":           true,
		"192.168.0.10":         true,
		"141.101.84.252":       true, // Cloudflare
		"2606:4700:10::1":      true, // Cloudflare v6
		"::ffff:162.158.49.31": true,
		"104.28.63.127":        false, // Cloudflare WARP egress, a client, not the proxy
		"34.141.129.46":        false,
		"8.8.8.8":              false,
		"garbage":              false,
	}
	for ip, want := range cases {
		if got := isTrustedProxy(ip); got != want {
			t.Errorf("isTrustedProxy(%q) = %v, want %v", ip, got, want)
		}
	}
}
