package monitor

import "testing"

func TestClassifyBind(t *testing.T) {
	cases := []struct {
		name string
		addr string
		want Exposure
	}{
		// Every spelling of "all interfaces" that ss produces across families
		// and versions. Getting any of these wrong understates a real exposure.
		{"ipv4 wildcard", "0.0.0.0", ExposureWildcard},
		{"star wildcard", "*", ExposureWildcard},
		{"empty is wildcard", "", ExposureWildcard},
		{"ipv6 wildcard", "::", ExposureWildcard},
		{"ipv6 wildcard bracketed", "[::]", ExposureWildcard},

		{"ipv4 loopback", "127.0.0.1", ExposureLoopback},
		{"ipv4 loopback alt", "127.0.1.1", ExposureLoopback},
		{"ipv6 loopback", "::1", ExposureLoopback},
		{"ipv6 loopback bracketed", "[::1]", ExposureLoopback},

		// The case the two checks disagreed about: reachable from the LAN, not
		// from the internet. Neither "safe" nor "publicly exposed".
		{"rfc1918 ten", "10.0.0.5", ExposurePrivate},
		{"rfc1918 172", "172.16.4.1", ExposurePrivate},
		{"rfc1918 172 upper", "172.31.255.254", ExposurePrivate},
		{"rfc1918 192.168", "192.168.1.10", ExposurePrivate},
		{"link local", "169.254.1.1", ExposurePrivate},

		// 172.32 is outside RFC1918 — the classic off-by-one in hand-rolled
		// private-range checks.
		{"172.32 is public", "172.32.0.1", ExposurePublic},
		{"routable", "185.7.81.107", ExposurePublic},
		{"ipv6 routable", "2a01:4f8::1", ExposurePublic},

		// Unparseable must not be downgraded to safe. A finding we cannot
		// classify is reported, not silently cleared.
		{"garbage is not safe", "not-an-address", ExposureWildcard},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ClassifyBind(c.addr); got != c.want {
				t.Errorf("ClassifyBind(%q) = %q, want %q", c.addr, got, c.want)
			}
		})
	}
}

func TestClassifyBindStripsInterfaceSuffix(t *testing.T) {
	if got := ClassifyBind("fe80::1%eth0"); got != ExposurePrivate {
		t.Errorf("link-local with zone = %q, want %q", got, ExposurePrivate)
	}
}

func TestExposureReachability(t *testing.T) {
	cases := []struct {
		e                 Exposure
		reachable, public bool
	}{
		{ExposureLoopback, false, false},
		{ExposurePrivate, true, false},
		{ExposureWildcard, true, true},
		{ExposurePublic, true, true},
	}

	for _, c := range cases {
		if got := c.e.Reachable(); got != c.reachable {
			t.Errorf("%q.Reachable() = %v, want %v", c.e, got, c.reachable)
		}
		if got := c.e.PubliclyReachable(); got != c.public {
			t.Errorf("%q.PubliclyReachable() = %v, want %v", c.e, got, c.public)
		}
	}
}

// The peer column of a LISTEN row is itself "0.0.0.0:*". The previous checks
// matched substrings against the whole ss output, so they read that column as a
// bind address; they only ever worked because the port number happened to be
// appended to the pattern. This test pins the field-position parse.
func TestParseListenersIgnoresThePeerColumn(t *testing.T) {
	// Real `ss -tlnH` output: a MySQL bound only to loopback.
	out := "LISTEN 0      151          127.0.0.1:3306      0.0.0.0:*    users:((\"mysqld\",pid=1234,fd=23))\n"

	got := ParseListeners(out)
	if len(got) != 1 {
		t.Fatalf("got %d listeners, want 1: %+v", len(got), got)
	}
	if got[0].Bind != "127.0.0.1" {
		t.Errorf("bind = %q, want 127.0.0.1 (the peer column must not be read as the bind)", got[0].Bind)
	}
	if got[0].Exposure != ExposureLoopback {
		t.Errorf("exposure = %q, want %q — a loopback MySQL must never read as exposed", got[0].Exposure, ExposureLoopback)
	}
	if got[0].Port != 3306 {
		t.Errorf("port = %d, want 3306", got[0].Port)
	}
}

func TestParseListeners(t *testing.T) {
	out := `LISTEN 0 151 0.0.0.0:3306 0.0.0.0:* users:(("mysqld",pid=1,fd=23))
LISTEN 0 4096 127.0.0.1:6379 0.0.0.0:* users:(("redis-server",pid=2,fd=6))
LISTEN 0 511 *:80 *:* users:(("nginx",pid=3,fd=6))
LISTEN 0 128 [::1]:5432 [::]:* users:(("postgres",pid=4,fd=5))
LISTEN 0 128 192.168.1.10:27017 0.0.0.0:* users:(("mongod",pid=5,fd=9))
`

	got := ParseListeners(out)
	if len(got) != 5 {
		t.Fatalf("got %d listeners, want 5: %+v", len(got), got)
	}

	want := map[int]struct {
		bind string
		exp  Exposure
	}{
		3306:  {"0.0.0.0", ExposureWildcard},
		6379:  {"127.0.0.1", ExposureLoopback},
		80:    {"*", ExposureWildcard},
		5432:  {"[::1]", ExposureLoopback},
		27017: {"192.168.1.10", ExposurePrivate},
	}

	for _, l := range got {
		w, ok := want[l.Port]
		if !ok {
			t.Errorf("unexpected port %d", l.Port)
			continue
		}
		if l.Bind != w.bind {
			t.Errorf("port %d bind = %q, want %q", l.Port, l.Bind, w.bind)
		}
		if l.Exposure != w.exp {
			t.Errorf("port %d exposure = %q, want %q", l.Port, l.Exposure, w.exp)
		}
	}
}

func TestParseListenersSkipsJunk(t *testing.T) {
	out := `State  Recv-Q Send-Q Local Address:Port Peer Address:Port
LISTEN 0 151 0.0.0.0:3306 0.0.0.0:*
short line
LISTEN 0 151 noport 0.0.0.0:*
LISTEN 0 151 0.0.0.0:notanumber 0.0.0.0:*
LISTEN 0 151 0.0.0.0:99999 0.0.0.0:*
`

	got := ParseListeners(out)
	if len(got) != 1 {
		t.Fatalf("got %d listeners, want 1 (only the valid row): %+v", len(got), got)
	}
	if got[0].Port != 3306 {
		t.Errorf("port = %d, want 3306", got[0].Port)
	}
}
