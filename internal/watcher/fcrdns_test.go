package watcher

import "testing"

func TestInKnownBotNetwork(t *testing.T) {
	cases := []struct {
		name string
		ip   string
		slug string
		want bool
	}{
		// Meta's own fetchers, the ones rDNS could not verify (no PTR record).
		{"meta ipv6 crawler", "2a03:2880:f800:1::1", "facebookbot", true},
		{"meta ipv4 crawler", "173.252.83.117", "facebookbot", true},
		{"meta ipv4 mapped", "::ffff:69.171.249.10", "facebookbot", true},
		// Link previews built on consumer lines: not Meta, so not verified here.
		{"uk mobile preview", "82.132.237.206", "facebookbot", false},
		{"uk broadband ipv6 preview", "2a06:5902:4a25:db00:ccd3:52be:5717:4030", "facebookbot", false},
		// A published network only vouches for the bot that owns it.
		{"meta ip claiming googlebot", "2a03:2880:f800:1::1", "googlebot", false},
		{"unknown slug", "173.252.83.117", "somebot", false},
		{"unparseable ip", "not-an-ip", "facebookbot", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := inKnownBotNetwork(c.ip, c.slug); got != c.want {
				t.Errorf("inKnownBotNetwork(%q, %q) = %v, want %v", c.ip, c.slug, got, c.want)
			}
		})
	}
}

func TestCheckBotFcrdnsTrustsPublishedNetworkWithoutDNS(t *testing.T) {
	w := &WebWatcher{fcrdns: newFcrdnsCache(0)}
	// This address has no PTR record, so rDNS alone fails it — which is how Meta's
	// own crawlers were being reported as spoofed. It must verify on the network.
	if verified, _ := w.checkBotFcrdns("2a03:2880:f800:1::1", "facebookbot"); !verified {
		t.Error("request from Meta's network was not verified")
	}
}

func TestUnverifiedBotEvent(t *testing.T) {
	cases := []struct {
		category   string
		wantType   string
		wantSev    string
		wantAction string
	}{
		// A social preview UA is sent by real phones: failing rDNS is expected.
		{"social", "bot_monitor", "info", "unverified_preview"},
		// A search crawler that does not verify is a forgery, as before.
		{"search", "bot_spoofed", "warning", "spoofed"},
		{"", "bot_spoofed", "warning", "spoofed"},
	}
	for _, c := range cases {
		gotType, gotSev, gotAction := unverifiedBotEvent(c.category)
		if gotType != c.wantType || gotSev != c.wantSev || gotAction != c.wantAction {
			t.Errorf("unverifiedBotEvent(%q) = (%q, %q, %q), want (%q, %q, %q)",
				c.category, gotType, gotSev, gotAction, c.wantType, c.wantSev, c.wantAction)
		}
	}
}

func TestMetaNetworksParse(t *testing.T) {
	if len(metaNetworks) != 31 {
		t.Errorf("metaNetworks has %d prefixes, want 31", len(metaNetworks))
	}
}
