package modsecurity

import "testing"

// sanabilisConf is our own server's shape, reduced from its `nginx -T` output
// on 20 Nov 2026. nginx owns :80 and :443, Apache listens on :8080 and :8443,
// and nginx forwards only to Node backends.
//
// The reduction is faithful on the point being tested: the parser was run over
// the full 985-line output of the real host and returned exactly [3002 8000
// 5678] — no Apache port — which is what this fixture also produces. The full
// output is not committed because it carries customer hostnames and paths and
// this repository is public.
//
// Ground truth, verified by hand on the host: the same SQL injection returns
// 403 on Apache's :8080 and 404 on the public :443. The mismatch warning is
// CORRECT here and must survive this check.
const sanabilisConf = `
http {
    server {
        listen 443 ssl;
        server_name sanabilis.me;
        location / {
            proxy_pass http://127.0.0.1:3002/;
        }
        location /hooks {
            proxy_pass http://127.0.0.1:5678;
        }
        location ~ \.php$ {
            fastcgi_pass unix:/run/php/php8.2-fpm.sock;
        }
    }
    server {
        listen 443 ssl;
        server_name api.example.com;
        location / { proxy_pass http://127.0.0.1:8000; }
    }
}
`

// cpanelConf is the arrangement cPanel and Plesk build: nginx on the public
// ports forwarding every request to Apache, which carries ModSecurity. The
// warning here would be wrong — Apache inspects everything.
const cpanelConf = `
http {
    server {
        listen 80;
        server_name shop.example.com;
        location / {
            proxy_pass http://127.0.0.1:8080;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
    }
}
`

// upstreamConf points proxy_pass at a named upstream, so the port only appears
// on the upstream's server line.
const upstreamConf = `
http {
    upstream apache_backend {
        server 127.0.0.1:8080 weight=2;
        server 127.0.0.1:8081 backup;
    }
    server {
        listen 443 ssl;
        location / { proxy_pass http://apache_backend; }
    }
}
`

func TestParseNginxProxyPorts(t *testing.T) {
	got := ParseNginxProxyPorts(sanabilisConf)

	want := map[int]bool{3002: true, 5678: true, 8000: true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want the three Node ports", got)
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected port %d in %v", p, got)
		}
	}
}

// TestParseNginxProxyPortsReadsUpstreamBlocks: a named upstream hides the port
// from the proxy_pass line, and missing it would report a mismatch on a host
// that is fully protected.
func TestParseNginxProxyPortsReadsUpstreamBlocks(t *testing.T) {
	got := ParseNginxProxyPorts(upstreamConf)

	if !forwardsTo(got, []int{8080}) {
		t.Fatalf("an upstream server line must be read as a proxy target, got %v", got)
	}
}

func TestParseNginxProxyPortsIgnoresFastcgiSockets(t *testing.T) {
	// A unix socket has no port; nothing should be invented for it.
	for _, p := range ParseNginxProxyPorts(`location ~ \.php$ { fastcgi_pass unix:/run/php/php8.2-fpm.sock; }`) {
		t.Errorf("a unix socket produced port %d", p)
	}
}

// TestTheWarningSurvivesWhenNginxProxiesElsewhere is the sanabilis case,
// verified by hand on the host: same SQL injection returns 403 on Apache's
// :8080 and 404 on the public :443.
func TestTheWarningSurvivesWhenNginxProxiesElsewhere(t *testing.T) {
	restore := stubProxyProbes(t, sanabilisConf, []int{8080, 8443})
	defer restore()

	if proxiedToInspector("nginx", true) {
		t.Fatal("nginx forwards to Node backends, not to Apache — the warning must stand")
	}
}

// TestTheWarningIsSilencedBehindAReverseProxy is the case this file exists for.
func TestTheWarningIsSilencedBehindAReverseProxy(t *testing.T) {
	restore := stubProxyProbes(t, cpanelConf, []int{8080})
	defer restore()

	if !proxiedToInspector("nginx", true) {
		t.Fatal("nginx forwards every request to Apache, which carries the module: no mismatch")
	}
}

// TestAStoppedApacheInspectsNothing: the module is installed, but if Apache is
// not listening then wherever nginx forwards, it is not to an inspector.
func TestAStoppedApacheInspectsNothing(t *testing.T) {
	restore := stubProxyProbes(t, cpanelConf, nil)
	defer restore()

	if proxiedToInspector("nginx", true) {
		t.Fatal("Apache is not listening, so nothing it holds can inspect anything")
	}
}

// TestAnUnreadableConfigDoesNotSilenceTheWarning pins the bias: `nginx -T` also
// fails when the configuration is broken, and an empty answer means "we do not
// know", not "it is proxied".
func TestAnUnreadableConfigDoesNotSilenceTheWarning(t *testing.T) {
	restore := stubProxyProbes(t, "", []int{8080})
	defer restore()

	if proxiedToInspector("nginx", true) {
		t.Fatal("an unreadable config must not be read as proof of proxying")
	}
}

func TestApacheOnThePublicPortsIsNotAProxyCase(t *testing.T) {
	restore := stubProxyProbes(t, cpanelConf, []int{80, 443})
	defer restore()

	// Apache holds the ports itself: decideActive answers this, not the proxy check.
	if proxiedToInspector("apache", true) {
		t.Fatal("Apache serving directly is not a proxy arrangement")
	}
}

func TestNginxWithoutApacheModuleIsNotAProxyCase(t *testing.T) {
	restore := stubProxyProbes(t, cpanelConf, []int{8080})
	defer restore()

	if proxiedToInspector("nginx", false) {
		t.Fatal("if Apache has no module, forwarding to it protects nothing")
	}
}

func stubProxyProbes(t *testing.T, conf string, apachePorts []int) func() {
	t.Helper()

	origConf, origPorts := nginxConfigOutput, listeningPortsOf
	nginxConfigOutput = func() string { return conf }
	listeningPortsOf = func(name string) []int {
		if name == "apache" {
			return apachePorts
		}

		return nil
	}

	return func() { nginxConfigOutput, listeningPortsOf = origConf, origPorts }
}

// TestAnInlineProxyPassIsNotMissed: `location / { proxy_pass ...; }` on one
// line is legal nginx and the first version of the regex, anchored to the line
// start, skipped it. Missing a proxy target is the direction that produces a
// wrong warning.
func TestAnInlineProxyPassIsNotMissed(t *testing.T) {
	ports := ParseNginxProxyPorts(`server { location / { proxy_pass http://127.0.0.1:8080; } }`)

	if !forwardsTo(ports, []int{8080}) {
		t.Fatalf("inline proxy_pass missed, got %v", ports)
	}
}

// TestACommentedBackendDoesNotCount guards the bias in the other direction: a
// commented-out backend must not be read as proof of proxying.
func TestACommentedBackendDoesNotCount(t *testing.T) {
	conf := `
http {
    upstream old {
        # server 127.0.0.1:8080;   disabled during the migration
    }
    server { location / { proxy_pass http://127.0.0.1:3002; } }
}
`
	if forwardsTo(ParseNginxProxyPorts(conf), []int{8080}) {
		t.Fatal("a commented-out backend was counted as a live proxy target")
	}
}
