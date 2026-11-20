package modsecurity

import (
	"os/exec"
	"regexp"
	"strconv"

	"github.com/defensia/agent/internal/monitor"
	"github.com/defensia/agent/internal/webserver"
)

// Reverse-proxy awareness for the mismatch check.
//
// "Which server holds ports 80 and 443" is not the same question as "does the
// traffic pass through the server that carries ModSecurity", and the difference
// is an entire architecture: nginx in front of Apache is what cPanel and Plesk
// build by default, and there ModSecurity on Apache inspects every request even
// though Apache owns no public port at all.
//
// Without this, the mismatch warning tells those hosts they are unprotected
// when they are fully protected. Measured on our own server, where the warning
// is correct and this check must NOT silence it: nginx owns :80 and :443,
// Apache listens on :8080, and nginx's proxy_pass targets are 127.0.0.1:3002,
// :5678 and :8000 — Node backends. Nothing public reaches Apache, and the same
// SQL injection returns 403 on :8080 and 404 on :443.
//
// The bias is deliberate: anything unparseable or unknown resolves to "we do
// not know that it is proxied", which leaves the mismatch unreported. Telling a
// customer their WAF is in the wrong place when it is not is worse than saying
// nothing.

// proxyTargetPort matches the port in a proxy_pass or upstream server target:
// proxy_pass http://127.0.0.1:8080/, server 127.0.0.1:8080 weight=2.
//
// Not anchored to the start of a line. An earlier version was, and missed
// `location / { proxy_pass http://127.0.0.1:8000; }` — legal nginx, and present
// in a real configuration in the fleet.
var proxyTargetPort = regexp.MustCompile(`\b(?:proxy_pass\s+\w+://|server\s+)[^\s;:{}]+:(\d{1,5})`)

// nginxComment strips `# ...` to end of line.
//
// Without this, a commented-out `# server 127.0.0.1:8080;` would read as proof
// that nginx forwards to Apache and would silence a warning that should fire —
// the one direction of error that matters here.
var nginxComment = regexp.MustCompile(`(?m)#.*$`)

// nginxConfigOutput is `nginx -T`: the fully resolved configuration, includes
// expanded. A var so a test can supply a configuration without nginx.
var nginxConfigOutput = func() string {
	out, err := exec.Command("nginx", "-T").CombinedOutput()
	if err != nil {
		// -T also fails when the config is broken, in which case we know
		// nothing about where it proxies. Caller treats empty as "unknown".
		return ""
	}

	return string(out)
}

// listeningPortsOf is the ports a given web server currently listens on.
// A var for the same reason.
var listeningPortsOf = func(name string) []int {
	var ports []int

	for _, svc := range monitor.DetectListeningServices() {
		if webserver.FromProcess(svc.Process) == name {
			ports = append(ports, svc.Port)
		}
	}

	return ports
}

// ParseNginxProxyPorts returns every port nginx forwards requests to, taken
// from both proxy_pass directives and the server lines of upstream blocks.
//
// Both are collected rather than resolving proxy_pass -> upstream by name
// because the question being asked is coarse — does nginx forward anywhere
// Apache is listening — and an unresolved upstream name would answer it with a
// false negative, which is the direction that produces a wrong warning.
func ParseNginxProxyPorts(conf string) []int {
	seen := make(map[int]bool)
	var ports []int

	for _, m := range proxyTargetPort.FindAllStringSubmatch(nginxComment.ReplaceAllString(conf, ""), -1) {
		p, err := strconv.Atoi(m[1])
		if err != nil || p < 1 || p > 65535 || seen[p] {
			continue
		}

		seen[p] = true
		ports = append(ports, p)
	}

	return ports
}

// forwardsTo reports whether any of the proxied ports is one the backend holds.
func forwardsTo(proxied, backend []int) bool {
	if len(proxied) == 0 || len(backend) == 0 {
		return false
	}

	held := make(map[int]bool, len(backend))
	for _, p := range backend {
		held[p] = true
	}

	for _, p := range proxied {
		if held[p] {
			return true
		}
	}

	return false
}

// proxiedToInspector reports whether the server on the public ports forwards to
// a server that carries ModSecurity.
//
// Scoped to nginx in front of Apache, which is the arrangement that exists in
// the fleet and the one this was measured against. Other combinations return
// false, which only means the mismatch is reported as before — never that a
// protected host is told it is unprotected by a path nobody has tested.
func proxiedToInspector(serving string, apacheHasModule bool) bool {
	if serving != "apache" && serving != "nginx" {
		return false
	}
	if serving == "nginx" && !apacheHasModule {
		return false
	}
	if serving == "apache" {
		// Apache already holds the ports; decideActive handles it.
		return false
	}

	apachePorts := listeningPortsOf("apache")
	if len(apachePorts) == 0 {
		// The module is installed but Apache is not running: it inspects
		// nothing, wherever nginx forwards.
		return false
	}

	return forwardsTo(ParseNginxProxyPorts(nginxConfigOutput()), apachePorts)
}
