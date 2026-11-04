package watcher

import (
	"net"
	"strings"
)

// cloudflareNetworks is the address space Cloudflare proxies from, as published at
// https://www.cloudflare.com/ips-v4 and https://www.cloudflare.com/ips-v6.
var cloudflareNetworks = mustParseCIDRs(
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
)

// isTrustedProxy reports whether ip is a hop allowed to tell us who the client is:
// a proxy on this host or its private network (nginx in front of Apache, a Docker
// bridge, a load balancer), or Cloudflare.
func isTrustedProxy(ip string) bool {
	parsed := net.ParseIP(strings.TrimPrefix(ip, "::ffff:"))
	if parsed == nil {
		return false
	}
	if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() {
		return true
	}
	for _, n := range cloudflareNetworks {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// clientIPFromXFF decides which address a request is attributed to, given the
// peer that opened the connection and the X-Forwarded-For value the web server
// logged. It returns the chosen address and whether it came from the header.
//
// X-Forwarded-For is written by the client unless a proxy we trust wrote it. A
// client that connects directly can put anything there: scanners routinely send
// "X-Forwarded-For: 8.8.8.8" or "1.1.1.1", and taking that at face value banned
// Google and Cloudflare's resolvers while the scanner itself went untouched. So
// the header is only read when the peer is a trusted proxy.
//
// Even then the leftmost entry is the client's own claim: a proxy appends the
// address it saw to whatever the client sent. The real client is the rightmost
// entry that is not itself a trusted proxy. An entry that is not an address means
// the chain cannot be read, and the peer is kept.
func clientIPFromXFF(peer, xff string) (string, bool) {
	if !isTrustedProxy(peer) {
		return peer, false
	}
	hops := strings.Split(xff, ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(hops[i])
		if hop == "" || !isIPAddress(hop) || net.ParseIP(strings.TrimPrefix(hop, "::ffff:")) == nil {
			return peer, false
		}
		if !isTrustedProxy(hop) {
			return hop, true
		}
	}
	// Every hop is a trusted proxy: the client is the first one recorded.
	return strings.TrimSpace(hops[0]), true
}
