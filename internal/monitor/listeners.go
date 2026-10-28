package monitor

import (
	"net"
	"os/exec"
	"strconv"
	"strings"
)

// Exposure classifies what a listening socket's bind address means for reachability.
//
// This type exists because two separate checks — the db_exposed event in
// internal/watcher and the PORT_* audit findings in internal/scanner — each decided
// for themselves what "exposed" meant, and disagreed. A database on 192.168.1.10:3306
// was silent in one and "exposed externally" in the other. Both now classify through
// here so they cannot drift again.
type Exposure string

const (
	// ExposureLoopback — bound to 127.0.0.0/8 or ::1. Not reachable off the host.
	ExposureLoopback Exposure = "loopback"

	// ExposurePrivate — bound to one RFC1918 / link-local address. Reachable from
	// that network but not from the internet. Worth telling the operator about; not
	// the same claim as "publicly exposed".
	ExposurePrivate Exposure = "private"

	// ExposureWildcard — bound to 0.0.0.0, ::, or * — every interface the host has,
	// including any public one. This is the case worth a critical alert.
	ExposureWildcard Exposure = "wildcard"

	// ExposurePublic — bound to one specific address that is neither loopback nor
	// private, i.e. a routable address.
	ExposurePublic Exposure = "public"
)

// Reachable reports whether a listener could be reached from off the host.
func (e Exposure) Reachable() bool {
	return e == ExposurePrivate || e == ExposureWildcard || e == ExposurePublic
}

// PubliclyReachable reports whether a listener could be reached from the internet.
// A private bind is deliberately excluded: it is reachable, but not publicly.
func (e Exposure) PubliclyReachable() bool {
	return e == ExposureWildcard || e == ExposurePublic
}

// Listener is one listening TCP socket, with its bind address classified.
type Listener struct {
	Port     int
	Bind     string
	Exposure Exposure
}

// ClassifyBind maps a bind address, as `ss` prints it, to an Exposure.
//
// `ss -tlnH` writes the wildcard several ways depending on family and version:
// "0.0.0.0", "*", "" , "::" and "[::]" all mean every interface. IPv6 loopback
// appears as "::1" or "[::1]". Anything else is parsed as an address.
func ClassifyBind(addr string) Exposure {
	addr = strings.TrimSpace(addr)

	// A port-only form ("*:3306" split on the last colon leaves "*").
	switch addr {
	case "", "*", "0.0.0.0", "::", "[::]", "0.0.0.0%0":
		return ExposureWildcard
	}

	// Strip brackets from IPv6 literals and any interface suffix (fe80::1%eth0).
	addr = strings.TrimPrefix(addr, "[")
	addr = strings.TrimSuffix(addr, "]")
	if i := strings.Index(addr, "%"); i >= 0 {
		addr = addr[:i]
	}

	ip := net.ParseIP(addr)
	if ip == nil {
		// Unparseable. Treat as wildcard rather than as safe: a finding we cannot
		// classify must not be silently downgraded to "bound to localhost".
		return ExposureWildcard
	}

	if ip.IsUnspecified() {
		return ExposureWildcard
	}
	if ip.IsLoopback() {
		return ExposureLoopback
	}
	if IsPrivateIP(ip) || ip.IsLinkLocalUnicast() {
		return ExposurePrivate
	}
	return ExposurePublic
}

// ParseListeners turns `ss -tlnH` output into classified listeners.
//
// Taking the local address by field position matters. The previous checks matched
// substrings against the whole output, which only ever worked by accident: the peer
// column of a LISTEN row is itself "0.0.0.0:*", so a naive search for "0.0.0.0" hits
// every row including the loopback ones.
//
//	State  Recv-Q Send-Q Local Address:Port  Peer Address:Port  Process
//	LISTEN 0      151    127.0.0.1:3306      0.0.0.0:*          users:(("mysqld",…))
//	                     ^ field 3            ^ field 4 — never the bind address
//
// With -H there is no header row. Rows with fewer than four fields are skipped.
func ParseListeners(ssOutput string) []Listener {
	var out []Listener

	for _, line := range strings.Split(ssOutput, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// Skip a header if one slipped in (ss without -H).
		if fields[0] == "State" || fields[0] == "Netid" {
			continue
		}

		local := fields[3]
		i := strings.LastIndex(local, ":")
		if i < 0 {
			continue
		}
		addr := local[:i]
		port, err := strconv.Atoi(local[i+1:])
		if err != nil || port <= 0 || port > 65535 {
			continue
		}

		out = append(out, Listener{
			Port:     port,
			Bind:     addr,
			Exposure: ClassifyBind(addr),
		})
	}

	return out
}

// ListeningPorts returns the host's listening TCP sockets, classified.
//
// On a host with several addresses a port can be bound more than once. The most
// exposed binding wins, because that is the one that decides reachability — a MySQL
// on both 127.0.0.1 and 0.0.0.0 is reachable.
func ListeningPorts() map[int]Listener {
	result := make(map[int]Listener)

	out, err := exec.Command("ss", "-tlnH").Output()
	if err != nil {
		return result
	}

	rank := map[Exposure]int{
		ExposureLoopback: 0,
		ExposurePrivate:  1,
		ExposurePublic:   2,
		ExposureWildcard: 3,
	}

	for _, l := range ParseListeners(string(out)) {
		if prev, seen := result[l.Port]; !seen || rank[l.Exposure] > rank[prev.Exposure] {
			result[l.Port] = l
		}
	}

	return result
}
