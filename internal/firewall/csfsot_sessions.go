package firewall

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// sshSessionIPs answers "which IPs currently have an established SSH
// session to this host" — re-evaluated immediately before every allow
// removal or deny add, never cached, because sessions open and close
// between cycles. Primary source is `ss`, queried once per candidate SSH
// port; if ss is unavailable, falls back to parsing /proc/net/tcp and
// /proc/net/tcp6 directly. If NEITHER source can answer, returns an
// error: the caller (guardAllowRemoval/guardDenyAdd) must then fail
// closed and refuse the operation rather than guess.
func sshSessionIPs(ctx context.Context, sshPorts []int) ([]netip.Addr, error) {
	if len(sshPorts) == 0 {
		sshPorts = []int{22}
	}

	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	add := func(a netip.Addr) {
		a = a.Unmap()
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}

	if bin := ssBinaryPath(); bin != "" {
		anyOK := false
		for _, port := range sshPorts {
			data, err := run(ctx, csfExecTimeout, bin, "-Hnt", "state", "established", fmt.Sprintf("( sport = :%d )", port))
			if err != nil {
				continue
			}
			anyOK = true
			for _, addr := range parseSSPeers(string(data)) {
				add(addr)
			}
		}
		if anyOK {
			return out, nil
		}
	}

	procAddrs, err := sshSessionIPsFromProc(sshPorts)
	if err != nil {
		return nil, fmt.Errorf("ss unavailable and /proc fallback failed: %w", err)
	}
	for _, a := range procAddrs {
		add(a)
	}

	return out, nil
}

// parseSSPeers extracts the peer address from each line of
// `ss -Hnt state established ...` output. With an explicit `state
// established` filter, every iproute2 build observed against the real
// lab (AlmaLinux 8/9/10 and Debian 12, iproute2 5.x-6.x) OMITS the State
// column entirely from the data rows -- confirmed live (phase 16.1,
// 2026-11-19): a hardcoded field index of 4 (assuming State Recv-Q
// Send-Q Local-Address:Port Peer-Address:Port, 5 columns) silently
// dropped every real row, because the actual rows are only 4 columns
// (Recv-Q Send-Q Local-Address:Port Peer-Address:Port) -- making
// guardAllowRemoval/guardDenyAdd see zero sessions and therefore refuse
// NOTHING, the opposite of fail-closed. Peer-Address:Port is always the
// LAST field regardless of whether State is present (no -p flag is ever
// passed here, so there is never a trailing process column either), so
// index from the end instead of a fixed position.
func parseSSPeers(out string) []netip.Addr {
	var addrs []netip.Addr
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if addr, ok := parseSSAddrPort(fields[len(fields)-1]); ok {
			addrs = append(addrs, addr)
		}
	}

	return addrs
}

// parseSSAddrPort parses an `ss` "host:port" or "[host]:port" column (v6
// addresses are bracketed) and returns just the address.
func parseSSAddrPort(field string) (netip.Addr, bool) {
	if strings.HasPrefix(field, "[") {
		end := strings.Index(field, "]")
		if end < 0 {
			return netip.Addr{}, false
		}
		addr, err := netip.ParseAddr(field[1:end])

		return addr, err == nil
	}

	host, _, ok := strings.Cut(field, ":")
	if !ok {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(host)

	return addr, err == nil
}

// sshSessionIPsFromProc is the fallback source: parses /proc/net/tcp and
// /proc/net/tcp6 directly for ESTABLISHED (state 01) rows whose LOCAL
// port is one of sshPorts, returning the peer address of each.
func sshSessionIPsFromProc(sshPorts []int) ([]netip.Addr, error) {
	wantPorts := map[int]bool{}
	for _, p := range sshPorts {
		wantPorts[p] = true
	}

	var addrs []netip.Addr
	var firstErr error
	any := false

	for _, name := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		got, err := parseProcNetTCP(hostPath(name), wantPorts)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}

			continue
		}
		any = true
		addrs = append(addrs, got...)
	}

	if !any {
		return nil, firstErr
	}

	return addrs, nil
}

// parseProcNetTCP parses one /proc/net/tcp(6)-shaped file, returning the
// peer address of every ESTABLISHED (st=01) row whose local port is in
// wantPorts. LISTEN (st=0A) and every other state is ignored.
func parseProcNetTCP(path string, wantPorts map[int]bool) ([]netip.Addr, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var addrs []netip.Addr
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false

			continue // header line
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}

		localPort, ok := procHexPort(fields[1])
		if !ok || !wantPorts[localPort] {
			continue
		}
		if fields[3] != "01" { // ESTABLISHED only
			continue
		}

		peer, ok := procHexAddr(fields[2])
		if !ok {
			continue
		}
		addrs = append(addrs, peer)
	}

	return addrs, sc.Err()
}

// procHexPort extracts the port half ("ADDR:PORT") of a /proc/net/tcp
// address column.
func procHexPort(field string) (int, bool) {
	_, portHex, ok := strings.Cut(field, ":")
	if !ok {
		return 0, false
	}
	port, err := strconv.ParseInt(portHex, 16, 32)

	return int(port), err == nil
}

// procHexAddr decodes the address half of a /proc/net/tcp(6) "ADDR:PORT"
// column: the IP is stored as hex bytes in reverse (per-32-bit-word, for
// v6) order from the normal dotted/colon form.
func procHexAddr(field string) (netip.Addr, bool) {
	addrHex, _, ok := strings.Cut(field, ":")
	if !ok {
		return netip.Addr{}, false
	}

	raw, err := hex.DecodeString(addrHex)
	if err != nil {
		return netip.Addr{}, false
	}

	switch len(raw) {
	case 4:
		reverseBytes(raw)

		addr, ok := netip.AddrFromSlice(raw)

		return addr, ok
	case 16:
		// Stored as four 32-bit little-endian words; reverse each word's
		// 4 bytes in place, the overall 16-byte sequence is then the
		// address in normal network-byte-order.
		for i := 0; i < 16; i += 4 {
			reverseBytes(raw[i : i+4])
		}

		addr, ok := netip.AddrFromSlice(raw)

		return addr, ok
	default:
		return netip.Addr{}, false
	}
}

func reverseBytes(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}
