package firewall

import (
	"encoding/binary"
	"net/netip"
	"strings"
)

// Linux glibc utmp record layout (amd64 and arm64): fixed 384-byte records.
// ut_type is an int16 at offset 0 (USER_PROCESS = 7); ut_user is a 32-byte
// field at offset 44; ut_host is a 256-byte field at offset 76; ut_addr_v6
// is [4]int32 (16 bytes, network-order) at offset 348. This file has no
// build tag: the parser is pure byte manipulation with no syscalls, so it
// compiles and is unit-tested on every platform; only the "open /var/run/
// utmp and read it" part (guard_sessions_linux.go) is Linux-only.
const (
	utmpRecordSize   = 384
	utmpTypeOffset   = 0
	utmpUserOffset   = 44
	utmpUserLen      = 32
	utmpHostOffset   = 76
	utmpHostLen      = 256
	utmpAddrV6Offset = 348
	utmpUserProcess  = 7
)

// parseUtmp extracts session source IPs from a raw utmp file buffer. Only
// USER_PROCESS records are considered; a truncated trailing partial record
// is ignored rather than causing a panic.
func parseUtmp(data []byte) []netip.Addr {
	var out []netip.Addr
	seen := map[netip.Addr]bool{}

	for off := 0; off+utmpRecordSize <= len(data); off += utmpRecordSize {
		rec := data[off : off+utmpRecordSize]

		utType := int16(binary.LittleEndian.Uint16(rec[utmpTypeOffset : utmpTypeOffset+2]))
		if utType != utmpUserProcess {
			continue
		}

		addr, ok := utmpRecordAddr(rec)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if !seen[addr] {
			seen[addr] = true
			out = append(out, addr)
		}
	}

	return out
}

// utmpRecordAddr derives the session's source IP from one utmp record's
// ut_addr_v6 ([4]int32, network-order bytes), falling back to parsing
// ut_host as a literal IP when ut_addr_v6 is all zero.
func utmpRecordAddr(rec []byte) (netip.Addr, bool) {
	addrBytes := rec[utmpAddrV6Offset : utmpAddrV6Offset+16]

	if isZero(addrBytes) {
		host := rec[utmpHostOffset : utmpHostOffset+utmpHostLen]
		hostStr := strings.TrimSpace(string(host[:indexNUL(host)]))
		if hostStr == "" {
			return netip.Addr{}, false
		}
		addr, err := netip.ParseAddr(hostStr)
		if err != nil {
			return netip.Addr{}, false
		}

		return addr, true
	}

	// words 1-3 (bytes 4-15) zero => an IPv4 address stored in word 0.
	if isZero(addrBytes[4:16]) {
		var v4 [4]byte
		copy(v4[:], addrBytes[0:4])

		return netip.AddrFrom4(v4), true
	}

	var v6 [16]byte
	copy(v6[:], addrBytes)

	return netip.AddrFrom16(v6), true
}

func isZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}

	return true
}

func indexNUL(b []byte) int {
	for i, v := range b {
		if v == 0 {
			return i
		}
	}

	return len(b)
}
