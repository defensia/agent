package monitor

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	TCPEstablished = 0x01
	TCPSynRecv     = 0x02
	TCPTimeWait    = 0x06
)

type TCPConn struct {
	LocalIP    net.IP
	RemoteIP   net.IP
	LocalPort  uint16
	RemotePort uint16
	State      uint8
}

func ParseProcNetTCP() ([]TCPConn, error) {
	data, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return nil, fmt.Errorf("read /proc/net/tcp: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	var conns []TCPConn

	for i, line := range lines {
		if i == 0 {
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		localIP, localPort, err := parseHexAddr(fields[1])
		if err != nil {
			continue
		}

		remoteIP, remotePort, err := parseHexAddr(fields[2])
		if err != nil {
			continue
		}

		state, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil {
			continue
		}

		conns = append(conns, TCPConn{
			LocalIP:    localIP,
			RemoteIP:   remoteIP,
			LocalPort:  localPort,
			RemotePort: remotePort,
			State:      uint8(state),
		})
	}

	return conns, nil
}

func parseHexAddr(s string) (net.IP, uint16, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return nil, 0, fmt.Errorf("invalid addr: %s", s)
	}

	ipHex := parts[0]
	if len(ipHex) != 8 {
		return nil, 0, fmt.Errorf("invalid ip hex: %s", ipHex)
	}

	ipBytes, err := hex.DecodeString(ipHex)
	if err != nil {
		return nil, 0, err
	}

	// /proc/net/tcp uses little-endian for IPv4
	ip := net.IPv4(ipBytes[3], ipBytes[2], ipBytes[1], ipBytes[0])

	port, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return nil, 0, err
	}

	return ip, uint16(port), nil
}

func IsPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() {
		return true
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	if ip4[0] == 10 {
		return true
	}
	if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
		return true
	}
	if ip4[0] == 192 && ip4[1] == 168 {
		return true
	}
	return false
}