package monitor

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/defensia/agent/internal/api"
)

const (
	floodConnThreshold    = 200
	synCookiesDeltaMin    = 100
	listenDropsDeltaMin   = 10
	floodCooldown         = 5 * time.Minute
)

type FloodDetector struct {
	prevTCPExt map[string]uint64
	reported   map[string]time.Time
	whitelists []string
}

func NewFloodDetector() *FloodDetector {
	return &FloodDetector{
		prevTCPExt: make(map[string]uint64),
		reported:   make(map[string]time.Time),
	}
}

func (d *FloodDetector) SetWhitelists(ips []string) {
	d.whitelists = ips
}

func (d *FloodDetector) Scan() []api.EventRequest {
	now := time.Now()
	var events []api.EventRequest

	// Prune expired cooldowns
	for k, t := range d.reported {
		if now.Sub(t) > floodCooldown {
			delete(d.reported, k)
		}
	}

	// --- Signal A: Connection flood per IP ---
	conns, err := ParseProcNetTCP()
	if err != nil {
		log.Printf("[flood] error reading /proc/net/tcp: %v", err)
	} else {
		connCount := make(map[string]int)
		for _, c := range conns {
			if c.State != TCPEstablished && c.State != TCPSynRecv && c.State != TCPTimeWait {
				continue
			}
			srcIP := c.RemoteIP.String()
			if d.shouldSkip(c.RemoteIP, srcIP) {
				continue
			}
			connCount[srcIP]++
		}

		for srcIP, count := range connCount {
			if count < floodConnThreshold {
				continue
			}
			coolKey := "conn:" + srcIP
			if _, cooled := d.reported[coolKey]; cooled {
				continue
			}

			events = append(events, api.EventRequest{
				Type:     "flood",
				Severity: "critical",
				SourceIP: srcIP,
				Details: map[string]string{
					"flood_type":  "connection_flood",
					"connections": fmt.Sprintf("%d", count),
				},
				OccurredAt: now.UTC().Format(time.RFC3339),
			})
			d.reported[coolKey] = now
		}
	}

	// --- Signal B: SYN flood global ---
	curTCPExt := parseTCPExt()
	if len(d.prevTCPExt) > 0 && len(curTCPExt) > 0 {
		syncDelta := safeDelta(curTCPExt["SyncookiesSent"], d.prevTCPExt["SyncookiesSent"])
		dropsDelta := safeDelta(curTCPExt["ListenDrops"], d.prevTCPExt["ListenDrops"])

		if syncDelta > synCookiesDeltaMin && dropsDelta > listenDropsDeltaMin {
			coolKey := "synflood"
			if _, cooled := d.reported[coolKey]; !cooled {
				events = append(events, api.EventRequest{
					Type:     "flood",
					Severity: "critical",
					Details: map[string]string{
						"flood_type":      "syn_flood",
						"syncookies_sent": fmt.Sprintf("%d", syncDelta),
						"listen_drops":    fmt.Sprintf("%d", dropsDelta),
					},
					OccurredAt: now.UTC().Format(time.RFC3339),
				})
				d.reported[coolKey] = now
			}
		}
	}
	d.prevTCPExt = curTCPExt

	return events
}

func (d *FloodDetector) shouldSkip(ip net.IP, ipStr string) bool {
	if IsPrivateIP(ip) {
		return true
	}
	for _, wl := range d.whitelists {
		if wl == ipStr {
			return true
		}
	}
	return false
}

// parseTCPExt reads /proc/net/netstat and returns TcpExt counters.
func parseTCPExt() map[string]uint64 {
	data, err := os.ReadFile("/proc/net/netstat")
	if err != nil {
		return nil
	}

	result := make(map[string]uint64)
	lines := strings.Split(string(data), "\n")

	for i := 0; i+1 < len(lines); i += 2 {
		if !strings.HasPrefix(lines[i], "TcpExt:") {
			continue
		}
		keys := strings.Fields(lines[i])
		vals := strings.Fields(lines[i+1])
		if len(keys) != len(vals) {
			continue
		}
		for j := 1; j < len(keys); j++ {
			v, err := strconv.ParseUint(vals[j], 10, 64)
			if err == nil {
				result[keys[j]] = v
			}
		}
		break
	}

	return result
}

func safeDelta(cur, prev uint64) uint64 {
	if cur >= prev {
		return cur - prev
	}
	return 0
}
