package monitor

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/defensia/agent/internal/api"
)

const (
	portScanThreshold = 15
	portScanWindow    = 60 * time.Second
	portScanCooldown  = 10 * time.Minute
)

type PortScanDetector struct {
	targets    map[string]map[uint16]time.Time // srcIP → {dstPort → firstSeen}
	reported   map[string]time.Time
	whitelists []string
}

func NewPortScanDetector() *PortScanDetector {
	return &PortScanDetector{
		targets:  make(map[string]map[uint16]time.Time),
		reported: make(map[string]time.Time),
	}
}

func (d *PortScanDetector) SetWhitelists(ips []string) {
	d.whitelists = ips
}

func (d *PortScanDetector) Scan() []api.EventRequest {
	conns, err := ParseProcNetTCP()
	if err != nil {
		log.Printf("[portscan] error reading /proc/net/tcp: %v", err)
		return nil
	}

	now := time.Now()

	// Collect SYN_RECV connections grouped by source IP
	for _, c := range conns {
		if c.State != TCPSynRecv {
			continue
		}
		srcIP := c.RemoteIP.String()
		if d.shouldSkip(c.RemoteIP, srcIP) {
			continue
		}

		if d.targets[srcIP] == nil {
			d.targets[srcIP] = make(map[uint16]time.Time)
		}
		if _, exists := d.targets[srcIP][c.LocalPort]; !exists {
			d.targets[srcIP][c.LocalPort] = now
		}
	}

	// Prune entries outside window
	for srcIP, ports := range d.targets {
		for port, firstSeen := range ports {
			if now.Sub(firstSeen) > portScanWindow {
				delete(ports, port)
			}
		}
		if len(ports) == 0 {
			delete(d.targets, srcIP)
		}
	}

	// Prune expired cooldowns
	for ip, t := range d.reported {
		if now.Sub(t) > portScanCooldown {
			delete(d.reported, ip)
		}
	}

	// Check thresholds
	var events []api.EventRequest
	for srcIP, ports := range d.targets {
		portCount := len(ports)
		if portCount < portScanThreshold {
			continue
		}
		if _, cooled := d.reported[srcIP]; cooled {
			continue
		}

		severity := "warning"
		if portCount >= 30 {
			severity = "critical"
		}

		events = append(events, api.EventRequest{
			Type:     "port_scan",
			Severity: severity,
			SourceIP: srcIP,
			Details: map[string]string{
				"ports_scanned": fmt.Sprintf("%d", portCount),
			},
			OccurredAt: now.UTC().Format(time.RFC3339),
		})

		d.reported[srcIP] = now
		delete(d.targets, srcIP)
	}

	return events
}

func (d *PortScanDetector) shouldSkip(ip net.IP, ipStr string) bool {
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
