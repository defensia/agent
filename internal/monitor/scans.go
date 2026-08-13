package monitor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ScanResult holds a single monitor run result to be reported to the panel.
type ScanResult struct {
	Monitor    string            `json:"monitor"`    // port_scan, flood, integrity_change
	Detections int               `json:"detections"`
	Summary    map[string]string `json:"summary"`
	RanAt      string            `json:"ran_at"`
}

// ── Port Scan Detection ──────────────────────────────────────────────

// PortScanDetector watches for SYN_RECV connections that indicate someone is probing ports.
type PortScanDetector struct {
	mu       sync.Mutex
	history  map[string]int // IP → distinct port count from previous cycle
}

func NewPortScanDetector() *PortScanDetector {
	return &PortScanDetector{history: make(map[string]int)}
}

// Run checks current SYN_RECV connections and detects port scanning.
func (d *PortScanDetector) Run() ScanResult {
	result := ScanResult{
		Monitor: "port_scan",
		RanAt:   time.Now().UTC().Format(time.RFC3339),
		Summary: make(map[string]string),
	}

	// Get SYN_RECV connections from ss
	out, err := exec.Command("ss", "-tn", "state", "syn-recv").CombinedOutput()
	if err != nil {
		// Fallback: try netstat
		out, err = exec.Command("netstat", "-tn").CombinedOutput()
		if err != nil {
			result.Summary["error"] = "cannot read connections"
			return result
		}
	}

	// Parse: count unique destination ports per source IP
	ipPorts := make(map[string]map[int]bool) // srcIP → set of dst ports
	totalChecked := 0

	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// ss format: State Recv-Q Send-Q Local:Port Peer:Port
		// netstat format: Proto Recv-Q Send-Q Local Peer State
		var localAddr, peerAddr string
		if strings.Contains(line, "SYN") || strings.Contains(line, "syn-recv") || strings.Contains(line, "SYN_RECV") {
			// Find the addresses
			for _, f := range fields {
				if strings.Contains(f, ":") && !strings.HasPrefix(f, "SYN") {
					if localAddr == "" {
						localAddr = f
					} else if peerAddr == "" {
						peerAddr = f
					}
				}
			}
		} else {
			continue
		}

		if localAddr == "" || peerAddr == "" {
			continue
		}
		totalChecked++

		// Extract source IP and destination port
		srcIP := extractIP(peerAddr)
		dstPort := extractPort(localAddr)
		if srcIP == "" || dstPort == 0 {
			continue
		}

		if ipPorts[srcIP] == nil {
			ipPorts[srcIP] = make(map[int]bool)
		}
		ipPorts[srcIP][dstPort] = true
	}

	// Detect: IP hitting >5 distinct ports = port scan
	detections := 0
	scanners := []string{}
	for ip, ports := range ipPorts {
		if len(ports) >= 5 {
			detections++
			scanners = append(scanners, fmt.Sprintf("%s(%d ports)", ip, len(ports)))
		}
	}

	result.Detections = detections
	result.Summary["syn_recv"] = strconv.Itoa(totalChecked)
	result.Summary["unique_ips"] = strconv.Itoa(len(ipPorts))
	result.Summary["connections_checked"] = strconv.Itoa(totalChecked)
	if len(scanners) > 0 {
		result.Summary["scanners"] = strings.Join(scanners, ", ")
		log.Printf("[monitor-portscan] detected %d port scanners: %s", detections, result.Summary["scanners"])
	}

	return result
}

// ── Flood / DDoS Detection ──────────────────────────────────────────

// FloodDetector watches for abnormal connection spikes.
type FloodDetector struct {
	mu       sync.Mutex
	baseline []int // rolling window of total connection counts
}

func NewFloodDetector() *FloodDetector {
	return &FloodDetector{baseline: make([]int, 0, 10)}
}

// Run counts active connections and detects abnormal spikes.
func (d *FloodDetector) Run() ScanResult {
	result := ScanResult{
		Monitor: "flood",
		RanAt:   time.Now().UTC().Format(time.RFC3339),
		Summary: make(map[string]string),
	}

	// Count established TCP connections
	out, err := exec.Command("ss", "-tn", "state", "established").CombinedOutput()
	if err != nil {
		result.Summary["error"] = "cannot read connections"
		return result
	}

	// Count connections per IP
	ipConns := make(map[string]int)
	total := 0
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// Skip header
		if strings.HasPrefix(line, "Recv") || strings.HasPrefix(line, "State") {
			continue
		}
		total++

		// Extract peer IP
		peerField := ""
		for i := len(fields) - 1; i >= 0; i-- {
			if strings.Contains(fields[i], ":") {
				peerField = fields[i]
				break
			}
		}
		srcIP := extractIP(peerField)
		if srcIP != "" && !isPrivateIP(srcIP) {
			ipConns[srcIP]++
		}
	}

	// Update baseline (rolling window of 10)
	d.mu.Lock()
	d.baseline = append(d.baseline, total)
	if len(d.baseline) > 10 {
		d.baseline = d.baseline[len(d.baseline)-10:]
	}
	avg := 0
	for _, c := range d.baseline {
		avg += c
	}
	if len(d.baseline) > 0 {
		avg = avg / len(d.baseline)
	}
	d.mu.Unlock()

	// Detect: single IP with >100 connections or total >5x baseline
	detections := 0
	flooders := []string{}
	for ip, count := range ipConns {
		if count > 100 {
			detections++
			flooders = append(flooders, fmt.Sprintf("%s(%d conns)", ip, count))
		}
	}

	if avg > 0 && total > avg*5 && total > 200 {
		detections++
		result.Summary["spike"] = fmt.Sprintf("total %d vs avg %d (%.1fx)", total, avg, float64(total)/float64(avg))
		log.Printf("[monitor-flood] connection spike: %s", result.Summary["spike"])
	}

	result.Detections = detections
	result.Summary["total_connections"] = strconv.Itoa(total)
	result.Summary["unique_ips"] = strconv.Itoa(len(ipConns))
	result.Summary["baseline_avg"] = strconv.Itoa(avg)
	if len(flooders) > 0 {
		result.Summary["flooders"] = strings.Join(flooders, ", ")
		log.Printf("[monitor-flood] detected %d flooders: %s", detections, result.Summary["flooders"])
	}

	return result
}

// ── File Integrity Monitor ──────────────────────────────────────────

// Critical system files to monitor.
var integrityFiles = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/group",
	"/etc/sudoers",
	"/etc/ssh/sshd_config",
	"/etc/crontab",
	"/etc/hosts",
	"/etc/hosts.allow",
	"/etc/hosts.deny",
	"/etc/resolv.conf",
}

// IntegrityMonitor tracks SHA-256 checksums of critical files.
type IntegrityMonitor struct {
	mu        sync.Mutex
	checksums map[string]string // filepath → sha256
	firstRun  bool
}

func NewIntegrityMonitor() *IntegrityMonitor {
	return &IntegrityMonitor{
		checksums: make(map[string]string),
		firstRun:  true,
	}
}

// Run calculates checksums and detects changes.
func (m *IntegrityMonitor) Run() ScanResult {
	result := ScanResult{
		Monitor: "integrity_change",
		RanAt:   time.Now().UTC().Format(time.RFC3339),
		Summary: make(map[string]string),
	}

	current := make(map[string]string)
	for _, path := range integrityFiles {
		hash, err := sha256File(path)
		if err != nil {
			continue // file doesn't exist, skip
		}
		current[path] = hash
	}

	result.Summary["files_monitored"] = strconv.Itoa(len(current))

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.firstRun {
		// First run: establish baseline, no detections
		m.checksums = current
		m.firstRun = false
		result.Summary["status"] = "baseline_established"
		log.Printf("[monitor-integrity] baseline established for %d files", len(current))
		return result
	}

	// Compare with previous checksums
	changed := []string{}
	for path, newHash := range current {
		oldHash, existed := m.checksums[path]
		if existed && oldHash != newHash {
			changed = append(changed, path)
			log.Printf("[monitor-integrity] CHANGED: %s (was %s, now %s)", path, oldHash[:12], newHash[:12])
		}
	}

	// Check for deleted files
	for path := range m.checksums {
		if _, exists := current[path]; !exists {
			changed = append(changed, path+" (deleted)")
			log.Printf("[monitor-integrity] DELETED: %s", path)
		}
	}

	// Update stored checksums
	m.checksums = current

	result.Detections = len(changed)
	if len(changed) > 0 {
		result.Summary["changed_files"] = strings.Join(changed, ", ")
	}

	return result
}

// ── Helpers ──────────────────────────────────────────────────────────

func sha256File(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

func extractIP(addr string) string {
	// Handle [IPv6]:port and IPv4:port
	if strings.HasPrefix(addr, "[") {
		// IPv6: [::1]:22
		end := strings.Index(addr, "]")
		if end > 0 {
			return addr[1:end]
		}
		return ""
	}
	// IPv4: 1.2.3.4:22
	lastColon := strings.LastIndex(addr, ":")
	if lastColon > 0 {
		return addr[:lastColon]
	}
	return addr
}

func extractPort(addr string) int {
	lastColon := strings.LastIndex(addr, ":")
	if lastColon < 0 || lastColon >= len(addr)-1 {
		return 0
	}
	p, err := strconv.Atoi(addr[lastColon+1:])
	if err != nil {
		return 0
	}
	return p
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}
