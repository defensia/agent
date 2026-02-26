package monitor

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// SystemMetrics holds a snapshot of server resource usage.
type SystemMetrics struct {
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryTotal   uint64  `json:"memory_total"`
	MemoryUsed    uint64  `json:"memory_used"`
	MemoryPercent float64 `json:"memory_percent"`
	DiskTotal     uint64  `json:"disk_total"`
	DiskUsed      uint64  `json:"disk_used"`
	DiskPercent   float64 `json:"disk_percent"`
	LoadAvg1      float64 `json:"load_avg_1"`
	LoadAvg5      float64 `json:"load_avg_5"`
	LoadAvg15     float64 `json:"load_avg_15"`
	NetBytesIn    uint64  `json:"net_bytes_in"`
	NetBytesOut   uint64  `json:"net_bytes_out"`
}

// cpuTimes holds raw CPU jiffies from /proc/stat.
type cpuTimes struct {
	idle  uint64
	total uint64
}

// MetricsCollector gathers system metrics. It keeps state between
// calls so it can compute deltas for CPU and network.
type MetricsCollector struct {
	prevCPU cpuTimes
	prevNet struct {
		bytesIn  uint64
		bytesOut uint64
	}
	hasPrev bool
}

// NewMetricsCollector creates a collector and takes an initial
// reading so the first real Collect() can compute deltas.
func NewMetricsCollector() *MetricsCollector {
	mc := &MetricsCollector{}
	// Seed initial CPU and network values
	mc.prevCPU = readCPUTimes()
	mc.prevNet.bytesIn, mc.prevNet.bytesOut = readNetBytes()
	mc.hasPrev = true
	return mc
}

// Collect gathers all system metrics. Safe to call every 60s.
func (mc *MetricsCollector) Collect() SystemMetrics {
	m := SystemMetrics{}

	// CPU
	cur := readCPUTimes()
	if mc.hasPrev && cur.total > mc.prevCPU.total {
		deltaTotal := cur.total - mc.prevCPU.total
		deltaIdle := cur.idle - mc.prevCPU.idle
		m.CPUPercent = float64(deltaTotal-deltaIdle) / float64(deltaTotal) * 100
	}
	mc.prevCPU = cur

	// Memory
	m.MemoryTotal, m.MemoryUsed, m.MemoryPercent = readMemory()

	// Disk (root partition)
	m.DiskTotal, m.DiskUsed, m.DiskPercent = readDisk("/")

	// Load average
	m.LoadAvg1, m.LoadAvg5, m.LoadAvg15 = readLoadAvg()

	// Network
	curIn, curOut := readNetBytes()
	if mc.hasPrev {
		if curIn >= mc.prevNet.bytesIn {
			m.NetBytesIn = curIn - mc.prevNet.bytesIn
		}
		if curOut >= mc.prevNet.bytesOut {
			m.NetBytesOut = curOut - mc.prevNet.bytesOut
		}
	}
	mc.prevNet.bytesIn = curIn
	mc.prevNet.bytesOut = curOut

	mc.hasPrev = true
	return m
}

// readCPUTimes parses /proc/stat for aggregate CPU jiffies.
func readCPUTimes() cpuTimes {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return cpuTimes{}
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return cpuTimes{}
	}

	// First line: "cpu  user nice system idle iowait irq softirq steal ..."
	fields := strings.Fields(scanner.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuTimes{}
	}

	var total, idle uint64
	for i := 1; i < len(fields); i++ {
		v, _ := strconv.ParseUint(fields[i], 10, 64)
		total += v
		if i == 4 { // idle is the 4th value (index 4 in fields)
			idle = v
		}
	}

	return cpuTimes{idle: idle, total: total}
}

// readMemory parses /proc/meminfo.
func readMemory() (total, used uint64, percent float64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer f.Close()

	var memTotal, memAvailable uint64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			memTotal = parseMemInfoValue(line)
		} else if strings.HasPrefix(line, "MemAvailable:") {
			memAvailable = parseMemInfoValue(line)
			break // MemAvailable comes after MemTotal, so we're done
		}
	}

	total = memTotal * 1024 // kB to bytes
	if memTotal > 0 {
		used = (memTotal - memAvailable) * 1024
		percent = float64(memTotal-memAvailable) / float64(memTotal) * 100
	}
	return
}

// parseMemInfoValue extracts the numeric kB value from a /proc/meminfo line.
func parseMemInfoValue(line string) uint64 {
	fields := strings.Fields(line)
	if len(fields) >= 2 {
		v, _ := strconv.ParseUint(fields[1], 10, 64)
		return v
	}
	return 0
}

// readDisk uses syscall.Statfs to get disk usage for a mount point.
func readDisk(path string) (total, used uint64, percent float64) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return
	}

	total = stat.Blocks * uint64(stat.Bsize)
	free := stat.Bfree * uint64(stat.Bsize)
	used = total - free
	if total > 0 {
		percent = float64(used) / float64(total) * 100
	}
	return
}

// readLoadAvg parses /proc/loadavg.
func readLoadAvg() (avg1, avg5, avg15 float64) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return
	}

	fields := strings.Fields(string(data))
	if len(fields) >= 3 {
		avg1, _ = strconv.ParseFloat(fields[0], 64)
		avg5, _ = strconv.ParseFloat(fields[1], 64)
		avg15, _ = strconv.ParseFloat(fields[2], 64)
	}
	return
}

// readNetBytes sums rx/tx bytes across all non-loopback interfaces from /proc/net/dev.
func readNetBytes() (bytesIn, bytesOut uint64) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum <= 2 {
			continue // skip header lines
		}

		line := scanner.Text()
		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			continue
		}

		iface := strings.TrimSpace(line[:colonIdx])
		if iface == "lo" {
			continue
		}

		fields := strings.Fields(line[colonIdx+1:])
		if len(fields) < 10 {
			continue
		}

		// fields[0] = rx bytes, fields[8] = tx bytes
		rx, _ := strconv.ParseUint(fields[0], 10, 64)
		tx, _ := strconv.ParseUint(fields[8], 10, 64)
		bytesIn += rx
		bytesOut += tx
	}

	return
}

// FormatBytes returns a human-readable string for a byte count.
func FormatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
