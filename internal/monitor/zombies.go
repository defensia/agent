package monitor

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ZombieProcess represents a single zombie process found on the system.
type ZombieProcess struct {
	PID        int    `json:"pid"`
	PPID       int    `json:"ppid"`
	Command    string `json:"command"`
	ParentCmd  string `json:"parent_command"`
}

// ZombieReport is the result of a zombie process scan.
type ZombieReport struct {
	Count      int                        `json:"count"`
	Zombies    []ZombieProcess            `json:"zombies"`
	ParentPIDs map[int]int                `json:"parent_pids"` // ppid -> count of zombies
	Parents    map[int]string             `json:"parents"`     // ppid -> command name
}

// ScanZombies reads /proc to find all zombie processes and their parents.
func ScanZombies() ZombieReport {
	report := ZombieReport{
		ParentPIDs: make(map[int]int),
		Parents:    make(map[int]string),
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return report
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // not a PID directory
		}

		statusPath := filepath.Join("/proc", entry.Name(), "status")
		data, err := os.ReadFile(statusPath)
		if err != nil {
			continue
		}

		state, ppid, name := parseStatus(string(data))
		if state != "Z" {
			continue
		}

		parentCmd := readComm(ppid)

		z := ZombieProcess{
			PID:       pid,
			PPID:      ppid,
			Command:   name,
			ParentCmd: parentCmd,
		}

		report.Zombies = append(report.Zombies, z)
		report.Count++
		report.ParentPIDs[ppid]++
		if _, ok := report.Parents[ppid]; !ok {
			report.Parents[ppid] = parentCmd
		}
	}

	return report
}

// Severity returns the alert severity based on zombie count.
func (r ZombieReport) Severity() string {
	switch {
	case r.Count >= 20:
		return "critical"
	case r.Count >= 6:
		return "warning"
	case r.Count >= 1:
		return "info"
	default:
		return ""
	}
}

// TopParents returns a summary of parent processes with the most zombies (up to n).
func (r ZombieReport) TopParents(n int) []string {
	type entry struct {
		pid   int
		name  string
		count int
	}

	var entries []entry
	for pid, count := range r.ParentPIDs {
		entries = append(entries, entry{pid, r.Parents[pid], count})
	}

	// Simple sort by count descending
	for i := 0; i < len(entries); i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[j].count > entries[i].count {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}

	if len(entries) > n {
		entries = entries[:n]
	}

	var result []string
	for _, e := range entries {
		result = append(result, fmt.Sprintf("%s(pid=%d): %d zombies", e.name, e.pid, e.count))
	}
	return result
}

// parseStatus extracts State, PPid, and Name from /proc/[pid]/status content.
func parseStatus(content string) (state string, ppid int, name string) {
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "State:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				state = fields[1]
			}
		} else if strings.HasPrefix(line, "PPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				ppid, _ = strconv.Atoi(fields[1])
			}
		} else if strings.HasPrefix(line, "Name:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				name = fields[1]
			}
		}
	}
	return
}

// readComm reads /proc/[pid]/comm to get the process command name.
func readComm(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}
