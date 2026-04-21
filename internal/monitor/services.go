package monitor

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const tcpListen = 0x0A

// ListeningService represents a TCP port in LISTEN state with its owning process.
type ListeningService struct {
	Port    int    `json:"port"`
	Process string `json:"process"`
	Proto   string `json:"proto"` // "tcp" or "tcp6"
}

// DetectListeningServices reads /proc/net/tcp and /proc/net/tcp6 for LISTEN sockets,
// resolves the owning process via /proc/*/fd, and returns a deduplicated list.
func DetectListeningServices() []ListeningService {
	// Build inode→pid map
	inodePID := buildInodePIDMap()

	seen := make(map[int]bool)
	var result []ListeningService

	for _, proto := range []string{"tcp", "tcp6"} {
		path := "/proc/net/" + proto
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		for i, line := range strings.Split(string(data), "\n") {
			if i == 0 || strings.TrimSpace(line) == "" {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}

			// State is field[3]
			state, err := strconv.ParseUint(fields[3], 16, 8)
			if err != nil || state != tcpListen {
				continue
			}

			// Parse local address for port
			localParts := strings.SplitN(fields[1], ":", 2)
			if len(localParts) != 2 {
				continue
			}
			port64, err := strconv.ParseUint(localParts[1], 16, 16)
			if err != nil {
				continue
			}
			port := int(port64)

			if seen[port] {
				continue
			}
			seen[port] = true

			// Resolve process name via inode (field[9])
			inode := fields[9]
			process := ""
			if pid, ok := inodePID[inode]; ok {
				process = readProcessName(pid)
			}

			result = append(result, ListeningService{
				Port:    port,
				Process: process,
				Proto:   proto,
			})
		}
	}

	return result
}

// buildInodePIDMap scans /proc/*/fd to build a map of socket inode → PID.
func buildInodePIDMap() map[string]int {
	m := make(map[string]int)

	procs, err := os.ReadDir("/proc")
	if err != nil {
		return m
	}

	for _, entry := range procs {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			// socket:[12345]
			if strings.HasPrefix(link, "socket:[") {
				inode := link[8 : len(link)-1]
				m[inode] = pid
			}
		}
	}

	return m
}

// readProcessName reads the process name from /proc/{pid}/comm.
func readProcessName(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
