package firewall

import (
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

// CSFStatus holds the current state of ConfigServer Firewall.
type CSFStatus struct {
	Installed bool   `json:"installed"`
	Version   string `json:"version,omitempty"`
	PortsIn   string `json:"ports_in,omitempty"`
	PortsOut  string `json:"ports_out,omitempty"`
	DenyCount int    `json:"deny_count"`
	AllowCount int   `json:"allow_count"`
}

var (
	csfAvailable bool
	csfOnce      sync.Once
)

// HasCSF returns true if CSF is installed on the system.
func HasCSF() bool {
	csfOnce.Do(func() {
		// Check for CSF binary
		if _, err := exec.LookPath("csf"); err == nil {
			csfAvailable = true
		} else if _, err := os.Stat("/usr/sbin/csf"); err == nil {
			csfAvailable = true
		} else if _, err := os.Stat("/usr/local/csf/bin/csf"); err == nil {
			csfAvailable = true
		}
		if csfAvailable {
			log.Println("[firewall] CSF detected")
		}
	})
	return csfAvailable
}

// CSFInfo gathers CSF status: version, open ports, deny/allow counts.
func CSFInfo() CSFStatus {
	if !HasCSF() {
		return CSFStatus{}
	}

	status := CSFStatus{Installed: true}

	// Version
	if out, err := exec.Command("csf", "-v").CombinedOutput(); err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "csf:") || strings.HasPrefix(line, "v") {
				// Extract version number from lines like "csf: v14.20" or "v14.20"
				parts := strings.Fields(line)
				for _, p := range parts {
					if strings.HasPrefix(p, "v") && len(p) > 1 {
						status.Version = strings.TrimPrefix(p, "v")
						break
					}
				}
			}
		}
	}

	// Open ports from csf.conf
	status.PortsIn = csfConfigValue("TCP_IN")
	status.PortsOut = csfConfigValue("TCP_OUT")

	// Deny list count
	status.DenyCount = csfFileLineCount("/etc/csf/csf.deny")

	// Allow list count
	status.AllowCount = csfFileLineCount("/etc/csf/csf.allow")

	return status
}

// csfConfigValue reads a value from /etc/csf/csf.conf.
func csfConfigValue(key string) string {
	data, err := os.ReadFile("/etc/csf/csf.conf")
	if err != nil {
		return ""
	}
	prefix := key + " = \""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, prefix) {
			// Extract value between quotes: TCP_IN = "22,80,443"
			val := strings.TrimPrefix(line, prefix)
			val = strings.TrimSuffix(val, "\"")
			return val
		}
	}
	return ""
}

// csfFileLineCount counts non-empty, non-comment lines in a CSF list file.
func csfFileLineCount(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		count++
	}
	return count
}

// CSFDenyList returns the IPs/CIDRs in CSF's deny list with their comments.
type CSFDenyEntry struct {
	IP      string `json:"ip"`
	Comment string `json:"comment,omitempty"`
}

func CSFDenyList() []CSFDenyEntry {
	data, err := os.ReadFile("/etc/csf/csf.deny")
	if err != nil {
		return nil
	}
	var entries []CSFDenyEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "#", 2)
		ip := strings.TrimSpace(parts[0])
		comment := ""
		if len(parts) > 1 {
			comment = strings.TrimSpace(parts[1])
		}
		if ip != "" {
			entries = append(entries, CSFDenyEntry{IP: ip, Comment: comment})
		}
	}
	return entries
}

// CSFAllowList returns the IPs/CIDRs in CSF's allow list.
func CSFAllowList() []CSFDenyEntry {
	data, err := os.ReadFile("/etc/csf/csf.allow")
	if err != nil {
		return nil
	}
	var entries []CSFDenyEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "#", 2)
		ip := strings.TrimSpace(parts[0])
		comment := ""
		if len(parts) > 1 {
			comment = strings.TrimSpace(parts[1])
		}
		if ip != "" {
			entries = append(entries, CSFDenyEntry{IP: ip, Comment: comment})
		}
	}
	return entries
}

// CSFPortAction adds or removes a port from CSF configuration.
// direction: "in" or "out", action: "add" or "remove"
func CSFPortAction(port int, direction string, action string) error {
	key := "TCP_IN"
	if direction == "out" {
		key = "TCP_OUT"
	}

	current := csfConfigValue(key)
	portStr := strconv.Itoa(port)
	ports := strings.Split(current, ",")

	if action == "add" {
		// Check if already present
		for _, p := range ports {
			if strings.TrimSpace(p) == portStr {
				return nil // already open
			}
		}
		ports = append(ports, portStr)
	} else if action == "remove" {
		var filtered []string
		for _, p := range ports {
			if strings.TrimSpace(p) != portStr {
				filtered = append(filtered, p)
			}
		}
		ports = filtered
	}

	newValue := strings.Join(ports, ",")

	// Use csf --profile to apply changes safely
	// First update the config, then restart CSF
	if err := csfSetConfigValue(key, newValue); err != nil {
		return err
	}

	// Restart CSF to apply
	return exec.Command("csf", "-r").Run()
}

// csfSetConfigValue updates a value in /etc/csf/csf.conf using sed.
func csfSetConfigValue(key, value string) error {
	// Use sed to replace the line in-place
	pattern := `s/^` + key + ` = ".*"/` + key + ` = "` + value + `"/`
	return exec.Command("sed", "-i", pattern, "/etc/csf/csf.conf").Run()
}
