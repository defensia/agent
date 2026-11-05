package firewall

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// CSFStatus holds the current state of ConfigServer Firewall.
type CSFStatus struct {
	Installed  bool   `json:"installed"`
	Version    string `json:"version,omitempty"`
	PortsIn    string `json:"ports_in,omitempty"`
	PortsOut   string `json:"ports_out,omitempty"`
	DenyCount  int    `json:"deny_count"`
	AllowCount int    `json:"allow_count"`
}

var (
	csfAvailable bool
	csfOnce      sync.Once
)

// Test seams (Phase 14, LAB-04). Production values never change at runtime;
// unit tests point csfDir at internal/firewall/testdata/<fork>/ and stub csfExec.
var (
	csfDir = "/etc/csf"
	// csfExec runs every CSF command through the timeout-bounded run() choke
	// point (phase 15, COL-01) instead of a bare, unbounded exec.Command: the
	// original version had no timeout and ran inside the heartbeat goroutine,
	// so a hung `csf -v` stalled every heartbeat.
	csfExec = func(args ...string) ([]byte, error) {
		bin := csfBinaryPath()
		if bin == "" {
			bin = "csf"
		}
		return run(context.Background(), csfExecTimeout, bin, args...)
	}
)

// csfPath returns the absolute path of a file inside the CSF config dir.
func csfPath(name string) string { return filepath.Join(csfDir, name) }

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

// CSFInfo gathers CSF status: version, open ports, deny/allow counts. This
// is the synchronous compatibility path (Phase 14's lab integration tests
// call it directly inside real VMs) — everything else, including the
// heartbeat, reads CurrentCSFSnapshot() instead so it is never blocked by
// a slow csf/rpm/systemctl (phase 15, COL-03).
func CSFInfo() CSFStatus {
	return csfStatusFromSnapshot(CollectCSF(context.Background()))
}

// parseCSFVersion extracts the version number reported by `csf -v` across
// every known fork's output format (single-line "csf: vX.YY (...)", the
// multi-line Aetherinox banner, ANSI-coloured TTY banners, outputs preceded
// by a warning line, and RPM-style "-N" release suffixes like "16.34-1").
// Strips ANSI escapes first, then keeps the LAST matching line's version —
// tolerant rather than clever: an unrecognized line is simply ignored instead
// of causing an error.
func parseCSFVersion(out []byte) string {
	version := ""
	stripped := ansiRe.ReplaceAllString(string(out), "")
	for _, line := range strings.Split(stripped, "\n") {
		line = strings.TrimSpace(line)
		if m := verRe.FindStringSubmatch(line); m != nil {
			version = m[1]
		}
	}
	return version
}

// csfInfoFrom builds a CSFStatus from the raw `csf -v` output, reading the
// remaining fields (ports, deny/allow counts) from csfDir.
func csfInfoFrom(versionOut []byte) CSFStatus {
	return CSFStatus{
		Installed:  true,
		Version:    parseCSFVersion(versionOut),
		PortsIn:    csfConfigValue("TCP_IN"),
		PortsOut:   csfConfigValue("TCP_OUT"),
		DenyCount:  csfFileLineCount(csfPath("csf.deny")),
		AllowCount: csfFileLineCount(csfPath("csf.allow")),
	}
}

// csfConfigValue reads a value from csf.conf via the tolerant parser
// (csf_conf.go). Returns "" when csf.conf is unreadable or the key is absent.
func csfConfigValue(key string) string {
	vals, _, err := readCSFConf()
	if err != nil {
		return ""
	}
	return vals[key]
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
// Kind classifies the line (ip, cidr, advanced, include, other); IP is only
// ever populated for kind "ip"/"cidr" — an advanced filter line or an
// Include directive is never presented as an IP (see classifyCSFLine in
// csf_lists.go, phase 15 COL-03, for the misparse this fixes).
type CSFDenyEntry struct {
	IP      string `json:"ip"`
	Kind    string `json:"kind,omitempty"`
	Comment string `json:"comment,omitempty"`
}

func CSFDenyList() []CSFDenyEntry {
	return csfListEntries(csfPath("csf.deny"))
}

// CSFAllowList returns the IPs/CIDRs in CSF's allow list.
func CSFAllowList() []CSFDenyEntry {
	return csfListEntries(csfPath("csf.allow"))
}

// csfListEntries parses a CSF deny/allow list file through classifyCSFLine
// (csf_lists.go), preserving file order. IP is only set for kind "ip"/
// "cidr" — an advanced filter line (e.g. "tcp|in|d=22|s=1.2.3.4") or an
// Include directive is classified but never reported as an IP.
func csfListEntries(path string) []CSFDenyEntry {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var entries []CSFDenyEntry
	for _, line := range strings.Split(string(data), "\n") {
		entry, ok := classifyCSFLine(line)
		if !ok {
			continue
		}
		ip := ""
		if entry.Kind == "ip" || entry.Kind == "cidr" {
			ip = entry.Value
		}
		entries = append(entries, CSFDenyEntry{IP: ip, Kind: entry.Kind, Comment: entry.Comment})
	}
	return entries
}

// CSFPortAction adds or removes a port from CSF configuration. This is now
// a thin wrapper around SafePortChange (csf_ports.go, phase 15 COL-05),
// which replaced the old string-edited-in-place + unguarded csf -r implementation with a
// backed-up, Go-validated, atomically-written, health-checked and
// automatically-rolled-back change. direction: "in" or "out", action: "add"
// or "remove".
func CSFPortAction(port int, direction string, action string) error {
	r := SafePortChange(context.Background(), PortChangeRequest{
		Port:      port,
		Direction: direction,
		Action:    action,
	}, PortChangeOptions{})

	if r.Result == "applied" || r.Result == "unchanged" {
		return nil
	}
	return fmt.Errorf("csf port %s %d %s: %s: %v", action, port, direction, r.Reason, r.Err)
}
