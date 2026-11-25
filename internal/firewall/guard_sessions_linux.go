//go:build linux

package firewall

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"
)

// utmpPaths is a test seam; production checks /var/run/utmp then
// /run/utmp (whichever exists first).
var utmpPaths = []string{"/var/run/utmp", "/run/utmp"}

// defaultActiveSSHSessionIPs returns the source IPs of currently logged-in
// sessions (USER_PROCESS records in utmp, see guard_utmp.go for the record
// layout and parser), falling back to `loginctl` if no utmp file is present
// (some minimal/container-ish hosts run systemd-logind without a legacy
// utmp file at all).
func defaultActiveSSHSessionIPs() []netip.Addr {
	for _, p := range utmpPaths {
		data, err := os.ReadFile(p)
		if err == nil {
			return parseUtmp(data)
		}
	}

	return loginctlSessionIPs()
}

// loginctlSessionIPs is the fallback when no utmp file exists at all. One
// 3-second deadline governs the whole operation (the list call plus every
// per-session show-session call), not 3 seconds per call.
func loginctlSessionIPs() []netip.Addr {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "loginctl", "list-sessions", "--no-legend").Output()
	if err != nil {
		return nil
	}

	var ips []netip.Addr
	for _, line := range strings.Split(string(out), "\n") {
		if ctx.Err() != nil {
			break
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		sessionID := fields[0]

		rhOut, rhErr := exec.CommandContext(ctx, "loginctl", "show-session", sessionID, "-p", "RemoteHost", "--value").Output()
		if rhErr != nil {
			continue
		}
		host := strings.TrimSpace(string(rhOut))
		if host == "" {
			continue
		}
		if addr, err := netip.ParseAddr(host); err == nil {
			ips = append(ips, addr)
		}
	}

	return ips
}
