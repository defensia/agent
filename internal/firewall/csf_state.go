package firewall

import (
	"context"
	"os"
	"strconv"
	"strings"
)

// Caps on what readDownloadServers reports, independent of the heartbeat's
// own csf_download_servers caps (array max 10 of string max 200) — this is
// where those caps are actually enforced, on the agent side.
const (
	downloadServersMaxLines = 10
	downloadServersMaxChars = 200
)

// csfState holds the configuration/state facts COL-02 collects from
// csf.conf plus a handful of auxiliary files and one optional process
// check. Every field that can be genuinely unknown (the source itself
// doesn't say, or the check could not run) is a pointer: nil means
// "unknown", never a guessed default. This is report-only — it never
// interprets what TESTING=1 or LF_DAEMON=0 *means* for the server's health;
// that is Phase 16's job.
type csfState struct {
	Testing, AutoUpdates, LFDaemon, LFDRunning, IPv6 *bool
	AutoUpdatesCron                                  bool
	DownloadServers                                  []string
	DenyIPLimit, DenyTempIPLimit                     *int
	PortsIn, PortsOut                                string
}

// collectCSFState reads the state facts COL-02 needs from an already-parsed
// csf.conf map (vals from readCSFConf/parseCSFConf) plus the auxiliary
// files/process check that aren't part of csf.conf itself.
func collectCSFState(ctx context.Context, conf map[string]string) csfState {
	return csfState{
		Testing:         confBool(conf, "TESTING"),
		AutoUpdates:     confBool(conf, "AUTO_UPDATES"),
		LFDaemon:        confBool(conf, "LF_DAEMON"),
		LFDRunning:      lfdRunning(ctx),
		IPv6:            confBool(conf, "IPV6"),
		AutoUpdatesCron: autoUpdatesCron(),
		DownloadServers: readDownloadServers(),
		DenyIPLimit:     confInt(conf, "DENY_IP_LIMIT"),
		DenyTempIPLimit: confInt(conf, "DENY_TEMP_IP_LIMIT"),
		PortsIn:         conf["TCP_IN"],
		PortsOut:        conf["TCP_OUT"],
	}
}

// lfdRunning determines whether the lfd daemon is running, tri-state.
// Preferred path (no command run): read a pid file and check the matching
// /proc entry. Fallback (only when no pid file is readable): a single
// `systemctl is-active lfd` call, bounded by csfExecTimeout. `csf --lfd`
// itself is never used here — it just shells out to `systemctl status`
// without machine-friendly output (verified in 15-RESEARCH.md).
func lfdRunning(ctx context.Context) *bool {
	for _, p := range []string{hostPath("/var/run/lfd.pid"), hostPath("/run/lfd.pid")} {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		pid := strings.TrimSpace(string(data))
		if pid == "" {
			continue
		}
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		return lfdRunningFromProc(pid)
	}
	return lfdRunningFromSystemctl(ctx)
}

// lfdRunningFromProc inspects /proc/<pid>/cmdline then /proc/<pid>/comm for
// a process title containing "lfd" (lfd rewrites its own process title to
// "lfd - ..."). If neither is readable, the pid file is stale: false, not
// unknown — a dead pid cleanly means "not running".
func lfdRunningFromProc(pid string) *bool {
	for _, suffix := range []string{"cmdline", "comm"} {
		data, err := os.ReadFile(hostPath("/proc/" + pid + "/" + suffix))
		if err != nil {
			continue
		}
		content := strings.ToLower(strings.ReplaceAll(string(data), "\x00", " "))
		running := strings.Contains(content, "lfd")
		return &running
	}
	stale := false
	return &stale
}

// lfdRunningFromSystemctl is the fallback used only when no lfd.pid file
// could be read. A recognised status ("active" / "inactive" / "failed" /
// "unknown" / "activating") is decisive; anything else — including a
// timeout or systemctl being absent — leaves the result genuinely unknown.
func lfdRunningFromSystemctl(ctx context.Context) *bool {
	out, err := run(ctx, csfExecTimeout, "systemctl", "is-active", "lfd")
	status := strings.ToLower(strings.TrimSpace(string(out)))
	switch status {
	case "active":
		t := true
		return &t
	case "inactive", "failed", "unknown", "activating":
		f := false
		return &f
	}
	if err != nil {
		return nil
	}
	return nil
}

// readDownloadServers reads the active (non-comment, non-blank) lines of
// /etc/csf/downloadservers, capped at downloadServersMaxLines lines of at
// most downloadServersMaxChars characters each. Never nil — an absent file
// or an all-commented file both yield an empty, non-nil slice.
func readDownloadServers() []string {
	servers := []string{}
	data, err := os.ReadFile(csfPath("downloadservers"))
	if err != nil {
		return servers
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) > downloadServersMaxChars {
			line = line[:downloadServersMaxChars]
		}
		servers = append(servers, line)
		if len(servers) >= downloadServersMaxLines {
			break
		}
	}
	return servers
}

// autoUpdatesCron reports whether CSF's own daily auto-update cron job is
// installed — a fact independent of (and a cross-check against) the
// AUTO_UPDATES csf.conf flag, which cpanel-csf 16.x removes entirely.
func autoUpdatesCron() bool {
	_, err := os.Stat(hostPath("/etc/cron.d/csf_update"))
	return err == nil
}
