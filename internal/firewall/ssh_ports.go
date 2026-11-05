package firewall

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// activeSSHPorts answers one question for the CSF port guard: "which TCP
// ports could sshd be listening on right now?" It errs on the side of
// refusing a port change: every source below is attempted independently and
// the RESULT IS THE UNION, never a single source's answer — a false
// negative here (a port sshd actually uses but we fail to notice) is how a
// customer gets locked out of their own machine.
//
// Sources, in the order recommended by 15-RESEARCH.md Pattern 4:
//   - sshd-T:         `sshd -T` effective config dump (honours Match blocks,
//     Include directives, multiple Port lines)
//   - ss:             listening sockets owned by a process named sshd
//   - ss-established: sockets with an ESTABLISHED sshd connection (catches a
//     port sshd is actively serving even if `-T`/`ss -l` disagree)
//   - config:         a direct read of sshd_config(.d) as a last-resort
//     fallback when the commands above are unavailable or produce nothing
//   - default:        port 22, used only when every other source found
//     nothing at all
//
// A source only contributes its name to sources when it actually found at
// least one port — this keeps the returned evidence honest ("ss" means ss
// actually told us about a listening sshd, not merely that it ran).
func activeSSHPorts(ctx context.Context) (ports []int, sources []string) {
	found := map[int]bool{}
	var srcList []string
	addSource := func(name string) {
		for _, s := range srcList {
			if s == name {
				return
			}
		}
		srcList = append(srcList, name)
	}
	addPorts := func(ps []int, source string) {
		any := false
		for _, p := range ps {
			if p < 1 || p > 65535 {
				continue
			}
			found[p] = true
			any = true
		}
		if any {
			addSource(source)
		}
	}

	addPorts(sshPortsFromSshdT(ctx), "sshd-T")
	addPorts(sshPortsFromSSListen(ctx), "ss")
	addPorts(sshPortsFromSSEstablished(ctx), "ss-established")
	addPorts(sshPortsFromConfig(), "config")

	if len(found) == 0 {
		addPorts([]int{22}, "default")
	}

	ports = make([]int, 0, len(found))
	for p := range found {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	sort.Strings(srcList)
	return ports, srcList
}

// sshdTPortRe matches a `sshd -T` effective-config line "port N" (lower
// case, as sshd -T itself emits every directive name lower-cased).
var sshdTPortRe = regexp.MustCompile(`(?i)^port\s+(\d+)\s*$`)

// sshBinaryPath locates the sshd binary: PATH first, then the two paths it
// ships at on every distro the agent targets. Mirrors csfBinaryPath's
// no-cache, re-check-every-call behaviour.
func sshBinaryPath() string {
	if p, err := lookPath("sshd"); err == nil {
		return p
	}
	for _, candidate := range []string{"/usr/sbin/sshd", "/usr/bin/sshd"} {
		p := hostPath(candidate)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// ssBinaryPath locates the ss binary the same way.
func ssBinaryPath() string {
	if p, err := lookPath("ss"); err == nil {
		return p
	}
	for _, candidate := range []string{"/usr/sbin/ss", "/usr/bin/ss"} {
		p := hostPath(candidate)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// sshPortsFromSshdT runs `sshd -T` and extracts every "port N" line from its
// effective configuration dump. Returns nil (not an error) when sshd cannot
// be located or the command fails — activeSSHPorts treats that as "this
// source found nothing", not as a reason to stop trying the others.
func sshPortsFromSshdT(ctx context.Context) []int {
	bin := sshBinaryPath()
	if bin == "" {
		return nil
	}
	out, err := run(ctx, csfExecTimeout, bin, "-T")
	if err != nil {
		return nil
	}
	var ports []int
	for _, line := range strings.Split(string(out), "\n") {
		if m := sshdTPortRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			if p, err := strconv.Atoi(m[1]); err == nil {
				ports = append(ports, p)
			}
		}
	}
	return ports
}

// sshPortsFromSSListen runs `ss -H -ltnp` and keeps the local port of every
// LISTEN socket whose process field names sshd.
func sshPortsFromSSListen(ctx context.Context) []int {
	bin := ssBinaryPath()
	if bin == "" {
		return nil
	}
	out, err := run(ctx, csfExecTimeout, bin, "-H", "-ltnp")
	if err != nil {
		return nil
	}
	return parseSSPortsForSSHD(string(out))
}

// sshPortsFromSSEstablished runs `ss -H -tnp state established` and keeps
// the LOCAL port of every established socket owned by sshd — this catches a
// port sshd is actively serving a connection on even when the listen-socket
// view disagrees (e.g. a race during a reload).
func sshPortsFromSSEstablished(ctx context.Context) []int {
	bin := ssBinaryPath()
	if bin == "" {
		return nil
	}
	out, err := run(ctx, csfExecTimeout, bin, "-H", "-tnp", "state", "established")
	if err != nil {
		return nil
	}
	return parseSSPortsForSSHD(string(out))
}

// parseSSPortsForSSHD parses `ss -H ...` tabular output shared by both the
// listen and established queries: columns are
// "<state> <recv-q> <send-q> <local addr:port> <peer addr:port> <process>",
// and only lines whose process field mentions "sshd" are kept.
func parseSSPortsForSSHD(out string) []int {
	var ports []int
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, `"sshd"`) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if p, ok := sshPortFromAddr(fields[3]); ok {
			ports = append(ports, p)
		}
	}
	return ports
}

// sshPortFromAddr extracts the port from an `ss` local-address field, which
// may be "0.0.0.0:2200", "*:22", "[::]:22" or a plain "10.0.0.5:2201" — in
// every case the port is whatever follows the LAST colon.
func sshPortFromAddr(addr string) (int, bool) {
	idx := strings.LastIndex(addr, ":")
	if idx < 0 || idx == len(addr)-1 {
		return 0, false
	}
	p, err := strconv.Atoi(addr[idx+1:])
	if err != nil {
		return 0, false
	}
	return p, true
}

// sshdConfigPortRe matches a `Port N` directive in sshd_config(.d), case
// insensitive (sshd_config directives are case-insensitive).
var sshdConfigPortRe = regexp.MustCompile(`(?i)^\s*port\s+(\d+)\s*$`)

// sshPortsFromConfig is the last-resort fallback: a direct read of
// sshd_config plus every *.conf under sshd_config.d, used only when sshd -T
// and ss both fail to tell us anything (no privileges, no /run/sshd, a
// container without those binaries at all).
func sshPortsFromConfig() []int {
	var ports []int
	ports = append(ports, parsePortsFromFile(hostPath("/etc/ssh/sshd_config"))...)

	matches, _ := filepath.Glob(hostPath("/etc/ssh/sshd_config.d/*.conf"))
	sort.Strings(matches)
	for _, m := range matches {
		ports = append(ports, parsePortsFromFile(m)...)
	}
	return ports
}

// parsePortsFromFile extracts every "Port N" directive from a single
// sshd_config-style file. A missing/unreadable file simply contributes
// nothing.
func parsePortsFromFile(path string) []int {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var ports []int
	for _, line := range strings.Split(string(data), "\n") {
		if m := sshdConfigPortRe.FindStringSubmatch(line); m != nil {
			if p, err := strconv.Atoi(m[1]); err == nil {
				ports = append(ports, p)
			}
		}
	}
	return ports
}
