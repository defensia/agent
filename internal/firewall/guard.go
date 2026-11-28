package firewall

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

// Guard decides whether any given IP may ever be handed to a firewall
// backend for a ban. It is the single place that knows about the panel
// whitelist, CSF's own allow/ignore lists, and currently logged-in admin SSH
// sessions — none of which `csf -td` itself checks (verified against real
// CSF v15.00 behaviour in 18-02's lab benchmark), and none of which the
// package's own ban API checked before this plan (only watchers did, which
// is NOT the same as the ban path never emitting the ban at all).
//
// On nftables hosts the Defensia DROP rule runs at input hook priority -10,
// BEFORE CSF's own ACCEPT rules (Phase 17) — so a Defensia ban of a
// csf.allow IP would lock that IP out even though CSF "allows" it. This
// guard is what prevents that, on every backend, regardless of which
// executor (Defensia ipset/nftables/iptables, or CSF via -td) is active.
var (
	guardMu        sync.RWMutex
	guardWhitelist []netip.Prefix

	guardCSFAllow         []netip.Prefix
	guardCSFIgnore        []netip.Prefix
	guardCSFMtimes        = map[string]time.Time{}
	guardCSFCheckedAt     time.Time
	guardHostnamesIgnored int

	// guardHasCSF is a test seam; production value is HasCSF.
	guardHasCSF = HasCSF

	// guardListRefreshEvery bounds how often csf.allow/csf.ignore mtimes are
	// re-checked, so a guardCheck call on a hot ban path is never more than
	// one stat() per file away from reflecting a live edit.
	guardListRefreshEvery = 5 * time.Second
)

// SetWhitelist replaces the panel whitelist the guard enforces. ips are
// treated as single-host prefixes (/32 or /128); cidrs that fail to parse
// are silently ignored (never a panic, never block the rest of the sync).
func SetWhitelist(ips, cidrs []string) {
	prefixes := make([]netip.Prefix, 0, len(ips)+len(cidrs))
	for _, ip := range ips {
		if p, ok := singleHostPrefix(ip); ok {
			prefixes = append(prefixes, p)
		}
	}
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil {
			prefixes = append(prefixes, p)
		} else if p, ok := singleHostPrefix(c); ok {
			prefixes = append(prefixes, p)
		}
	}

	guardMu.Lock()
	guardWhitelist = prefixes
	guardMu.Unlock()
}

func singleHostPrefix(ip string) (netip.Prefix, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return netip.Prefix{}, false
	}
	addr = addr.Unmap()
	bits := 32
	if addr.Is6() {
		bits = 128
	}

	return netip.PrefixFrom(addr, bits), true
}

// guardCheck returns (true, "") when ip may be banned, else (false, reason)
// with reason in {invalid, safe, whitelist, csf_allow, csf_ignore,
// ssh_session} — the first matching reason wins, in that priority order.
func guardCheck(ip string) (bool, string) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false, "invalid"
	}
	addr = addr.Unmap()

	parsedNetIP := net.ParseIP(addr.String())
	if parsedNetIP != nil && isSafeIP(parsedNetIP) {
		return false, "safe"
	}

	guardMu.RLock()
	whitelist := guardWhitelist
	guardMu.RUnlock()
	for _, p := range whitelist {
		if p.Contains(addr) {
			return false, "whitelist"
		}
	}

	if guardHasCSF() {
		refreshCSFLists()
		guardMu.RLock()
		allow := guardCSFAllow
		ignore := guardCSFIgnore
		guardMu.RUnlock()
		for _, p := range allow {
			if p.Contains(addr) {
				return false, "csf_allow"
			}
		}
		for _, p := range ignore {
			if p.Contains(addr) {
				return false, "csf_ignore"
			}
		}
	}

	for _, sessionIP := range cachedSSHSessionIPs() {
		if sessionIP.Unmap() == addr {
			return false, "ssh_session"
		}
	}

	return true, ""
}

// refreshCSFLists rebuilds the cached csf.allow/csf.ignore prefixes if any
// source file's mtime changed, throttled to at most once per
// guardListRefreshEvery.
func refreshCSFLists() {
	guardMu.Lock()
	defer guardMu.Unlock()

	if time.Since(guardCSFCheckedAt) < guardListRefreshEvery {
		return
	}
	guardCSFCheckedAt = time.Now()

	allowPath := csfPath("csf.allow")
	ignorePath := csfPath("csf.ignore")

	allowChanged := fileChanged(allowPath, guardCSFMtimes)
	ignoreChanged := fileChanged(ignorePath, guardCSFMtimes)
	if !allowChanged && !ignoreChanged {
		// Neither source file's mtime moved since the last build (fileChanged
		// also returns true on the very first call for any never-seen path,
		// so this never skips the initial build).
		return
	}

	hostnames := 0
	guardCSFAllow = parseCSFList(allowPath, 0, map[string]bool{}, &hostnames)
	guardCSFIgnore = parseCSFList(ignorePath, 0, map[string]bool{}, &hostnames)
	guardHostnamesIgnored = hostnames
}

// fileChanged records fp's current mtime under mtimes[fp] and reports
// whether it differs from the previously recorded value (missing file ->
// zero time, also tracked so a file appearing/disappearing counts as a
// change).
func fileChanged(path string, mtimes map[string]time.Time) bool {
	var mt time.Time
	if st, err := os.Stat(path); err == nil {
		mt = st.ModTime()
	}
	prev, known := mtimes[path]
	mtimes[path] = mt
	return !known || !prev.Equal(mt)
}

// parseCSFList parses one CSF allow/ignore-style file: one entry per line,
// `#` strips trailing comments, blank lines skipped, `Include <path>`
// recurses (depth-capped, cycle-guarded by path), advanced filter syntax
// (`tcp|in|d=22|s=1.2.3.4`) contributes only its `s=` (source) value — `d=`/
// `u=`/`g=` never describe an IP that must not be banned. A bare token that
// is not an IP/CIDR is assumed to be a hostname (CSF supports csf.dyndns-
// style entries here); the guard does not resolve DNS, so it is ignored and
// counted via hostnames.
func parseCSFList(path string, depth int, seen map[string]bool, hostnames *int) []netip.Prefix {
	if depth > 5 || seen[path] {
		return nil
	}
	seen[path] = true

	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []netip.Prefix
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)

	for sc.Scan() {
		line := sc.Text()
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "Include ") || strings.HasPrefix(line, "include ") {
			incPath := strings.TrimSpace(line[len("Include "):])
			out = append(out, parseCSFList(incPath, depth+1, seen, hostnames)...)
			continue
		}

		if strings.Contains(line, "|") {
			// Advanced filter: tcp|in|d=22|s=1.2.3.4 (or s=1.2.3.0/24).
			// u=/g= entries describe outbound user/group rules, never an IP.
			for _, part := range strings.Split(line, "|") {
				if strings.HasPrefix(part, "s=") {
					if p, ok := parseIPOrCIDR(part[2:]); ok {
						out = append(out, p)
					}
				}
			}
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		token := fields[0]
		if p, ok := parseIPOrCIDR(token); ok {
			out = append(out, p)
		} else {
			*hostnames++
		}
	}

	return out
}

func parseIPOrCIDR(s string) (netip.Prefix, bool) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, true
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return singleHostPrefix(addr.String())
	}

	return netip.Prefix{}, false
}

// --- SSH session protection -------------------------------------------------

// activeSSHSessionIPs is the test seam (tests reassign this var directly);
// production default is defaultActiveSSHSessionIPs (platform-specific, see
// guard_sessions_*.go). cachedSSHSessionIPs() is what guardCheck actually
// calls: it caches the result for sshSessionCacheTTL so a hot ban path never
// re-reads utmp/loginctl on every single call.
//
// Deliberately NOT based on `ss state established`: a brute-forcer holds an
// established TCP connection to sshd for the whole duration of its guessing
// attempts, so using "established" as the signal would protect the
// attacker, not the admin. utmp/logind sessions only exist after a
// successful authentication.
var activeSSHSessionIPs = defaultActiveSSHSessionIPs

const sshSessionCacheTTL = 10 * time.Second

var (
	sshSessionCacheMu   sync.Mutex
	sshSessionCacheAt   time.Time
	sshSessionCacheData []netip.Addr
)

func cachedSSHSessionIPs() []netip.Addr {
	sshSessionCacheMu.Lock()
	defer sshSessionCacheMu.Unlock()

	if time.Since(sshSessionCacheAt) < sshSessionCacheTTL {
		return sshSessionCacheData
	}

	sshSessionCacheData = activeSSHSessionIPs()
	sshSessionCacheAt = time.Now()

	return sshSessionCacheData
}

// --- Chokepoint enforcement (phase 18-04 Task 3) ----------------------------

// ErrProtectedIP is returned when a ban is refused because the guard
// protects the IP (whitelist, csf.allow, csf.ignore, or an active SSH
// session) — distinct from ErrNoBackend, which means there was simply no
// backend to apply the ban to.
var ErrProtectedIP = errors.New("refusing to ban protected IP")

// admitBan is the single admission point every ban passes through before it
// reaches a backend's Ban/BanBatch (wired into backend.go's BanIPFor and
// ApplyBanEntries — the Phase 17 choke point BanIP/ApplyBans already
// delegate to). On nftables hosts the Defensia drop runs at input hook
// priority -10, BEFORE CSF's own ACCEPT rules, so this is what actually
// protects csf.allow/csf.ignore/whitelist/SSH-session IPs on every
// executor: a ban refused here never becomes an nft/ipset/iptables command.
func admitBan(ip string, path string) error {
	ok, reason := guardCheck(ip)
	if ok || reason == "safe" || reason == "invalid" {
		// "safe"/"invalid" are already handled by BanIPFor/ApplyBanEntries
		// with Phase 17's own existing semantics (refusing to ban safe IP /
		// invalid IP address) — admitBan must not duplicate or override them.
		return nil
	}

	notifyBanSkipped(ip, reason, path)

	return fmt.Errorf("%w (%s): %s", ErrProtectedIP, reason, ip)
}

// guardNow is a test seam; production value is time.Now.
var guardNow = time.Now

const banSkippedDedupeWindow = time.Hour

const banSkippedMaxTracked = 10_000

var (
	banSkippedHandler func(ip, reason, path string)
	banSkippedMu      sync.Mutex
	banSkippedLastAt  = map[string]time.Time{}
)

// SetBanSkippedHandler registers fn to be called (at most once per
// ip+reason per hour) whenever admitBan refuses a ban. Plan 09 wires this to
// emit a ban_skipped_protected event. Passing nil disables it.
func SetBanSkippedHandler(fn func(ip, reason, path string)) {
	banSkippedMu.Lock()
	banSkippedHandler = fn
	banSkippedMu.Unlock()
}

func notifyBanSkipped(ip, reason, path string) {
	key := ip + "|" + reason

	banSkippedMu.Lock()
	now := guardNow()
	last, seen := banSkippedLastAt[key]
	dueForLog := !seen || now.Sub(last) >= banSkippedDedupeWindow
	if dueForLog {
		banSkippedLastAt[key] = now
		if len(banSkippedLastAt) > banSkippedMaxTracked {
			banSkippedLastAt = map[string]time.Time{key: now}
		}
	}
	handler := banSkippedHandler
	banSkippedMu.Unlock()

	if !dueForLog {
		return
	}

	log.Printf("[firewall] refusing to ban %s: protected (%s)", ip, reason)
	if handler != nil {
		handler(ip, reason, path)
	}
}
