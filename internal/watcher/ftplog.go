package watcher

import (
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FTPPattern pairs a compiled regex with the event reason, the daemon whose log
// format it recognises, and what the line says went wrong. The last two are not
// recoverable from the line afterwards, so they are recorded here.
type FTPPattern struct {
	Re     *regexp.Regexp
	Reason string
	Daemon string
	Detail string
}

// ftpPatterns contains all FTP auth detection patterns.
// Each regex must have a capture group for the IP address.
//
// vsftpd:
//   - "FAIL LOGIN: Client \"X.X.X.X\""
//
// ProFTPD:
//   - "(user[X.X.X.X])...USER ...Login failed"
//   - "proftpd...[X.X.X.X]...no such user"
//
// Pure-FTPd:
//   - "pure-ftpd: (?@X.X.X.X) [WARNING] Authentication failed for user [name]"
//   - "pure-ftpd:...[X.X.X.X]...Authentication failed" (bracketed variants)
var ftpPatterns = []FTPPattern{
	// ── vsftpd ───────────────────────────────────────────────────────
	{Re: regexp.MustCompile(`FAIL LOGIN: Client "([\d.]+)"`), Reason: "ftp_brute_force", Daemon: "vsftpd", Detail: "login_failed"},

	// ── ProFTPD ──────────────────────────────────────────────────────
	{Re: regexp.MustCompile(`\(\S+\[([\d.]+)\]\).*USER \S+.*Login failed`), Reason: "ftp_brute_force", Daemon: "proftpd", Detail: "login_failed"},
	{Re: regexp.MustCompile(`proftpd.*\[([\d.]+)\].*no such user`), Reason: "ftp_brute_force", Daemon: "proftpd", Detail: "no_such_user"},

	// ── Pure-FTPd ────────────────────────────────────────────────────
	// Pure-FTPd writes the peer as "(user@1.2.3.4)", not "[1.2.3.4]". The
	// bracket form this pattern used to require matched "[WARNING]" instead and
	// captured nothing numeric, so no Pure-FTPd brute force was ever detected.
	{Re: regexp.MustCompile(`pure-ftpd:\s*\(\S*@([\d.]+)\).*[Aa]uthentication failed`), Reason: "ftp_brute_force", Daemon: "pure-ftpd", Detail: "auth_failed"},
	// Some builds and syslog templates do bracket the address; keep both.
	{Re: regexp.MustCompile(`pure-ftpd:.*\[([\d.]+)\].*[Aa]uthentication failed`), Reason: "ftp_brute_force", Daemon: "pure-ftpd", Detail: "auth_failed"},
}

// ftpUserPatterns read the account the client tried, which every FTP daemon
// reports in a different shape. Ordered most specific first.
var ftpUserPatterns = []*regexp.Regexp{
	// vsftpd: FAIL LOGIN: Client "1.2.3.4", "admin"
	regexp.MustCompile(`FAIL LOGIN: Client "[\d.]+",\s*"([^"]+)"`),
	// ProFTPD: USER admin (Login failed): Incorrect password
	regexp.MustCompile(`USER (\S+)\s*\(`),
	// ProFTPD: no such user 'admin' / no such user found: admin
	regexp.MustCompile(`no such user[^\w]*'?([\w.@-]+)'?`),
	// Pure-FTPd: Authentication failed for user [admin]
	regexp.MustCompile(`[Aa]uthentication failed for user \[([^\]]+)\]`),
	// Generic trailing "user admin"
	regexp.MustCompile(`\buser\s+'?([\w.@-]+)'?`),
}

// ftpObservation is what one matched log line tells us. Everything beyond IP and
// Reason is optional: FTP logs vary by daemon, and a consumer must treat an
// absent key as normal rather than as an error.
type ftpObservation struct {
	IP     string
	Reason string
	Daemon string
	Detail string
	User   string
}

// details renders the observation as the event payload, omitting what the line
// did not carry so a consumer can tell "not in this log line" from "empty".
//
// These events used to ship an empty map. Measured across the fleet, every
// single ftp_brute_force event carried no payload at all, which makes an alert
// impossible to verify or dispute — the same defect that lost us an argument
// with a customer over a db_exposed finding.
func (o ftpObservation) details(attempts int) map[string]string {
	d := map[string]string{
		"attempts": strconv.Itoa(attempts),
	}
	if o.Daemon != "" {
		d["service"] = o.Daemon
	}
	if o.Detail != "" {
		d["reason"] = o.Detail
	}
	if o.User != "" {
		d["target_user"] = o.User
	}

	return d
}

// FTPWatcher tails FTP logs and calls onBan when an IP exceeds the threshold.
type FTPWatcher struct {
	logPath string
	onBan   BanFunc
	onEvent EventFunc
	checkIP CheckIPFunc

	mu          sync.Mutex
	threshold   int
	window      time.Duration
	attempts    map[string][]time.Time
	banned      map[string]bool
	whitelist   map[string]bool
	wlNets      []*net.IPNet
	monitorMode bool
}

// detectFTPLogPath returns the FTP log path, checking env first, then auto-detecting.
func detectFTPLogPath() string {
	if p := os.Getenv("FTP_LOG_PATH"); p != "" {
		return p
	}

	// Check known FTP log paths for FTP-related content
	candidates := []string{
		"/var/log/vsftpd.log",
		"/var/log/proftpd/proftpd.log",
		"/var/log/auth.log",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	return ""
}

// HasFTPService returns true if an FTP server is detected on this system.
func HasFTPService() bool {
	for _, svc := range []string{"vsftpd", "proftpd", "pure-ftpd"} {
		if out, err := exec.Command("systemctl", "is-active", svc).Output(); err == nil {
			if strings.TrimSpace(string(out)) == "active" {
				return true
			}
		}
	}
	return detectFTPLogPath() != ""
}

// NewFTPWatcher creates a watcher for FTP server logs.
// Returns nil if no FTP log is found.
func NewFTPWatcher(onBan BanFunc) *FTPWatcher {
	path := detectFTPLogPath()
	if path == "" {
		return nil
	}

	return &FTPWatcher{
		logPath:   path,
		threshold: 5,
		window:    5 * time.Minute,
		onBan:     onBan,
		attempts:  make(map[string][]time.Time),
		banned:    make(map[string]bool),
		whitelist: make(map[string]bool),
	}
}

// SetCheckIP sets a callback for geoblocking checks.
func (w *FTPWatcher) SetCheckIP(fn CheckIPFunc) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.checkIP = fn
}

// SetOnEvent sets the callback for reporting detection events.
func (w *FTPWatcher) SetOnEvent(fn EventFunc) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.onEvent = fn
}

// SetMonitorMode enables or disables monitor-only mode.
func (w *FTPWatcher) SetMonitorMode(enabled bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.monitorMode = enabled
}

// UpdateConfig reconfigures threshold and window at runtime.
func (w *FTPWatcher) UpdateConfig(cfg Config) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if cfg.Threshold > 0 {
		w.threshold = cfg.Threshold
	}
	if cfg.Window > 0 {
		w.window = cfg.Window
	}
}

// UpdateWhitelist replaces the whitelist with a new set of IPs/CIDRs.
func (w *FTPWatcher) UpdateWhitelist(ips []string, cidrs []string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.whitelist = make(map[string]bool, len(ips))
	for _, ip := range ips {
		w.whitelist[ip] = true
	}

	w.wlNets = make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			w.wlNets = append(w.wlNets, ipNet)
		}
	}
}

func (w *FTPWatcher) isWhitelisted(ip string) bool {
	if w.whitelist[ip] {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range w.wlNets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// Run starts tailing the FTP log. Blocks indefinitely.
func (w *FTPWatcher) Run() {
	log.Printf("[ftpwatcher] watching %s (threshold: %d in %s)", w.logPath, w.threshold, w.window)

	go w.cleanupLoop()

	for {
		if err := w.tail(); err != nil {
			log.Printf("[ftpwatcher] error: %v — retrying in 5s", err)
			time.Sleep(5 * time.Second)
		}
	}
}

func (w *FTPWatcher) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		w.mu.Lock()
		now := time.Now()
		for ip, times := range w.attempts {
			var recent []time.Time
			for _, t := range times {
				if now.Sub(t) <= w.window {
					recent = append(recent, t)
				}
			}
			if len(recent) == 0 {
				delete(w.attempts, ip)
				delete(w.banned, ip)
			} else {
				w.attempts[ip] = recent
			}
		}
		const maxEntries = 50000
		if len(w.attempts) > maxEntries {
			w.attempts = make(map[string][]time.Time)
			w.banned = make(map[string]bool)
			log.Printf("[ftpwatcher] attempts map exceeded %d entries — reset", maxEntries)
		}
		w.mu.Unlock()
	}
}

func (w *FTPWatcher) tail() error {
	f, err := os.Open(w.logPath)
	if err != nil {
		return err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return err
	}
	offset := fi.Size()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	var partial string

	for range ticker.C {
		fi, err = os.Stat(w.logPath)
		if err != nil {
			return err
		}

		size := fi.Size()
		if size <= offset {
			if size < offset {
				offset = 0 // file rotated
			}
			continue
		}

		readF, err := os.Open(w.logPath)
		if err != nil {
			return err
		}

		readF.Seek(offset, io.SeekStart)
		buf := make([]byte, size-offset)
		n, err := io.ReadFull(readF, buf)
		readF.Close()

		if n > 0 {
			partial += string(buf[:n])
			offset += int64(n)

			for {
				idx := strings.IndexByte(partial, '\n')
				if idx < 0 {
					break
				}
				w.processLine(partial[:idx])
				partial = partial[idx+1:]
			}
		}

		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}
	}

	return nil
}

// observeFTPLine extracts everything one log line carries. Separate from
// processLine so the pattern table can be tested against real log lines rather
// than against a re-implementation of this loop.
func observeFTPLine(line string) (ftpObservation, bool) {
	for _, p := range ftpPatterns {
		m := p.Re.FindStringSubmatch(line)
		if len(m) >= 2 {
			return ftpObservation{
				IP:     m[1],
				Reason: p.Reason,
				Daemon: p.Daemon,
				Detail: p.Detail,
				User:   firstSubmatch(line, ftpUserPatterns),
			}, true
		}
	}

	return ftpObservation{}, false
}

func (w *FTPWatcher) processLine(line string) {
	obs, ok := observeFTPLine(line)
	if !ok {
		return
	}

	if isPrivateIP(obs.IP) {
		return
	}

	w.recordAttempt(obs)
}

func (w *FTPWatcher) recordAttempt(obs ftpObservation) {
	ip, reason := obs.IP, obs.Reason
	now := time.Now()

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.banned[ip] {
		return
	}

	if w.isWhitelisted(ip) {
		return
	}

	// Geoblocking — immediate ban
	if w.checkIP != nil {
		if banReason := w.checkIP(ip); banReason != "" {
			w.banned[ip] = true
			if w.monitorMode {
				if w.onEvent != nil {
					d := obs.details(1)
					d["reason"] = banReason
					go w.onEvent(ip, reason, "critical", d)
				}
			} else {
				go w.onBan(ip, banReason, 1)
			}
			return
		}
	}

	// Count the attempt before reporting it, so the event carries how many
	// times this IP has tried inside the window rather than a bare "1".
	var recent []time.Time
	for _, t := range w.attempts[ip] {
		if now.Sub(t) <= w.window {
			recent = append(recent, t)
		}
	}

	recent = append(recent, now)
	w.attempts[ip] = recent

	// Report event for monitor mode or event tracking
	if w.onEvent != nil {
		go w.onEvent(ip, reason, "critical", obs.details(len(recent)))
	}

	if len(recent) >= w.threshold {
		w.banned[ip] = true
		count := len(recent)
		if w.monitorMode {
			// Already reported event above
		} else {
			go w.onBan(ip, reason, count)
		}
		_ = count
	}
}
