package watcher

import (
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// FTPPattern pairs a compiled regex with the event reason.
type FTPPattern struct {
	Re     *regexp.Regexp
	Reason string
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
//   - "pure-ftpd:...[X.X.X.X]...Authentication failed"
var ftpPatterns = []FTPPattern{
	// ── vsftpd ───────────────────────────────────────────────────────
	{Re: regexp.MustCompile(`FAIL LOGIN: Client "([\d.]+)"`), Reason: "ftp_brute_force"},

	// ── ProFTPD ──────────────────────────────────────────────────────
	{Re: regexp.MustCompile(`\(\S+\[([\d.]+)\]\).*USER \S+.*Login failed`), Reason: "ftp_brute_force"},
	{Re: regexp.MustCompile(`proftpd.*\[([\d.]+)\].*no such user`), Reason: "ftp_brute_force"},

	// ── Pure-FTPd ────────────────────────────────────────────────────
	{Re: regexp.MustCompile(`pure-ftpd:.*\[([\d.]+)\].*Authentication failed`), Reason: "ftp_brute_force"},
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

	for {
		if err := w.tail(); err != nil {
			log.Printf("[ftpwatcher] error: %v — retrying in 5s", err)
			time.Sleep(5 * time.Second)
		}
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

func (w *FTPWatcher) processLine(line string) {
	var ip, reason string
	for _, p := range ftpPatterns {
		m := p.Re.FindStringSubmatch(line)
		if len(m) >= 2 {
			ip = m[1]
			reason = p.Reason
			break
		}
	}
	if ip == "" {
		return
	}

	if isPrivateIP(ip) {
		return
	}

	w.recordAttempt(ip, reason)
}

func (w *FTPWatcher) recordAttempt(ip, reason string) {
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
					go w.onEvent(ip, reason, "critical", map[string]string{
						"reason": banReason,
					})
				}
			} else {
				go w.onBan(ip, banReason, 1)
			}
			return
		}
	}

	// Report event for monitor mode or event tracking
	if w.onEvent != nil {
		severity := "critical"
		go w.onEvent(ip, reason, severity, map[string]string{})
	}

	// Threshold check
	var recent []time.Time
	for _, t := range w.attempts[ip] {
		if now.Sub(t) <= w.window {
			recent = append(recent, t)
		}
	}

	recent = append(recent, now)
	w.attempts[ip] = recent

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
