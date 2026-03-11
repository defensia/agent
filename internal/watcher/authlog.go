package watcher

import (
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const defaultLogPath = "/var/log/auth.log"

// SSHPattern pairs a compiled regex with the ban reason it represents.
type SSHPattern struct {
	Re     *regexp.Regexp
	Reason string
}

// sshPatterns contains all SSH detection patterns, ordered by frequency.
// Each regex must have a capture group for the IP address.
//
// Auth failures (normal mode) — standard brute force indicators:
//
//   - "Failed password for root from X.X.X.X"
//   - "Failed password for invalid user foo from X.X.X.X"
//   - "Invalid user foo from X.X.X.X"
//   - "authentication failure; ... rhost=X.X.X.X" (PAM)
//   - "maximum authentication attempts exceeded ... from X.X.X.X"
//   - "Received disconnect from X.X.X.X ... Auth fail"
//   - "User X not allowed because ..."
//   - "ROOT LOGIN REFUSED FROM X.X.X.X"
//
// Pre-auth scanning (ddos mode) — connection-level abuse:
//
//   - "Did not receive identification string from X.X.X.X"
//   - "Bad protocol version identification ... from X.X.X.X"
//   - "Unable to negotiate with X.X.X.X: no matching ..."
//   - "Connection closed by X.X.X.X ... [preauth]"
//   - "banner exchange: Connection from X.X.X.X ..."
//   - "ssh_dispatch_run_fatal: Connection from X.X.X.X ..."
var sshPatterns = []SSHPattern{
	// ── Auth failures (most common first) ──────────────────────────────
	{Re: regexp.MustCompile(`Failed \S+ for (?:invalid user )?\S+ from ([\d.]+)`), Reason: "brute_force_ssh"},
	{Re: regexp.MustCompile(`[iI](?:llegal|nvalid) user \S+ from ([\d.]+)`), Reason: "brute_force_ssh"},
	{Re: regexp.MustCompile(`pam_[a-z]+\(sshd:auth\):\s+authentication failure;.*rhost=([\d.]+)`), Reason: "brute_force_ssh"},
	{Re: regexp.MustCompile(`maximum authentication attempts exceeded for .+? from ([\d.]+)`), Reason: "brute_force_ssh"},
	{Re: regexp.MustCompile(`Received disconnect from ([\d.]+).*:\s*3:.*Auth fail`), Reason: "brute_force_ssh"},
	{Re: regexp.MustCompile(`User \S+ from ([\d.]+) not allowed because`), Reason: "brute_force_ssh"},
	{Re: regexp.MustCompile(`ROOT LOGIN REFUSED FROM ([\d.]+)`), Reason: "brute_force_ssh"},
	{Re: regexp.MustCompile(`refused connect from \S+ \(([\d.]+)\)`), Reason: "brute_force_ssh"},
	{Re: regexp.MustCompile(`Disconnecting(?: from)? (?:invalid|authenticating) user \S+ ([\d.]+).*\[preauth\]`), Reason: "brute_force_ssh"},

	// ── Pre-auth scanning / DDoS ───────────────────────────────────────
	{Re: regexp.MustCompile(`Did not receive identification string from ([\d.]+)`), Reason: "brute_force_ssh_preauth"},
	{Re: regexp.MustCompile(`Bad protocol version identification '.*?' from ([\d.]+)`), Reason: "brute_force_ssh_preauth"},
	{Re: regexp.MustCompile(`Unable to negotiate with ([\d.]+)`), Reason: "brute_force_ssh_preauth"},
	{Re: regexp.MustCompile(`(?:banner exchange|ssh_dispatch_run_fatal): Connection from ([\d.]+)`), Reason: "brute_force_ssh_preauth"},
	{Re: regexp.MustCompile(`Connection (?:closed|reset) by ([\d.]+).*\[preauth\]`), Reason: "brute_force_ssh_preauth"},
	{Re: regexp.MustCompile(`Timeout before authentication for(?: connection from)? ([\d.]+)`), Reason: "brute_force_ssh_preauth"},
}

// BanFunc is called when an IP exceeds the threshold.
type BanFunc func(ip, reason string, count int)

// CheckIPFunc is called for every detected IP. If it returns a non-empty reason,
// the IP is banned immediately (used for geoblocking).
type CheckIPFunc func(ip string) (banReason string)

// Config holds the watcher's tunable parameters.
type Config struct {
	Threshold int
	Window    time.Duration
}

// Watcher tails auth.log and calls onBan when an IP exceeds the threshold.
type Watcher struct {
	logPath string
	onBan   BanFunc
	checkIP CheckIPFunc

	mu          sync.Mutex
	threshold   int
	window      time.Duration
	attempts    map[string][]time.Time
	banned      map[string]bool
	whitelist   map[string]bool // IPs or CIDRs that are never banned
	wlNets      []*net.IPNet    // parsed CIDR whitelists
	monitorMode bool            // when true, detect but do not ban
}

// detectLogPath returns the auth log path, checking the environment variable
// first, then auto-detecting between Debian/Ubuntu and RHEL/CentOS paths.
func detectLogPath() string {
	if p := os.Getenv("AUTH_LOG_PATH"); p != "" {
		return p
	}
	if _, err := os.Stat("/var/log/auth.log"); err == nil {
		return "/var/log/auth.log"
	}
	if _, err := os.Stat("/var/log/secure"); err == nil {
		return "/var/log/secure"
	}
	return defaultLogPath
}

func New(onBan BanFunc) *Watcher {
	path := detectLogPath()

	return &Watcher{
		logPath:   path,
		threshold: 5,
		window:    5 * time.Minute,
		onBan:     onBan,
		attempts:  make(map[string][]time.Time),
		banned:    make(map[string]bool),
		whitelist: make(map[string]bool),
	}
}

// SetCheckIP sets a callback that is invoked for every unique IP seen.
// If it returns a non-empty string, the IP is banned immediately.
func (w *Watcher) SetCheckIP(fn CheckIPFunc) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.checkIP = fn
}

// SetMonitorMode enables or disables monitor-only mode. When enabled, the
// watcher detects attacks and records attempts but does not call onBan.
func (w *Watcher) SetMonitorMode(enabled bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.monitorMode = enabled
	log.Printf("[watcher] monitor mode: %v", enabled)
}

// UpdateConfig reconfigures threshold and window at runtime.
func (w *Watcher) UpdateConfig(cfg Config) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if cfg.Threshold > 0 {
		w.threshold = cfg.Threshold
	}
	if cfg.Window > 0 {
		w.window = cfg.Window
	}

	log.Printf("[watcher] config updated: threshold=%d window=%s", w.threshold, w.window)
}

// UpdatePatterns replaces the SSH detection patterns with rules from the panel.
// If patterns is empty, the hardcoded defaults are kept.
func (w *Watcher) UpdatePatterns(patterns []SSHPattern) {
	if len(patterns) == 0 {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	sshPatterns = patterns
	log.Printf("[watcher] detection patterns updated: %d rules", len(patterns))
}

// ParsePattern compiles a regex string into an SSHPattern. Returns nil on error.
func ParsePattern(pattern, reason string) *SSHPattern {
	re, err := regexp.Compile(pattern)
	if err != nil {
		log.Printf("[watcher] invalid pattern %q: %v", pattern, err)
		return nil
	}
	return &SSHPattern{Re: re, Reason: reason}
}

// UpdateWhitelist replaces the whitelist with a new set of IPs/CIDRs.
func (w *Watcher) UpdateWhitelist(ips []string, cidrs []string) {
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

	log.Printf("[watcher] whitelist updated: %d IPs, %d CIDRs", len(ips), len(w.wlNets))
}

// isWhitelisted checks if an IP is in the whitelist. Caller must hold w.mu.
func (w *Watcher) isWhitelisted(ip string) bool {
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

// Run starts tailing the log file. Blocks indefinitely.
func (w *Watcher) Run() {
	log.Printf("[watcher] watching %s (threshold: %d in %s)", w.logPath, w.threshold, w.window)

	for {
		if err := w.tail(); err != nil {
			log.Printf("[watcher] error: %v — retrying in 5s", err)
			time.Sleep(5 * time.Second)
		}
	}
}

func (w *Watcher) tail() error {
	f, err := os.Open(w.logPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// Get initial file size so we only process new lines
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	offset := fi.Size()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	var partial string

	for range ticker.C {
		// Check if file has grown
		fi, err = os.Stat(w.logPath)
		if err != nil {
			return err
		}

		size := fi.Size()
		if size <= offset {
			if size < offset {
				// File was truncated/rotated — reset
				offset = 0
			}
			continue
		}

		// Read the new data
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

			// Process all complete lines
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

func (w *Watcher) processLine(line string) {
	var ip, reason string
	for _, p := range sshPatterns {
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

	w.recordAttempt(ip, reason)
}

// recordAttempt tracks a failed attempt for the given IP and bans when threshold is exceeded.
func (w *Watcher) recordAttempt(ip, reason string) {
	now := time.Now()

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.banned[ip] {
		return
	}

	if w.isWhitelisted(ip) {
		return
	}

	// Check geoblocking callback first — immediate ban
	if w.checkIP != nil {
		if banReason := w.checkIP(ip); banReason != "" {
			w.banned[ip] = true
			if !w.monitorMode {
				go w.onBan(ip, banReason, 1)
			}
			return
		}
	}

	// Keep only attempts within the window
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
		if !w.monitorMode {
			go w.onBan(ip, reason, count)
		}
	}
}
