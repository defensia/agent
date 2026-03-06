package watcher

import (
	"bufio"
	"fmt"
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

const defaultLogPath = "/var/log/auth.log"

// cPHulk SQLite paths (cPanel v62+)
const (
	cpHulkDB     = "/var/cpanel/hulkd/cphulk.sqlite"
	cpHulkSQLite = "/usr/local/cpanel/3rdparty/bin/sqlite3"
)

// failedPattern matches SSH authentication failure lines from /var/log/auth.log
// and /var/log/secure. Covers both password-based and key-only SSH configs:
//   - "Failed password for root from X.X.X.X"             (password auth)
//   - "Failed password for invalid user foo from X.X.X.X" (password auth, bad user)
//   - "Invalid user foo from X.X.X.X"                     (key-only auth / PasswordAuthentication no)
var failedPattern = regexp.MustCompile(
	`(?:Failed password for (?:invalid user )?\S+ from|Invalid user \S+ from)\s*([\d.]+)`,
)

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
	Method  string // "cphulk", "journald", "file_tail", "none"

	mu        sync.Mutex
	threshold int
	window    time.Duration
	attempts  map[string][]time.Time
	banned    map[string]bool
	whitelist map[string]bool // IPs or CIDRs that are never banned
	wlNets    []*net.IPNet    // parsed CIDR whitelists
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

// ── Detection helpers ────────────────────────────────────────────────

func (w *Watcher) hasCPHulk() bool {
	if _, err := os.Stat(cpHulkDB); err != nil {
		return false
	}
	if _, err := os.Stat(cpHulkSQLite); err != nil {
		return false
	}
	return true
}

func (w *Watcher) logFileEmpty() bool {
	fi, err := os.Stat(w.logPath)
	return err != nil || fi.Size() == 0
}

func (w *Watcher) hasJournald() bool {
	_, err := exec.LookPath("journalctl")
	return err == nil
}

// shouldUseJournald returns true when journald is the better SSH log source.
// On RHEL-family systems (/var/log/secure), cPanel may disable rsyslog's auth
// facility so sshd logs go exclusively to journald even when the file exists.
// We always prefer journald on those systems when journalctl is available.
func (w *Watcher) shouldUseJournald() bool {
	if !w.hasJournald() {
		return false
	}
	// File missing or empty → always use journald
	if w.logFileEmpty() {
		return true
	}
	// On RHEL-family (/var/log/secure), prefer journald — cPanel/CloudLinux
	// may suppress sshd output to the file even when it exists.
	if w.logPath == "/var/log/secure" {
		return true
	}
	return false
}

// ── Run — routing logic ──────────────────────────────────────────────

// Run starts monitoring SSH auth events. Blocks indefinitely.
// Detection order:
//  1. cPHulk SQLite (cPanel/CloudLinux) — if database and sqlite3 binary found
//  2. journald — if journalctl available AND (file empty OR RHEL-family path)
//  3. File tail — default (Debian/Ubuntu auth.log)
func (w *Watcher) Run() {
	if w.hasCPHulk() {
		w.Method = "cphulk"
		log.Printf("[watcher] cPHulk detected — polling %s every 30s", cpHulkDB)
		w.runCPHulk()
		return
	}

	if w.shouldUseJournald() {
		w.Method = "journald"
		log.Printf("[watcher] using journald for SSH monitoring (path: %s)", w.logPath)
		w.runJournald()
		return
	}

	if w.logFileEmpty() {
		w.Method = "none"
		log.Printf("[watcher] no auth log source found (file: %s empty/missing, no journald, no cphulk)", w.logPath)
	} else {
		w.Method = "file_tail"
	}

	log.Printf("[watcher] watching %s (threshold: %d in %s)", w.logPath, w.threshold, w.window)
	for {
		if err := w.tail(); err != nil {
			log.Printf("[watcher] error: %v — retrying in 5s", err)
			time.Sleep(5 * time.Second)
		}
	}
}

// ── cPHulk SQLite polling ────────────────────────────────────────────

// runCPHulk polls the cPHulk SQLite database every 30 seconds.
// It reads from two tables:
//   - login_log (status=0): failed login attempts → threshold-based banning
//   - blocked_ips: IPs already blocked by cPHulk → immediate ban in Defensia
func (w *Watcher) runCPHulk() {
	lastLoginTime := time.Now().Unix()
	lastBlockTime := time.Now().Unix()

	for {
		time.Sleep(30 * time.Second)
		w.pollCPHulkLogins(&lastLoginTime)
		w.pollCPHulkBlocked(&lastBlockTime)
	}
}

// pollCPHulkLogins reads new failed login entries from login_log since lastSeen.
func (w *Watcher) pollCPHulkLogins(lastSeen *int64) {
	query := fmt.Sprintf(
		"SELECT ip, login_time FROM login_log WHERE status=0 AND login_time>%d ORDER BY login_time ASC;",
		*lastSeen,
	)
	out, err := exec.Command(cpHulkSQLite, cpHulkDB, query).Output()
	if err != nil {
		log.Printf("[cphulk] login_log query error: %v", err)
		return
	}

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 2 {
			continue
		}
		ip := strings.TrimSpace(parts[0])
		ts, _ := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
		if ts > *lastSeen {
			*lastSeen = ts
		}
		if net.ParseIP(ip) == nil {
			continue
		}
		w.recordAttempt(ip)
	}
}

// pollCPHulkBlocked reads new entries from blocked_ips since lastSeen.
// These are IPs that cPHulk has already decided to block — Defensia bans them
// immediately without waiting for the threshold.
func (w *Watcher) pollCPHulkBlocked(lastSeen *int64) {
	query := fmt.Sprintf(
		"SELECT ip, block_time, reason FROM blocked_ips WHERE block_time>%d ORDER BY block_time ASC;",
		*lastSeen,
	)
	out, err := exec.Command(cpHulkSQLite, cpHulkDB, query).Output()
	if err != nil {
		log.Printf("[cphulk] blocked_ips query error: %v", err)
		return
	}

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 2 {
			continue
		}
		ip := strings.TrimSpace(parts[0])
		ts, _ := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
		if ts > *lastSeen {
			*lastSeen = ts
		}
		if net.ParseIP(ip) == nil {
			continue
		}

		w.mu.Lock()
		alreadyBanned := w.banned[ip]
		whitelisted := w.isWhitelisted(ip)
		if !alreadyBanned && !whitelisted {
			w.banned[ip] = true
		}
		w.mu.Unlock()

		if !alreadyBanned && !whitelisted {
			log.Printf("[cphulk] banned by cPHulk: %s", ip)
			go w.onBan(ip, "brute_force_cpanel", 1)
		}
	}
}

// ── journald fallback ────────────────────────────────────────────────

// runJournald streams SSH events from the systemd journal. Used on systems
// where sshd logs only to journald (CloudLinux 8/9, RHEL 9 minimal, etc.).
func (w *Watcher) runJournald() {
	for {
		// Watch both sshd and ssh units to cover different distro naming
		cmd := exec.Command("journalctl", "-f",
			"-u", "sshd", "-u", "ssh",
			"--output=short", "--no-pager")
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			log.Printf("[watcher] journald pipe: %v — retrying in 5s", err)
			time.Sleep(5 * time.Second)
			continue
		}
		if err := cmd.Start(); err != nil {
			log.Printf("[watcher] journald start: %v — retrying in 5s", err)
			time.Sleep(5 * time.Second)
			continue
		}
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			w.processLine(scanner.Text())
		}
		cmd.Wait()
		log.Printf("[watcher] journald exited — retrying in 5s")
		time.Sleep(5 * time.Second)
	}
}

// ── File tail ────────────────────────────────────────────────────────

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

// ── Line / attempt processing ────────────────────────────────────────

func (w *Watcher) processLine(line string) {
	matches := failedPattern.FindStringSubmatch(line)
	if len(matches) < 2 {
		return
	}
	w.recordAttempt(matches[1])
}

// recordAttempt applies threshold logic for a given IP.
// Called by processLine (file/journald) and pollCPHulkLogins.
func (w *Watcher) recordAttempt(ip string) {
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
		if reason := w.checkIP(ip); reason != "" {
			w.banned[ip] = true
			go w.onBan(ip, reason, 1)
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
		go w.onBan(ip, "brute_force_ssh", count)
	}
}
