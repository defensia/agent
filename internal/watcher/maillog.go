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

// MailPattern pairs a compiled regex with the event type and reason it represents.
type MailPattern struct {
	Re     *regexp.Regexp
	Reason string
}

// mailPatterns contains all mail detection patterns, ordered by frequency.
// Each regex must have a capture group for the IP address.
//
// Postfix SASL:
//   - "warning: unknown[X.X.X.X]: SASL LOGIN authentication failed"
//   - "NOQUEUE: reject: RCPT from unknown[X.X.X.X]: 554 5.7.1 Relay access denied"
//   - "too many errors after AUTH from unknown[X.X.X.X]"
//   - "warning: X.X.X.X: hostname does not resolve"
//   - "improper command pipelining after ... from unknown[X.X.X.X]"
//
// Dovecot:
//   - "imap-login: Aborted login (auth failed, N attempts): ... rip=X.X.X.X"
//   - "pop3-login: Aborted login (auth failed): ... rip=X.X.X.X"
//   - "auth: passwd(user,X.X.X.X): unknown user"
//   - "imap(user,<X.X.X.X>): Too many invalid commands"
//   - "auth: passwd(user,X.X.X.X): Password mismatch"
//
// Roundcube:
//   - "IMAP Error: Login failed for user against server from X.X.X.X"
//   - "Failed login for user from X.X.X.X in session"
var mailPatterns = []MailPattern{
	// ── Postfix SASL ──────────────────────────────────────────────────
	{Re: regexp.MustCompile(`\S+\[([\d.]+)\]: SASL (?:LOGIN|PLAIN|CRAM-MD5|DIGEST-MD5) authentication failed`), Reason: "mail_brute_force"},
	{Re: regexp.MustCompile(`NOQUEUE: reject:.*from \S+\[([\d.]+)\].*(?:Relay access denied|Client host rejected)`), Reason: "mail_relay_scan"},
	{Re: regexp.MustCompile(`too many errors after AUTH from \S+\[([\d.]+)\]`), Reason: "mail_brute_force"},
	{Re: regexp.MustCompile(`warning: ([\d.]+): hostname \S+ does not resolve`), Reason: "mail_suspicious"},
	{Re: regexp.MustCompile(`improper command pipelining after \S+ from \S+\[([\d.]+)\]`), Reason: "mail_suspicious"},

	// ── Dovecot ───────────────────────────────────────────────────────
	{Re: regexp.MustCompile(`(?:imap|pop3|submission|managesieve)-login: (?:Disconnected|Aborted login) \((?:auth failed|tried to use (?:disabled|disallowed)).*rip=([\d.]+)`), Reason: "mail_brute_force"},
	{Re: regexp.MustCompile(`auth:.*\(\S+,([\d.]+)\):\s+unknown user`), Reason: "mail_brute_force"},
	{Re: regexp.MustCompile(`(?:imap|pop3)\(\S+,<?([\d.]+)>?\).*Too many invalid`), Reason: "mail_brute_force"},
	{Re: regexp.MustCompile(`auth:.*\(\S+,([\d.]+)\):\s+[Pp]assword mismatch`), Reason: "mail_brute_force"},

	// ── Roundcube ─────────────────────────────────────────────────────
	{Re: regexp.MustCompile(`IMAP Error: Login failed for \S+ against \S+ from ([\d.]+)`), Reason: "mail_brute_force"},
	{Re: regexp.MustCompile(`Failed login for \S+ from ([\d.]+) in session`), Reason: "mail_brute_force"},
}

// MailWatcher tails mail logs and calls onBan when an IP exceeds the threshold.
type MailWatcher struct {
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

// detectMailLogPath returns the mail log path, checking env first, then auto-detecting.
func detectMailLogPath() string {
	if p := os.Getenv("MAIL_LOG_PATH"); p != "" {
		return p
	}
	if _, err := os.Stat("/var/log/mail.log"); err == nil {
		return "/var/log/mail.log"
	}
	if _, err := os.Stat("/var/log/maillog"); err == nil {
		return "/var/log/maillog"
	}
	if _, err := os.Stat("/var/log/dovecot.log"); err == nil {
		return "/var/log/dovecot.log"
	}
	return ""
}

// HasMailService returns true if a mail server is detected on this system.
func HasMailService() bool {
	for _, svc := range []string{"postfix", "dovecot"} {
		if out, err := exec.Command("systemctl", "is-active", svc).Output(); err == nil {
			if strings.TrimSpace(string(out)) == "active" {
				return true
			}
		}
	}
	return detectMailLogPath() != ""
}

// NewMailWatcher creates a watcher for mail server logs.
// Returns nil if no mail log is found.
func NewMailWatcher(onBan BanFunc) *MailWatcher {
	path := detectMailLogPath()
	if path == "" {
		return nil
	}

	return &MailWatcher{
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
func (w *MailWatcher) SetCheckIP(fn CheckIPFunc) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.checkIP = fn
}

// SetOnEvent sets the callback for reporting detection events.
func (w *MailWatcher) SetOnEvent(fn EventFunc) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.onEvent = fn
}

// SetMonitorMode enables or disables monitor-only mode.
func (w *MailWatcher) SetMonitorMode(enabled bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.monitorMode = enabled
}

// UpdateConfig reconfigures threshold and window at runtime.
func (w *MailWatcher) UpdateConfig(cfg Config) {
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
func (w *MailWatcher) UpdateWhitelist(ips []string, cidrs []string) {
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

func (w *MailWatcher) isWhitelisted(ip string) bool {
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

// Run starts tailing the mail log. Blocks indefinitely.
func (w *MailWatcher) Run() {
	log.Printf("[mailwatcher] watching %s (threshold: %d in %s)", w.logPath, w.threshold, w.window)

	for {
		if err := w.tail(); err != nil {
			log.Printf("[mailwatcher] error: %v — retrying in 5s", err)
			time.Sleep(5 * time.Second)
		}
	}
}

func (w *MailWatcher) tail() error {
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

func (w *MailWatcher) processLine(line string) {
	var ip, reason string
	for _, p := range mailPatterns {
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

func (w *MailWatcher) recordAttempt(ip, reason string) {
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
		severity := "warning"
		if reason == "mail_brute_force" {
			severity = "critical"
		}
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
	}
}
