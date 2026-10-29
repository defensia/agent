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

// MailPattern pairs a compiled regex with the event type and reason it represents.
//
// Protocol and Detail are static facts about the pattern rather than things
// read out of the line: a Postfix SASL failure is always SMTP, and a NOQUEUE
// reject is always a relay denial. Empty means "not known from this pattern".
type MailPattern struct {
	Re       *regexp.Regexp
	Reason   string
	Protocol string
	Detail   string
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
	{Re: regexp.MustCompile(`\S+\[([\d.]+)\]: SASL (?:LOGIN|PLAIN|CRAM-MD5|DIGEST-MD5) authentication failed`), Reason: "mail_brute_force", Protocol: "smtp"},
	{Re: regexp.MustCompile(`NOQUEUE: reject:.*from \S+\[([\d.]+)\].*(?:Relay access denied|Client host rejected)`), Reason: "mail_relay_scan", Protocol: "smtp", Detail: "relay_denied"},
	{Re: regexp.MustCompile(`too many errors after AUTH from \S+\[([\d.]+)\]`), Reason: "mail_brute_force", Protocol: "smtp"},
	{Re: regexp.MustCompile(`warning: ([\d.]+): hostname \S+ does not resolve`), Reason: "mail_suspicious", Protocol: "smtp", Detail: "unresolvable_hostname"},
	{Re: regexp.MustCompile(`improper command pipelining after \S+ from \S+\[([\d.]+)\]`), Reason: "mail_suspicious", Protocol: "smtp", Detail: "command_pipelining"},

	// ── Dovecot ───────────────────────────────────────────────────────
	{Re: regexp.MustCompile(`(?:imap|pop3|submission|managesieve)-login: (?:Disconnected|Aborted login) \((?:auth failed|tried to use (?:disabled|disallowed)).*rip=([\d.]+)`), Reason: "mail_brute_force"},
	{Re: regexp.MustCompile(`auth:.*\(\S+,([\d.]+)\):\s+unknown user`), Reason: "mail_brute_force"},
	{Re: regexp.MustCompile(`(?:imap|pop3)\(\S+,<?([\d.]+)>?\).*Too many invalid`), Reason: "mail_brute_force"},
	{Re: regexp.MustCompile(`auth:.*\(\S+,([\d.]+)\):\s+[Pp]assword mismatch`), Reason: "mail_brute_force"},

	// ── Roundcube ─────────────────────────────────────────────────────
	{Re: regexp.MustCompile(`IMAP Error: Login failed for \S+ against \S+ from ([\d.]+)`), Reason: "mail_brute_force", Protocol: "imap"},
	{Re: regexp.MustCompile(`Failed login for \S+ from ([\d.]+) in session`), Reason: "mail_brute_force", Protocol: "imap"},
}

// ─── Enrichment ───────────────────────────────────────────────────────
//
// These read extra fields out of a line that a detection pattern has ALREADY
// matched. They are deliberately separate from the detection patterns above:
// an MSP asked for the targeted mailbox in the event payload (29-oct-2026),
// and widening eleven detection regexes to carry more capture groups would put
// banning — the thing that actually protects a customer — at risk for the sake
// of a reporting field. Detection stays untouched; enrichment is additive and
// every field is optional.
//
// Each returns the first submatch, or "" when the line does not carry it.

// mailUserPatterns extract the targeted mailbox, in order of specificity.
//
// Note what is NOT here: Postfix SASL authentication failures. Those lines
// carry the client IP and the mechanism but no username at all, so for SMTP
// AUTH attacks target_user is legitimately absent rather than missing by
// oversight. Dovecot and Roundcube do name the account.
var mailUserPatterns = []*regexp.Regexp{
	// Dovecot login: "user=<sales@example.com>, method=PLAIN, rip=1.2.3.4"
	regexp.MustCompile(`user=<([^>]+)>`),
	// Dovecot auth / imap: "(sales@example.com,1.2.3.4): Password mismatch"
	regexp.MustCompile(`\((\S+?),(?:<)?[\d.]+(?:>)?\)`),
	// Roundcube
	regexp.MustCompile(`Login failed for (\S+) against`),
	regexp.MustCompile(`Failed login for (\S+) from`),
}

// mailMethodPatterns extract the authentication mechanism.
var mailMethodPatterns = []*regexp.Regexp{
	// Dovecot: "method=PLAIN,"
	regexp.MustCompile(`method=([A-Za-z0-9-]+)`),
	// Postfix: "SASL LOGIN authentication failed"
	regexp.MustCompile(`SASL (LOGIN|PLAIN|CRAM-MD5|DIGEST-MD5)`),
}

// mailProtocolPattern reads the service out of a Dovecot line, where it varies
// per connection rather than being fixed by the pattern.
var mailProtocolPattern = regexp.MustCompile(`\b(imap|pop3|submission|managesieve)(?:-login)?[(:]`)

// mailRcptPattern reads the attempted recipient from a Postfix reject line:
// "to=<victim@example.com>".
var mailRcptPattern = regexp.MustCompile(`to=<([^>]*)>`)

// firstSubmatch returns the first capture group of the first pattern that
// matches, or "" if none do.
func firstSubmatch(line string, patterns []*regexp.Regexp) string {
	for _, re := range patterns {
		if m := re.FindStringSubmatch(line); len(m) >= 2 && m[1] != "" {
			return m[1]
		}
	}
	return ""
}

// mailObservation is what one matched log line tells us. Every field beyond
// IP and Reason is optional: mail logs vary by server, and a consumer parsing
// these events must treat an absent key as normal rather than as an error.
type mailObservation struct {
	IP       string
	Reason   string
	User     string
	Method   string
	Protocol string
	Rcpt     string
	Detail   string
}

// details renders the observation as the event payload, omitting what the line
// did not carry so a consumer can tell "not in this log line" from "empty".
func (o mailObservation) details(attempts int) map[string]string {
	d := map[string]string{
		"attempts": strconv.Itoa(attempts),
	}
	if o.User != "" {
		d["target_user"] = o.User
	}
	if o.Protocol != "" {
		d["protocol"] = o.Protocol
	}
	if o.Method != "" {
		d["auth_method"] = strings.ToLower(o.Method)
	}
	if o.Detail != "" {
		d["reason"] = o.Detail
	}
	if o.Rcpt != "" {
		d["rcpt_to"] = o.Rcpt
		if i := strings.LastIndex(o.Rcpt, "@"); i >= 0 && i+1 < len(o.Rcpt) {
			d["rcpt_domain"] = o.Rcpt[i+1:]
		}
	}

	return d
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

	go w.cleanupLoop()

	for {
		if err := w.tail(); err != nil {
			log.Printf("[mailwatcher] error: %v — retrying in 5s", err)
			time.Sleep(5 * time.Second)
		}
	}
}

func (w *MailWatcher) cleanupLoop() {
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
			log.Printf("[mailwatcher] attempts map exceeded %d entries — reset", maxEntries)
		}
		w.mu.Unlock()
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

// observeMailLine matches a line against the detection patterns and, if one
// hits, reads out the optional fields. Returns false when the line is not a
// mail security event.
//
// Separate from processLine so the tests can exercise the real extraction
// against real log lines rather than a copy of it.
func observeMailLine(line string) (mailObservation, bool) {
	var obs mailObservation
	for _, p := range mailPatterns {
		m := p.Re.FindStringSubmatch(line)
		if len(m) >= 2 {
			obs = mailObservation{
				IP:       m[1],
				Reason:   p.Reason,
				Protocol: p.Protocol,
				Detail:   p.Detail,
			}
			break
		}
	}
	if obs.IP == "" {
		return obs, false
	}

	// Enrich only after a pattern matched, so a malformed line costs nothing:
	// these run on one line, a handful of times a second at worst.
	obs.User = firstSubmatch(line, mailUserPatterns)
	obs.Method = firstSubmatch(line, mailMethodPatterns)
	obs.Rcpt = firstSubmatch(line, []*regexp.Regexp{mailRcptPattern})
	if obs.Protocol == "" {
		obs.Protocol = firstSubmatch(line, []*regexp.Regexp{mailProtocolPattern})
	}

	// The Dovecot "(user,ip)" extractor picks up the address itself on lines
	// that omit the username. Never report the source IP as the targeted
	// mailbox.
	if obs.User == obs.IP {
		obs.User = ""
	}

	return obs, true
}

func (w *MailWatcher) processLine(line string) {
	obs, ok := observeMailLine(line)
	if !ok {
		return
	}

	if isPrivateIP(obs.IP) {
		return
	}

	w.recordAttempt(obs)
}

func (w *MailWatcher) recordAttempt(obs mailObservation) {
	now := time.Now()
	ip, reason := obs.IP, obs.Reason

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
					// The geoblock reason is why we acted, which is not the
					// same fact as why the line was suspicious.
					d["geoblock_reason"] = banReason
					go w.onEvent(ip, reason, "critical", d)
				}
			} else {
				go w.onBan(ip, banReason, 1)
			}
			return
		}
	}

	// Count this attempt before reporting, so `attempts` in the payload is the
	// number within the window including this one. The order change is only
	// that: the same single append and the same threshold comparison decide a
	// ban exactly as before.
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
		severity := "warning"
		if reason == "mail_brute_force" {
			severity = "critical"
		}
		go w.onEvent(ip, reason, severity, obs.details(len(recent)))
	}

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
