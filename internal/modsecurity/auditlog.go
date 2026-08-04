package modsecurity

import (
	"io"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// AuditEntry represents a parsed ModSecurity audit log entry.
type AuditEntry struct {
	UniqueID   string
	Timestamp  string
	SourceIP   string
	SourcePort string
	DestIP     string
	DestPort   string
	Method     string
	URI        string
	Host       string
	UserAgent  string
	StatusCode string
	Rules      []RuleMatch
	Action     string // "Intercepted" or ""
	EngineMode string // "ENABLED" or "DETECTION_ONLY"
}

// RuleMatch represents a single ModSecurity rule match from the H section.
type RuleMatch struct {
	ID       string
	Msg      string
	Data     string
	Severity string // CRITICAL, ERROR, WARNING, NOTICE
	Tags     []string
}

// AuditEventFunc is called when a ModSecurity block/detection is parsed.
type AuditEventFunc func(entry AuditEntry)

// knownAuditLogPaths are the common locations for ModSecurity audit logs.
var knownAuditLogPaths = []string{
	"/var/log/modsec_audit.log",
	"/var/log/bunkerweb/modsec_audit.log",
	"/var/log/apache2/modsec_audit.log",
	"/var/log/httpd/modsec_audit.log",
	"/usr/local/apache/logs/modsec_audit.log",
	"/var/log/nginx/modsec_audit.log",
}

// regex to match section boundaries: --<id>-<section>--
var sectionBoundary = regexp.MustCompile(`^--([a-zA-Z0-9]+)-([A-Z])--$`)

// regex to extract fields from H section Message: lines
var reRuleID = regexp.MustCompile(`\[id "(\d+)"\]`)
var reRuleMsg = regexp.MustCompile(`\[msg "([^"]+)"\]`)
var reRuleData = regexp.MustCompile(`\[data "([^"]+)"\]`)
var reRuleSeverity = regexp.MustCompile(`\[severity "([^"]+)"\]`)
var reRuleTag = regexp.MustCompile(`\[tag "([^"]+)"\]`)

// AuditLogWatcher tails a ModSecurity audit log and emits parsed events.
type AuditLogWatcher struct {
	logPath string
	onEvent AuditEventFunc
	mu      sync.Mutex
	stop    chan struct{}

	// Rate limiting: group events per IP within a window
	recentIPs map[string]time.Time
	rateLimit time.Duration
}

// DetectAuditLogPath finds the ModSecurity audit log, checking env var first.
func DetectAuditLogPath() string {
	if p := os.Getenv("MODSEC_AUDIT_LOG"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	for _, p := range knownAuditLogPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	return ""
}

// NewAuditLogWatcher creates a watcher for the ModSecurity audit log.
// Returns nil if no audit log is found.
func NewAuditLogWatcher(onEvent AuditEventFunc) *AuditLogWatcher {
	path := DetectAuditLogPath()
	if path == "" {
		return nil
	}

	log.Printf("[modsec-audit] detected audit log: %s", path)

	return &AuditLogWatcher{
		logPath:   path,
		onEvent:   onEvent,
		stop:      make(chan struct{}),
		recentIPs: make(map[string]time.Time),
		rateLimit: 10 * time.Second, // max 1 event per IP per 10s
	}
}

// Run starts tailing the audit log. Blocks until Stop() is called.
func (w *AuditLogWatcher) Run() {
	log.Printf("[modsec-audit] watching %s", w.logPath)

	for {
		select {
		case <-w.stop:
			return
		default:
		}

		if err := w.tail(); err != nil {
			log.Printf("[modsec-audit] error: %v — retrying in 10s", err)
			select {
			case <-w.stop:
				return
			case <-time.After(10 * time.Second):
			}
		}
	}
}

// Stop signals the watcher to stop.
func (w *AuditLogWatcher) Stop() {
	close(w.stop)
}

// Path returns the audit log path being watched.
func (w *AuditLogWatcher) Path() string {
	return w.logPath
}

func (w *AuditLogWatcher) tail() error {
	f, err := os.Open(w.logPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// Start from end of file (only process new entries)
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	offset := fi.Size()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var partial string

	for {
		select {
		case <-w.stop:
			return nil
		case <-ticker.C:
		}

		fi, err = os.Stat(w.logPath)
		if err != nil {
			return err
		}

		size := fi.Size()
		if size <= offset {
			if size < offset {
				// File rotated — reset
				offset = 0
				partial = ""
			}
			continue
		}

		readF, err := os.Open(w.logPath)
		if err != nil {
			return err
		}

		readF.Seek(offset, io.SeekStart)
		buf := make([]byte, size-offset)
		n, readErr := io.ReadFull(readF, buf)
		readF.Close()

		if n > 0 {
			partial += string(buf[:n])
			offset += int64(n)

			// Try to parse complete entries (delimited by Z section)
			w.processBuffer(&partial)
		}

		if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
			return readErr
		}
	}
}

// processBuffer extracts complete audit log entries from the buffer.
// An entry is complete when we see a Z section boundary.
func (w *AuditLogWatcher) processBuffer(buf *string) {
	for {
		// Find the end of a complete entry (Z section marker)
		zIdx := strings.Index(*buf, "-Z--\n")
		if zIdx < 0 {
			// Also try without trailing newline (last entry in file)
			zIdx = strings.Index(*buf, "-Z--")
			if zIdx < 0 || zIdx+4 != len(*buf) {
				return
			}
		}

		// Extract the complete entry
		entryEnd := zIdx + 5 // include the newline after -Z--
		if entryEnd > len(*buf) {
			entryEnd = len(*buf)
		}
		entryText := (*buf)[:entryEnd]
		*buf = (*buf)[entryEnd:]

		entry := w.parseEntry(entryText)
		if entry == nil {
			continue
		}

		// Rate limit: skip if we recently reported this IP
		if entry.SourceIP != "" {
			w.mu.Lock()
			lastSeen, exists := w.recentIPs[entry.SourceIP]
			now := time.Now()
			if exists && now.Sub(lastSeen) < w.rateLimit {
				w.mu.Unlock()
				continue
			}
			w.recentIPs[entry.SourceIP] = now
			// Prune old entries periodically
			if len(w.recentIPs) > 1000 {
				for ip, t := range w.recentIPs {
					if now.Sub(t) > 5*time.Minute {
						delete(w.recentIPs, ip)
					}
				}
			}
			w.mu.Unlock()
		}

		// Only emit if there are rule matches
		if len(entry.Rules) > 0 {
			w.onEvent(*entry)
		}
	}
}

// parseEntry parses a single ModSecurity serial audit log entry.
func (w *AuditLogWatcher) parseEntry(text string) *AuditEntry {
	entry := &AuditEntry{}

	// Split into sections by boundary markers
	sections := make(map[string]string) // section letter -> content
	lines := strings.Split(text, "\n")

	var currentSection string
	var sectionLines []string

	for _, line := range lines {
		m := sectionBoundary.FindStringSubmatch(line)
		if m != nil {
			// Save previous section
			if currentSection != "" {
				sections[currentSection] = strings.Join(sectionLines, "\n")
			}
			currentSection = m[2]
			sectionLines = nil
			continue
		}
		if currentSection != "" {
			sectionLines = append(sectionLines, line)
		}
	}
	// Save last section
	if currentSection != "" {
		sections[currentSection] = strings.Join(sectionLines, "\n")
	}

	// Parse section A: timestamp, unique ID, source IP/port, dest IP/port
	if a, ok := sections["A"]; ok {
		w.parseSectionA(a, entry)
	}

	// Parse section B: request line + headers
	if b, ok := sections["B"]; ok {
		w.parseSectionB(b, entry)
	}

	// Parse section F: response headers (status code)
	if f, ok := sections["F"]; ok {
		w.parseSectionF(f, entry)
	}

	// Parse section H: rule matches, action, engine mode
	if h, ok := sections["H"]; ok {
		w.parseSectionH(h, entry)
	}

	// Skip entries with no source IP (malformed)
	if entry.SourceIP == "" {
		return nil
	}

	return entry
}

// parseSectionA extracts timestamp, unique ID, and connection info.
// Format: [timestamp] unique_id source_ip source_port dest_ip dest_port
func (w *AuditLogWatcher) parseSectionA(text string, entry *AuditEntry) {
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}

	// Extract timestamp in brackets
	if idx := strings.Index(text, "]"); idx > 0 {
		entry.Timestamp = strings.TrimPrefix(text[:idx+1], "[")
		text = strings.TrimSpace(text[idx+1:])
	}

	parts := strings.Fields(text)
	if len(parts) >= 1 {
		entry.UniqueID = parts[0]
	}
	if len(parts) >= 2 {
		entry.SourceIP = parts[1]
	}
	if len(parts) >= 3 {
		entry.SourcePort = parts[2]
	}
	if len(parts) >= 4 {
		entry.DestIP = parts[3]
	}
	if len(parts) >= 5 {
		entry.DestPort = parts[4]
	}
}

// parseSectionB extracts the request method, URI, and key headers.
func (w *AuditLogWatcher) parseSectionB(text string, entry *AuditEntry) {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) == 0 {
		return
	}

	// First line is the request line: METHOD URI PROTOCOL
	reqParts := strings.Fields(lines[0])
	if len(reqParts) >= 1 {
		entry.Method = reqParts[0]
	}
	if len(reqParts) >= 2 {
		entry.URI = reqParts[1]
		// Truncate long URIs
		if len(entry.URI) > 500 {
			entry.URI = entry.URI[:500]
		}
	}

	// Parse headers
	for _, line := range lines[1:] {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "host:") {
			entry.Host = strings.TrimSpace(line[5:])
		} else if strings.HasPrefix(lower, "user-agent:") {
			entry.UserAgent = strings.TrimSpace(line[11:])
			if len(entry.UserAgent) > 200 {
				entry.UserAgent = entry.UserAgent[:200]
			}
		}
	}
}

// parseSectionF extracts the response status code.
func (w *AuditLogWatcher) parseSectionF(text string, entry *AuditEntry) {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) == 0 {
		return
	}

	// First line: HTTP/1.1 403 Forbidden
	parts := strings.Fields(lines[0])
	if len(parts) >= 2 {
		entry.StatusCode = parts[1]
	}
}

// parseSectionH extracts rule matches, action, and engine mode.
func (w *AuditLogWatcher) parseSectionH(text string, entry *AuditEntry) {
	lines := strings.Split(text, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "Message:") {
			rule := RuleMatch{}

			if m := reRuleID.FindStringSubmatch(line); len(m) > 1 {
				rule.ID = m[1]
			}
			if m := reRuleMsg.FindStringSubmatch(line); len(m) > 1 {
				rule.Msg = m[1]
			}
			if m := reRuleData.FindStringSubmatch(line); len(m) > 1 {
				rule.Data = m[1]
				// Truncate matched data for privacy
				if len(rule.Data) > 200 {
					rule.Data = rule.Data[:200]
				}
			}
			if m := reRuleSeverity.FindStringSubmatch(line); len(m) > 1 {
				rule.Severity = m[1]
			}

			// Extract all tags
			for _, tm := range reRuleTag.FindAllStringSubmatch(line, -1) {
				if len(tm) > 1 {
					rule.Tags = append(rule.Tags, tm[1])
				}
			}

			// Only add rules that have an ID (skip generic messages)
			if rule.ID != "" {
				entry.Rules = append(entry.Rules, rule)
			}
		} else if strings.HasPrefix(line, "Action:") {
			entry.Action = strings.TrimSpace(strings.TrimPrefix(line, "Action:"))
		} else if strings.HasPrefix(line, "Engine-Mode:") {
			entry.EngineMode = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "Engine-Mode:")), "\"")
		}
	}
}

// HighestSeverity returns the highest severity from all rule matches.
// CRITICAL > ERROR > WARNING > NOTICE
func (e *AuditEntry) HighestSeverity() string {
	severityRank := map[string]int{
		"CRITICAL": 4,
		"ERROR":    3,
		"WARNING":  2,
		"NOTICE":   1,
	}

	highest := ""
	highestRank := 0

	for _, r := range e.Rules {
		if rank, ok := severityRank[r.Severity]; ok && rank > highestRank {
			highest = r.Severity
			highestRank = rank
		}
	}

	return highest
}

// AttackCategory extracts the primary attack category from rule tags.
// Returns tags like "attack-sqli", "attack-xss", etc.
func (e *AuditEntry) AttackCategory() string {
	for _, r := range e.Rules {
		for _, tag := range r.Tags {
			if strings.HasPrefix(tag, "attack-") {
				return tag
			}
		}
	}
	return "unknown"
}

// MapSeverityToDefensia converts ModSecurity severity to Defensia severity.
func MapSeverityToDefensia(modSecSeverity string) string {
	switch strings.ToUpper(modSecSeverity) {
	case "CRITICAL":
		return "critical"
	case "ERROR":
		return "high"
	case "WARNING":
		return "warning"
	case "NOTICE":
		return "info"
	default:
		return "info"
	}
}

// MapAttackToEventType converts CRS attack tags to Defensia event types.
func MapAttackToEventType(attackTag string) string {
	mapping := map[string]string{
		"attack-sqli":            "sql_injection",
		"attack-xss":            "xss_attempt",
		"attack-rce":            "rce_attempt",
		"attack-lfi":            "path_traversal",
		"attack-rfi":            "path_traversal",
		"attack-injection-php":  "rce_attempt",
		"attack-fixation":       "web_exploit",
		"attack-reputation-ip":  "web_exploit",
		"attack-generic":        "web_exploit",
		"attack-protocol":       "web_exploit",
		"attack-disclosure":     "config_probe",
	}

	if eventType, ok := mapping[attackTag]; ok {
		return eventType
	}
	return "modsecurity_block"
}
