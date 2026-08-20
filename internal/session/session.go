package session

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Config holds session tracker configuration.
type Config struct {
	Enabled bool
}

// noisyUsers are service accounts that generate massive SSH session spam.
// These are automated monitoring/polling tools, not human sessions.
var noisyUsers = map[string]bool{
	"cacti":         true, // Cacti SNMP/metrics polling (~8 sessions/5min)
	"nagios":        true, // Nagios monitoring checks
	"zabbix":        true, // Zabbix agent polling
	"munin":         true, // Munin node stats
	"prometheus":    true, // Prometheus node_exporter
	"telegraf":      true, // Telegraf collector
	"monit":         true, // Monit process monitor
	"nrpe":          true, // Nagios Remote Plugin Executor
	"icinga":        true, // Icinga monitoring
	"checkmk":       true, // Checkmk monitoring
	"librenms":      true, // LibreNMS polling
	"observium":     true, // Observium polling
	"datadog-agent": true, // Datadog agent
}

// isNoisySession returns true for automated sessions that should be skipped.
// Filters: known monitoring users + private IPs with non-root users (internal tools).
func isNoisySession(user, ip string) bool {
	// Always skip known monitoring tool users
	if noisyUsers[user] {
		return true
	}

	// Skip non-root sessions from private IPs (internal automation like Cacti, Ansible, etc.)
	// Root from private IP is kept — could be an admin on the LAN
	if user != "root" && isPrivateIP(ip) {
		return true
	}

	return false
}

// isPrivateIP checks if an IP is in RFC1918/RFC4193 private ranges.
func isPrivateIP(ip string) bool {
	return strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "172.16.") || strings.HasPrefix(ip, "172.17.") ||
		strings.HasPrefix(ip, "172.18.") || strings.HasPrefix(ip, "172.19.") ||
		strings.HasPrefix(ip, "172.2") || strings.HasPrefix(ip, "172.30.") ||
		strings.HasPrefix(ip, "172.31.") ||
		strings.HasPrefix(ip, "192.168.") ||
		ip == "127.0.0.1" || ip == "::1"
}

// SessionConfig is the panel-synced configuration type embedded in SyncConfig.
// It is defined here so the session package is self-contained; api/client.go
// re-exports it as its own type (same JSON shape).
type SessionConfig struct {
	Enabled bool `json:"enabled"`
}

// EventFunc is called when a session closes (ssh_session) or a privileged operation occurs (system_audit).
// The tracker is monitor-only — it never bans IPs.
type EventFunc func(eventType, severity string, details map[string]string)

// Session tracks an active SSH session keyed by sshd PID.
type Session struct {
	PID       string
	User      string
	IP        string
	Port      int
	Method    string // "password" or "publickey"
	LoginAt   time.Time
	Commands  []CommandEntry
	SigmaHits int // correlated Sigma alerts during this session
}

// SessionTracker watches auth.log and tracks SSH sessions from login to logout.
type SessionTracker struct {
	mu       sync.Mutex
	config   Config
	onEvent  EventFunc
	sessions map[string]*Session // keyed by sshd PID
	knownIPs map[string]bool     // IPs seen before (persisted across sessions on this server)
	lastEmit map[string]time.Time // dedup: "ip:user" → last event time
	cancel   context.CancelFunc
	running  atomic.Bool
}

// New creates a new SessionTracker.
func New(onEvent EventFunc) *SessionTracker {
	return &SessionTracker{
		onEvent:  onEvent,
		sessions: make(map[string]*Session),
		knownIPs: make(map[string]bool),
		lastEmit: make(map[string]time.Time),
	}
}

// IsRunning returns true if the tracker goroutine is active.
func (t *SessionTracker) IsRunning() bool { return t.running.Load() }

// UpdateConfig reconfigures the tracker at runtime.
func (t *SessionTracker) UpdateConfig(cfg Config) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.config = cfg
}

// Run starts tailing auth.log. Blocks until Stop() is called.
func (t *SessionTracker) Run() {
	if !t.running.CompareAndSwap(false, true) {
		return // already running
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.mu.Lock()
	t.cancel = cancel
	t.mu.Unlock()

	logPath := detectAuthLogPath()
	log.Printf("[session] starting tracker on %s", logPath)

	// Tail goroutine
	go func() {
		for {
			if err := t.tail(ctx, logPath); err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("[session] error tailing %s: %v — retrying in 5s", logPath, err)
				time.Sleep(5 * time.Second)
			}
		}
	}()

	// Cleanup goroutine: auto-close sessions older than 24h
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				t.cleanupSessions()
			}
		}
	}()

	<-ctx.Done()
	t.running.Store(false)
}

// Stop signals the tracker to stop.
func (t *SessionTracker) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cancel != nil {
		t.cancel()
	}
}

// tail reads new lines from auth.log with rotation detection.
func (t *SessionTracker) tail(ctx context.Context, path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	offset := fi.Size() // start from EOF — skip historical lines

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}

		fi, err = os.Stat(path)
		if err != nil {
			return err
		}

		size := fi.Size()
		if size <= offset {
			if size < offset {
				offset = 0 // rotation detected
			}
			continue
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}

		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			f.Close()
			return err
		}

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if len(line) > 0 {
				t.processLine(line)
			}
		}

		offset = size
		f.Close()
	}
}

// cleanupSessions closes sessions that have been open for more than 24 hours.
func (t *SessionTracker) cleanupSessions() {
	t.mu.Lock()
	var stale []string
	for pid, sess := range t.sessions {
		if time.Since(sess.LoginAt) > 24*time.Hour {
			stale = append(stale, pid)
		}
	}
	// Copy sessions to close (release lock before calling closeSession which re-locks)
	toClose := make([]*Session, 0, len(stale))
	for _, pid := range stale {
		toClose = append(toClose, t.sessions[pid])
		delete(t.sessions, pid)
	}
	t.mu.Unlock()

	for _, sess := range toClose {
		t.closeSession(sess, "timeout")
	}
}

// processLine is the core state machine: parses a line and updates session state.
func (t *SessionTracker) processLine(line string) {
	t.mu.Lock()
	enabled := t.config.Enabled
	t.mu.Unlock()

	if !enabled {
		return
	}

	parsed := ParseLine(line)
	if parsed == nil {
		return
	}

	// Skip noisy automated sessions: monitoring tools, service accounts, private IPs
	if parsed.Type == SSHLogin && isNoisySession(parsed.User, parsed.IP) {
		return
	}

	switch parsed.Type {
	case SSHLogin:
		// Dedup: same IP+user within 2 minutes → skip (deploy scripts, sshpass chains)
		dedupKey := parsed.IP + ":" + parsed.User
		t.mu.Lock()
		if last, ok := t.lastEmit[dedupKey]; ok && time.Since(last) < 2*time.Minute {
			// Still track the session internally (for commands) but don't emit event
			sess := &Session{
				PID:     parsed.PID,
				User:    parsed.User,
				IP:      parsed.IP,
				Port:    parsed.Port,
				Method:  parsed.Method,
				LoginAt: time.Now(),
			}
			t.sessions[parsed.PID] = sess
			t.mu.Unlock()
			return
		}
		t.lastEmit[dedupKey] = time.Now()

		sess := &Session{
			PID:     parsed.PID,
			User:    parsed.User,
			IP:      parsed.IP,
			Port:    parsed.Port,
			Method:  parsed.Method,
			LoginAt: time.Now(),
		}
		t.sessions[parsed.PID] = sess
		t.knownIPs[parsed.IP] = true
		t.mu.Unlock()

		t.onEvent("system_audit", "info", map[string]string{
			"operation": "ssh_login",
			"user":      parsed.User,
			"ip":        parsed.IP,
			"method":    parsed.Method,
			"port":      strconv.Itoa(parsed.Port),
		})

	case SSHLogout:
		t.mu.Lock()
		sess, ok := t.sessions[parsed.PID]
		if ok {
			delete(t.sessions, parsed.PID)
		}
		t.mu.Unlock()

		if ok {
			t.closeSession(sess, "logout")
		}

	case Sudo:
		cmd := CommandEntry{
			Type:    "sudo",
			Command: parsed.Command,
			User:    parsed.User,
		}
		t.appendCommandToUser(parsed.User, cmd)

		t.onEvent("system_audit", "info", map[string]string{
			"operation":   "sudo",
			"user":        parsed.User,
			"target_user": parsed.TargetUser,
			"command":     parsed.Command,
			"pwd":         parsed.PWD,
		})

	case Useradd:
		cmd := CommandEntry{
			Type:    "useradd",
			Command: "useradd",
			Details: parsed.Details,
		}
		t.appendCommandToAllSessions(cmd)

		t.onEvent("system_audit", "warning", map[string]string{
			"operation": "useradd",
			"name":      parsed.Details["name"],
			"uid":       parsed.Details["UID"],
			"gid":       parsed.Details["GID"],
			"home":      parsed.Details["home"],
			"shell":     parsed.Details["shell"],
		})

	case Userdel:
		cmd := CommandEntry{
			Type:    "userdel",
			Command: "userdel",
			User:    parsed.User,
		}
		t.appendCommandToAllSessions(cmd)

		t.onEvent("system_audit", "warning", map[string]string{
			"operation": "userdel",
			"user":      parsed.User,
		})

	case Passwd:
		cmd := CommandEntry{
			Type:    "passwd",
			Command: "passwd",
			User:    parsed.User,
		}
		t.appendCommandToAllSessions(cmd)

		t.onEvent("system_audit", "info", map[string]string{
			"operation": "passwd",
			"user":      parsed.User,
		})

	case Crontab:
		cmd := CommandEntry{
			Type:    "crontab",
			Command: "crontab",
			User:    parsed.User,
		}
		t.appendCommandToUser(parsed.User, cmd)

		t.onEvent("system_audit", "info", map[string]string{
			"operation": "crontab",
			"user":      parsed.User,
		})

	case Su:
		cmd := CommandEntry{
			Type:    "su",
			Command: "su",
			User:    parsed.ByUser,
		}
		t.appendCommandToUser(parsed.ByUser, cmd)

		t.onEvent("system_audit", "info", map[string]string{
			"operation": "su",
			"user":      parsed.User,
			"by_user":   parsed.ByUser,
		})
	}
}

// appendCommandToUser appends a command to all sessions matching the given user.
func (t *SessionTracker) appendCommandToUser(user string, cmd CommandEntry) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, sess := range t.sessions {
		if sess.User == user {
			sess.Commands = append(sess.Commands, cmd)
		}
	}
}

// appendCommandToAllSessions appends a command to all active sessions.
func (t *SessionTracker) appendCommandToAllSessions(cmd CommandEntry) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, sess := range t.sessions {
		sess.Commands = append(sess.Commands, cmd)
	}
}

// closeSession calculates risk, determines severity, and emits an ssh_session event.
// Sessions with 0 commands and duration < 5s are suppressed (sshpass/deploy noise).
func (t *SessionTracker) closeSession(s *Session, reason string) {
	duration := time.Since(s.LoginAt)

	// Suppress empty short sessions (sshpass one-liners from deploy scripts)
	if len(s.Commands) == 0 && duration < 5*time.Second {
		return
	}
	t.mu.Lock()
	knownIPsCopy := make(map[string]bool, len(t.knownIPs))
	for k, v := range t.knownIPs {
		knownIPsCopy[k] = v
	}
	t.mu.Unlock()

	data := SessionData{
		AuthMethod:  s.Method,
		IP:          s.IP,
		User:        s.User,
		LoginHour:   s.LoginAt.Hour(),
		Commands:    s.Commands,
		KnownIPs:    knownIPsCopy,
		SigmaAlerts: s.SigmaHits,
	}

	risk := CalculateRisk(data)

	var severity string
	switch {
	case risk.Score >= 50:
		severity = "critical"
	case risk.Score >= 25:
		severity = "warning"
	default:
		severity = "info"
	}

	// Encode command timeline as JSON, truncated to 2000 chars
	cmdJSON, _ := json.Marshal(s.Commands)
	cmdStr := string(cmdJSON)
	if len(cmdStr) > 2000 {
		cmdStr = cmdStr[:2000]
	}

	details := map[string]string{
		"user":             s.User,
		"ip":               s.IP,
		"method":           s.Method,
		"port":             strconv.Itoa(s.Port),
		"duration_seconds": strconv.FormatInt(int64(duration.Seconds()), 10),
		"login_at":         s.LoginAt.UTC().Format(time.RFC3339),
		"command_count":    strconv.Itoa(len(s.Commands)),
		"commands":         cmdStr,
		"risk_score":       strconv.Itoa(risk.Score),
		"risk_factors":     strings.Join(risk.Factors, ","),
		"close_reason":     reason,
	}

	t.onEvent("ssh_session", severity, details)
}

// detectAuthLogPath returns the auth log path: checks AUTH_LOG_PATH env,
// then auto-detects between Debian/Ubuntu (/var/log/auth.log) and RHEL/CentOS (/var/log/secure).
func detectAuthLogPath() string {
	if p := os.Getenv("AUTH_LOG_PATH"); p != "" {
		return p
	}
	if _, err := os.Stat("/var/log/auth.log"); err == nil {
		return "/var/log/auth.log"
	}
	if _, err := os.Stat("/var/log/secure"); err == nil {
		return "/var/log/secure"
	}
	return "/var/log/auth.log"
}
