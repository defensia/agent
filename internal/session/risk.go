package session

import (
	"regexp"
	"strings"
)

// RiskResult holds the total score and the contributing factor names.
type RiskResult struct {
	Score   int
	Factors []string
}

// SessionData is the snapshot of a session passed to CalculateRisk.
type SessionData struct {
	AuthMethod  string            // "password" or "publickey"
	IP          string
	User        string
	LoginHour   int               // 0-23
	Commands    []CommandEntry
	KnownIPs    map[string]bool   // IPs seen before on this server
	SigmaAlerts int               // number of correlated Sigma alerts during the session
}

// CommandEntry records one privileged operation captured during a session.
type CommandEntry struct {
	Type    string            // "sudo", "useradd", "userdel", "passwd", "crontab", "su"
	Command string            // full command for sudo; descriptive string for others
	User    string
	Details map[string]string // useradd fields: name, UID, GID, home, shell
}

// Dangerous command patterns used by CalculateRisk.
var (
	reSensitiveRead = regexp.MustCompile(`cat\s+/etc/(shadow|passwd)`)
	reRemoteExec    = regexp.MustCompile(`(wget|curl).*\|.*(bash|sh)`)
)

// CalculateRisk computes a risk score (0-100) for a completed session.
// Each matching factor adds points; the total is capped at 100.
func CalculateRisk(data SessionData) RiskResult {
	var score int
	var factors []string

	add := func(points int, factor string) {
		score += points
		factors = append(factors, factor)
	}

	// Auth method risk
	if data.AuthMethod == "password" {
		add(15, "password_auth")
	}

	// Unknown source IP
	if len(data.KnownIPs) == 0 || !data.KnownIPs[data.IP] {
		add(20, "unknown_ip")
	}

	// Night-time login (22:00-05:59)
	if data.LoginHour >= 22 || data.LoginHour <= 5 {
		add(10, "night_login")
	}

	// Per-command analysis
	addedSensitiveRead := false
	addedRemoteExec := false
	addedRootUserCreation := false
	addedUserDeletion := false
	addedPasswdChange := false
	addedCrontab := false

	for _, cmd := range data.Commands {
		switch cmd.Type {
		case "sudo":
			cmdLower := strings.ToLower(cmd.Command)
			if !addedSensitiveRead && reSensitiveRead.MatchString(cmdLower) {
				add(30, "sensitive_file_read")
				addedSensitiveRead = true
			}
			if !addedRemoteExec && reRemoteExec.MatchString(cmdLower) {
				add(30, "remote_code_exec")
				addedRemoteExec = true
			}

		case "useradd":
			if !addedRootUserCreation && cmd.Details["UID"] == "0" {
				add(25, "root_user_creation")
				addedRootUserCreation = true
			}

		case "userdel":
			if !addedUserDeletion {
				add(15, "user_deletion")
				addedUserDeletion = true
			}

		case "passwd":
			if !addedPasswdChange {
				add(10, "password_change")
				addedPasswdChange = true
			}

		case "crontab":
			if !addedCrontab {
				add(10, "crontab_modification")
				addedCrontab = true
			}
		}
	}

	// Sigma alert correlation
	if data.SigmaAlerts > 0 {
		add(40*data.SigmaAlerts, "sigma_correlation")
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return RiskResult{
		Score:   score,
		Factors: factors,
	}
}
