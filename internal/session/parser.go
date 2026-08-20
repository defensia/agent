package session

import (
	"regexp"
	"strconv"
	"strings"
)

// LineType identifies the kind of auth.log event parsed.
type LineType int

const (
	SSHLogin  LineType = iota // Accepted password/publickey for user from IP port N
	SSHLogout                 // pam_unix(sshd:session): session closed for user
	Sudo                      // sudo: user : TTY=... ; PWD=... ; USER=... ; COMMAND=...
	Useradd                   // useradd[pid]: new user: name=...
	Userdel                   // userdel[pid]: delete user 'name'
	Passwd                    // passwd: pam_unix(passwd:chauthtok): password changed for user
	Crontab                   // crontab[pid]: (user) REPLACE/DELETE/LIST
	Su                        // su: pam_unix(su:session): session opened for user X by Y
)

// ParsedLine contains the structured fields extracted from one auth.log line.
type ParsedLine struct {
	Type       LineType
	PID        string            // sshd PID for login/logout; process PID for others
	User       string            // primary user (logged-in user, sudo actor, etc.)
	IP         string            // source IP (SSH only)
	Port       int               // source port (SSH only)
	Method     string            // "password" or "publickey" (SSH login only)
	TTY        string            // sudo TTY (e.g. "pts/0")
	PWD        string            // sudo working directory
	TargetUser string            // sudo target user; su target user
	ByUser     string            // su: user who initiated the su
	Command    string            // sudo COMMAND field
	Details    map[string]string // useradd fields: name, UID, GID, home, shell
	Raw        string            // original log line
}

// Package-level compiled regexes for zero-allocation matching.
var (
	// SSH login: sshd[PID]: Accepted METHOD for USER from IP port PORT
	reSSHLogin = regexp.MustCompile(
		`sshd\[(\d+)\]: Accepted (\w+) for (\S+) from ([\d.]+) port (\d+)`,
	)

	// SSH logout: sshd[PID]: pam_unix(sshd:session): session closed for user USER
	reSSHLogout = regexp.MustCompile(
		`sshd\[(\d+)\]: pam_unix\(sshd:session\): session closed for user (\S+)`,
	)

	// Sudo: sudo:   USER  : TTY=... ; PWD=... ; USER=... ; COMMAND=...
	reSudo = regexp.MustCompile(
		`sudo:\s+(\S+)\s+: TTY=(\S+) ; PWD=([^;]+) ; USER=(\S+) ; COMMAND=(.*)`,
	)

	// Useradd: useradd[PID]: new user: name=NAME, UID=N, GID=N, home=PATH, shell=SHELL
	reUseradd = regexp.MustCompile(
		`useradd\[(\d+)\]: new user: name=(\S+), UID=(\d+), GID=(\d+), home=([^,]+), shell=(\S+)`,
	)

	// Userdel: userdel[PID]: delete user 'NAME'
	reUserdel = regexp.MustCompile(
		`userdel\[(\d+)\]: delete user '(\S+)'`,
	)

	// Passwd: passwd.*pam_unix(passwd:chauthtok): password changed for USER
	rePasswd = regexp.MustCompile(
		`passwd.*pam_unix\(passwd:chauthtok\): password changed for (\S+)`,
	)

	// Crontab: crontab[PID]: (USER) REPLACE|DELETE|LIST
	reCrontab = regexp.MustCompile(
		`crontab\[(\d+)\]: \((\S+)\) (REPLACE|DELETE|LIST)`,
	)

	// Su: su.*pam_unix(su:session): session opened for user USER by BYUSER(uid=N)
	reSu = regexp.MustCompile(
		`su.*pam_unix\(su:session\): session opened for user (\S+) by (\S+)\(uid=\d+\)`,
	)
)

// ParseLine tries each regex in order and returns the first match.
// Returns nil if no pattern matches.
func ParseLine(line string) *ParsedLine {
	if m := reSSHLogin.FindStringSubmatch(line); m != nil {
		port, _ := strconv.Atoi(m[5])
		return &ParsedLine{
			Type:   SSHLogin,
			PID:    m[1],
			Method: m[2],
			User:   m[3],
			IP:     m[4],
			Port:   port,
			Raw:    line,
		}
	}

	if m := reSSHLogout.FindStringSubmatch(line); m != nil {
		return &ParsedLine{
			Type: SSHLogout,
			PID:  m[1],
			User: m[2],
			Raw:  line,
		}
	}

	if m := reSudo.FindStringSubmatch(line); m != nil {
		return &ParsedLine{
			Type:       Sudo,
			User:       m[1],
			TTY:        m[2],
			PWD:        strings.TrimSpace(m[3]),
			TargetUser: m[4],
			Command:    strings.TrimSpace(m[5]),
			Raw:        line,
		}
	}

	if m := reUseradd.FindStringSubmatch(line); m != nil {
		return &ParsedLine{
			Type: Useradd,
			PID:  m[1],
			Details: map[string]string{
				"name":  strings.TrimSuffix(m[2], ","),
				"UID":   m[3],
				"GID":   m[4],
				"home":  strings.TrimSpace(m[5]),
				"shell": m[6],
			},
			Raw: line,
		}
	}

	if m := reUserdel.FindStringSubmatch(line); m != nil {
		return &ParsedLine{
			Type: Userdel,
			PID:  m[1],
			User: m[2],
			Raw:  line,
		}
	}

	if m := rePasswd.FindStringSubmatch(line); m != nil {
		return &ParsedLine{
			Type: Passwd,
			User: m[1],
			Raw:  line,
		}
	}

	if m := reCrontab.FindStringSubmatch(line); m != nil {
		return &ParsedLine{
			Type: Crontab,
			PID:  m[1],
			User: m[2],
			Raw:  line,
		}
	}

	if m := reSu.FindStringSubmatch(line); m != nil {
		return &ParsedLine{
			Type:   Su,
			User:   m[1],
			ByUser: m[2],
			Raw:    line,
		}
	}

	return nil
}
