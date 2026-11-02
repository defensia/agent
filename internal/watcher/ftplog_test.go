package watcher

import "testing"

// Real log lines, as the three daemons actually write them. The point of this
// table is not that the regexes compile — it is to pin which fields each format
// genuinely carries, because every ftp_brute_force event we have ever emitted
// shipped an empty payload, and an alert nobody can verify is worse than none.
func TestFTPObservationFromRealLines(t *testing.T) {
	cases := []struct {
		name   string
		line   string
		reason string
		ip     string
		daemon string
		detail string
		user   string
	}{
		{
			name:   "vsftpd failed login names the account",
			line:   `Mon Nov  2 09:14:21 2026 [pid 2] [admin] FAIL LOGIN: Client "203.0.113.44", "admin"`,
			reason: "ftp_brute_force",
			ip:     "203.0.113.44",
			daemon: "vsftpd",
			detail: "login_failed",
			user:   "admin",
		},
		{
			name:   "vsftpd failed login without the account",
			line:   `Mon Nov  2 09:14:21 2026 [pid 2] FAIL LOGIN: Client "203.0.113.44"`,
			reason: "ftp_brute_force",
			ip:     "203.0.113.44",
			daemon: "vsftpd",
			detail: "login_failed",
		},
		{
			name:   "proftpd incorrect password",
			line:   `Nov  2 09:15:02 srv proftpd[4411] srv (client[198.51.100.7]): USER webmaster (Login failed): Incorrect password.`,
			reason: "ftp_brute_force",
			ip:     "198.51.100.7",
			daemon: "proftpd",
			detail: "login_failed",
			user:   "webmaster",
		},
		{
			name:   "proftpd unknown account",
			line:   `Nov  2 09:15:40 srv proftpd[4412] srv (client[198.51.100.7]): no such user 'oracle'`,
			reason: "ftp_brute_force",
			ip:     "198.51.100.7",
			daemon: "proftpd",
			detail: "no_such_user",
			user:   "oracle",
		},
		{
			name:   "pure-ftpd authentication failure",
			line:   `Nov  2 09:16:11 srv pure-ftpd: (?@192.0.2.55) [WARNING] Authentication failed for user [backup]`,
			reason: "ftp_brute_force",
			ip:     "192.0.2.55",
			daemon: "pure-ftpd",
			detail: "auth_failed",
			user:   "backup",
		},
	}

	for _, c := range cases {
		obs, ok := observeFTPLine(c.line)
		if !ok {
			t.Errorf("%s: no pattern matched the line", c.name)
			continue
		}
		if obs.Reason != c.reason {
			t.Errorf("%s: reason = %q, want %q", c.name, obs.Reason, c.reason)
		}
		if obs.IP != c.ip {
			t.Errorf("%s: ip = %q, want %q", c.name, obs.IP, c.ip)
		}
		if obs.Daemon != c.daemon {
			t.Errorf("%s: daemon = %q, want %q", c.name, obs.Daemon, c.daemon)
		}
		if obs.Detail != c.detail {
			t.Errorf("%s: detail = %q, want %q", c.name, obs.Detail, c.detail)
		}
		if obs.User != c.user {
			t.Errorf("%s: user = %q, want %q", c.name, obs.User, c.user)
		}
	}
}

func TestFTPLinesThatMustNotMatch(t *testing.T) {
	for _, line := range []string{
		`Nov  2 09:14:00 srv vsftpd: [pid 2] [admin] OK LOGIN: Client "203.0.113.44"`,
		`Nov  2 09:14:00 srv sshd[99]: Accepted password for root from 203.0.113.44 port 22 ssh2`,
		``,
	} {
		if obs, ok := observeFTPLine(line); ok {
			t.Errorf("observeFTPLine(%q) matched as %+v, want no match", line, obs)
		}
	}
}

// The payload must distinguish "this log line did not say" from "empty", so a
// consumer can treat an absent key as normal instead of as an error.
func TestFTPDetailsOmitsWhatTheLineDidNotCarry(t *testing.T) {
	full := ftpObservation{IP: "1.2.3.4", Reason: "ftp_brute_force", Daemon: "vsftpd", Detail: "login_failed", User: "admin"}
	d := full.details(7)
	for key, want := range map[string]string{
		"attempts":    "7",
		"service":     "vsftpd",
		"reason":      "login_failed",
		"target_user": "admin",
	} {
		if d[key] != want {
			t.Errorf("details()[%q] = %q, want %q", key, d[key], want)
		}
	}

	bare := ftpObservation{IP: "1.2.3.4", Reason: "ftp_brute_force", Daemon: "vsftpd", Detail: "login_failed"}
	if _, present := bare.details(1)["target_user"]; present {
		t.Error("details() invented a target_user the log line never carried")
	}
	if len(bare.details(1)) == 0 {
		t.Error("details() returned an empty map; that is the defect this replaces")
	}
}
