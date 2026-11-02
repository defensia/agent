package watcher

import "testing"

// Real log lines from the three engines. These events shipped an empty payload,
// which is what made a disputed db_exposed finding impossible to adjudicate
// against our own record.
func TestDBObservationFromRealLines(t *testing.T) {
	cases := []struct {
		name   string
		line   string
		reason string
		ip     string
		engine string
		detail string
		user   string
	}{
		{
			name:   "mysql access denied names the account",
			line:   `2026-11-02T09:20:11.441122Z 41 [Note] Access denied for user 'root'@'203.0.113.44' (using password: YES)`,
			reason: "db_brute_force",
			ip:     "203.0.113.44",
			engine: "mysql",
			detail: "access_denied",
			user:   "root",
		},
		{
			name:   "mysql host blocked",
			line:   `2026-11-02T09:21:00.001Z 0 [Warning] Host '198.51.100.7' is blocked because of many connection errors; unblock with 'mysqladmin flush-hosts'`,
			reason: "db_brute_force",
			ip:     "198.51.100.7",
			engine: "mysql",
			detail: "host_blocked",
		},
		{
			name:   "postgres password failure",
			line:   `2026-11-02 09:22:14.882 UTC [881] FATAL:  password authentication failed for user "postgres" connection host=192.0.2.55 port=5432`,
			reason: "db_brute_force",
			ip:     "192.0.2.55",
			engine: "postgresql",
			detail: "password_auth_failed",
			user:   "postgres",
		},
		{
			name:   "postgres no pg_hba entry",
			line:   `2026-11-02 09:23:01.004 UTC [882] FATAL:  no pg_hba.conf entry for host "192.0.2.56", user "admin", database "app", no encryption`,
			reason: "db_brute_force",
			ip:     "192.0.2.56",
			engine: "postgresql",
			detail: "no_pg_hba_entry",
			user:   "admin",
		},
		{
			name:   "mongodb auth failure",
			line:   `{"t":"2026-11-02T09:24:00.112Z","s":"I","c":"ACCESS","msg":"Authentication failed","attr":{"client:203.0.113.90"}}`,
			reason: "db_brute_force",
			ip:     "203.0.113.90",
			engine: "mongodb",
			detail: "auth_failed",
		},
	}

	for _, c := range cases {
		obs, ok := observeDBLine(c.line)
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
		if obs.Engine != c.engine {
			t.Errorf("%s: engine = %q, want %q", c.name, obs.Engine, c.engine)
		}
		if obs.Detail != c.detail {
			t.Errorf("%s: detail = %q, want %q", c.name, obs.Detail, c.detail)
		}
		if obs.User != c.user {
			t.Errorf("%s: user = %q, want %q", c.name, obs.User, c.user)
		}
	}
}

func TestDBDetailsOmitsWhatTheLineDidNotCarry(t *testing.T) {
	bare := dbObservation{IP: "1.2.3.4", Reason: "db_brute_force", Engine: "mysql", Detail: "host_blocked"}
	d := bare.details(3)
	if d["attempts"] != "3" || d["engine"] != "mysql" || d["reason"] != "host_blocked" {
		t.Errorf("details() = %v, missing what the line did carry", d)
	}
	if _, present := d["target_user"]; present {
		t.Error("details() invented a target_user the log line never carried")
	}
}
