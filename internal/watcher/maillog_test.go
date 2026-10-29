package watcher

import "testing"

// observe delegates to the production extraction, so this table tests the
// real code path rather than a re-implementation of it.
func observe(line string) (mailObservation, bool) {
	return observeMailLine(line)
}

// Real log lines, as the three servers actually write them. The point of this
// table is not that the regexes compile — it is to pin which fields each
// format genuinely carries, because an MSP is building an alerting pipeline on
// top of these events and a field that is present two thirds of the time is
// worse than one documented as optional.
func TestMailObservationFromRealLines(t *testing.T) {
	cases := []struct {
		name     string
		line     string
		reason   string
		ip       string
		user     string
		method   string
		protocol string
		detail   string
		rcpt     string
	}{
		{
			// The case the customer cares most about: an IMAP brute force.
			// Dovecot names the mailbox and the mechanism.
			name:     "dovecot imap login failure",
			line:     `Oct 29 07:12:03 mail dovecot: imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<sales@clientdomain.co.uk>, method=PLAIN, rip=157.66.48.88, lip=10.0.0.5, TLS`,
			reason:   "mail_brute_force",
			ip:       "157.66.48.88",
			user:     "sales@clientdomain.co.uk",
			method:   "PLAIN",
			protocol: "imap",
		},
		{
			name:     "dovecot pop3 login failure",
			line:     `Oct 29 07:12:03 mail dovecot: pop3-login: Aborted login (auth failed, 2 attempts): user=<info@example.com>, method=LOGIN, rip=203.0.113.9, lip=10.0.0.5`,
			reason:   "mail_brute_force",
			ip:       "203.0.113.9",
			user:     "info@example.com",
			method:   "LOGIN",
			protocol: "pop3",
		},
		{
			name:     "dovecot password mismatch",
			line:     `Oct 29 07:13:10 mail dovecot: auth: passwd-file(sales@clientdomain.co.uk,157.66.48.88): Password mismatch`,
			reason:   "mail_brute_force",
			ip:       "157.66.48.88",
			user:     "sales@clientdomain.co.uk",
			protocol: "",
		},
		{
			name:   "dovecot unknown user",
			line:   `Oct 29 07:13:11 mail dovecot: auth: passwd-file(nosuch@example.com,198.51.100.4): unknown user`,
			reason: "mail_brute_force",
			ip:     "198.51.100.4",
			user:   "nosuch@example.com",
		},
		{
			// Postfix SASL: the mechanism is there, the mailbox is NOT. This is
			// the honest limitation to document rather than paper over.
			name:     "postfix sasl failure has no username",
			line:     `Oct 29 07:14:02 mail postfix/smtpd[2048]: warning: unknown[185.220.101.7]: SASL LOGIN authentication failed: UGFzc3dvcmQ6`,
			reason:   "mail_brute_force",
			ip:       "185.220.101.7",
			user:     "",
			method:   "LOGIN",
			protocol: "smtp",
		},
		{
			name:     "postfix relay denied names the recipient",
			line:     `Oct 29 07:15:00 mail postfix/smtpd[2049]: NOQUEUE: reject: RCPT from unknown[91.240.118.3]: 554 5.7.1 <victim@clientdomain.co.uk>: Relay access denied; from=<spam@bad.tld> to=<victim@clientdomain.co.uk> proto=ESMTP helo=<x>`,
			reason:   "mail_relay_scan",
			ip:       "91.240.118.3",
			protocol: "smtp",
			detail:   "relay_denied",
			rcpt:     "victim@clientdomain.co.uk",
		},
		{
			name:     "postfix unresolvable hostname",
			line:     `Oct 29 07:16:00 mail postfix/smtpd[2050]: warning: 45.137.21.9: hostname bad.tld does not resolve`,
			reason:   "mail_suspicious",
			ip:       "45.137.21.9",
			protocol: "smtp",
			detail:   "unresolvable_hostname",
		},
		{
			name:     "postfix command pipelining",
			line:     `Oct 29 07:17:00 mail postfix/smtpd[2051]: improper command pipelining after AUTH from unknown[45.137.21.10]`,
			reason:   "mail_suspicious",
			ip:       "45.137.21.10",
			protocol: "smtp",
			detail:   "command_pipelining",
		},
		{
			name:     "roundcube login failure",
			line:     `Oct 29 07:18:00 web roundcube: IMAP Error: Login failed for sales@clientdomain.co.uk against mail.clientdomain.co.uk from 157.66.48.88`,
			reason:   "mail_brute_force",
			ip:       "157.66.48.88",
			user:     "sales@clientdomain.co.uk",
			protocol: "imap",
		},
		{
			name:     "postfix too many errors after auth",
			line:     `Oct 29 07:19:00 mail postfix/smtpd[2052]: too many errors after AUTH from unknown[185.220.101.8]`,
			reason:   "mail_brute_force",
			ip:       "185.220.101.8",
			protocol: "smtp",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			obs, ok := observe(c.line)
			if !ok {
				t.Fatalf("line did not match any pattern:\n  %s", c.line)
			}
			if obs.Reason != c.reason {
				t.Errorf("reason = %q, want %q", obs.Reason, c.reason)
			}
			if obs.IP != c.ip {
				t.Errorf("ip = %q, want %q", obs.IP, c.ip)
			}
			if obs.User != c.user {
				t.Errorf("user = %q, want %q", obs.User, c.user)
			}
			if obs.Method != c.method {
				t.Errorf("method = %q, want %q", obs.Method, c.method)
			}
			if obs.Protocol != c.protocol {
				t.Errorf("protocol = %q, want %q", obs.Protocol, c.protocol)
			}
			if obs.Detail != c.detail {
				t.Errorf("detail = %q, want %q", obs.Detail, c.detail)
			}
			if obs.Rcpt != c.rcpt {
				t.Errorf("rcpt = %q, want %q", obs.Rcpt, c.rcpt)
			}
		})
	}
}

// The payload is what an API consumer parses, so its shape is the contract.
func TestMailDetailsPayload(t *testing.T) {
	obs, ok := observe(`Oct 29 07:12:03 mail dovecot: imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<sales@clientdomain.co.uk>, method=PLAIN, rip=157.66.48.88, lip=10.0.0.5, TLS`)
	if !ok {
		t.Fatal("line did not match")
	}

	d := obs.details(3)

	want := map[string]string{
		"target_user": "sales@clientdomain.co.uk",
		"protocol":    "imap",
		"auth_method": "plain", // lowercased: the mechanism is not case-bearing
		"attempts":    "3",
	}
	for k, v := range want {
		if d[k] != v {
			t.Errorf("details[%q] = %q, want %q", k, d[k], v)
		}
	}
	if len(d) != len(want) {
		t.Errorf("payload has %d keys, want %d: %+v", len(d), len(want), d)
	}
}

// A field the line does not carry is absent, not empty-string. A consumer must
// be able to tell "this format has no mailbox" from "the mailbox was blank".
func TestMailDetailsOmitsWhatTheLineLacks(t *testing.T) {
	obs, ok := observe(`Oct 29 07:14:02 mail postfix/smtpd[2048]: warning: unknown[185.220.101.7]: SASL LOGIN authentication failed: UGFzc3dvcmQ6`)
	if !ok {
		t.Fatal("line did not match")
	}

	d := obs.details(1)

	if _, present := d["target_user"]; present {
		t.Errorf("target_user must be absent for Postfix SASL, got %q", d["target_user"])
	}
	if d["auth_method"] != "login" {
		t.Errorf("auth_method = %q, want login", d["auth_method"])
	}
	if d["protocol"] != "smtp" {
		t.Errorf("protocol = %q, want smtp", d["protocol"])
	}
}

// The relay payload carries both the full recipient and its domain, because an
// MSP watching several client domains wants to group by domain without parsing.
func TestMailDetailsSplitsTheRecipientDomain(t *testing.T) {
	obs, ok := observe(`Oct 29 07:15:00 mail postfix/smtpd[2049]: NOQUEUE: reject: RCPT from unknown[91.240.118.3]: 554 5.7.1 <victim@clientdomain.co.uk>: Relay access denied; from=<spam@bad.tld> to=<victim@clientdomain.co.uk> proto=ESMTP helo=<x>`)
	if !ok {
		t.Fatal("line did not match")
	}

	d := obs.details(1)

	if d["rcpt_to"] != "victim@clientdomain.co.uk" {
		t.Errorf("rcpt_to = %q", d["rcpt_to"])
	}
	if d["rcpt_domain"] != "clientdomain.co.uk" {
		t.Errorf("rcpt_domain = %q", d["rcpt_domain"])
	}
	if d["reason"] != "relay_denied" {
		t.Errorf("reason = %q", d["reason"])
	}
}

// `attempts` must always be present: it is the one field every format can
// supply, and it is what tells an operator whether this is one typo or a run.
func TestMailDetailsAlwaysCarriesAttempts(t *testing.T) {
	for _, line := range []string{
		`Oct 29 07:14:02 mail postfix/smtpd[2048]: warning: unknown[185.220.101.7]: SASL LOGIN authentication failed: UGFzc3dvcmQ6`,
		`Oct 29 07:16:00 mail postfix/smtpd[2050]: warning: 45.137.21.9: hostname bad.tld does not resolve`,
		`Oct 29 07:12:03 mail dovecot: imap-login: Disconnected (auth failed): user=<a@b.c>, method=PLAIN, rip=203.0.113.9`,
	} {
		obs, ok := observe(line)
		if !ok {
			t.Fatalf("line did not match: %s", line)
		}
		if obs.details(7)["attempts"] != "7" {
			t.Errorf("attempts missing or wrong for: %s", line)
		}
	}
}

// The source address must never be reported as the targeted mailbox. The
// Dovecot "(user,ip)" extractor can otherwise pick up the IP on lines that
// omit the username.
func TestMailUserIsNeverTheSourceIP(t *testing.T) {
	obs, ok := observe(`Oct 29 07:20:00 mail dovecot: auth: passwd-file(203.0.113.77,203.0.113.77): Password mismatch`)
	if !ok {
		t.Fatal("line did not match")
	}
	if obs.User != "" {
		t.Errorf("user = %q, want empty — the source IP is not a mailbox", obs.User)
	}
	if _, present := obs.details(1)["target_user"]; present {
		t.Error("target_user must be absent, not the source IP")
	}
}

// Private source addresses are dropped before enrichment, unchanged behaviour.
func TestMailPrivateIPsStillIgnored(t *testing.T) {
	for _, ip := range []string{"10.0.0.5", "192.168.1.9", "172.16.0.3", "127.0.0.1"} {
		if !isPrivateIP(ip) {
			t.Errorf("%s should be treated as private", ip)
		}
	}
}
