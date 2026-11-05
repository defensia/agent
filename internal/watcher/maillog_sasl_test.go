package watcher

import (
	"testing"
	"time"
)

// The lines Dovecot writes when it is Postfix's SASL backend.
//
// The base64 Postfix appends to "SASL LOGIN authentication failed" is the
// server's own challenge ("Password:"), identical on every failure whoever was
// targeted, so it is never a source for the account. This file was originally
// written believing that made the Dovecot line the ONLY place the account
// appears. It is not: Postfix adds sasl_username to the same warning whenever
// the mechanism reached the auth backend, and that is now the first thing we
// read — see mailUserPatterns. The Dovecot path below still matters for IMAP
// and POP3, and for SMTP failures that arrive without the field.
//
// Dovecot does not write its line from the `auth` process. Password lookups
// are delegated to a worker that identifies itself as `auth-worker(1234)`, and
// it is that worker which serves Postfix's requests over the auth socket. A
// pattern anchored on the literal `auth:` therefore discards exactly the line
// that carries the name.
//
// Reported by Kaburu MSP. The figure first recorded here — 644 mail events in
// seven days, none naming an account — was wrong: it summed mail_brute_force,
// mail_relay_scan and mail_suspicious, and only the first are authentication
// attempts. Measured properly on that server: 341 SMTP AUTH failures, 312 of
// them carrying a sasl_username we were not reading.
func TestDovecotAuthWorkerLinesNameTheMailbox(t *testing.T) {
	cases := []struct {
		name string
		line string
		user string
		ip   string
	}{
		{
			name: "auth-worker password mismatch",
			line: `Nov  3 10:15:04 mail dovecot: auth-worker(2451): passwd-file(sales@example.com,203.0.113.5): Password mismatch`,
			user: "sales@example.com",
			ip:   "203.0.113.5",
		},
		{
			name: "auth-worker unknown user",
			line: `Nov  3 10:15:04 mail dovecot: auth-worker(2451): sql(bob@example.com,198.51.100.9): unknown user`,
			user: "bob@example.com",
			ip:   "198.51.100.9",
		},
		{
			// Dovecot appends a session id when it has one, which the previous
			// pattern could not get past either.
			name: "auth-worker with a session id",
			line: `Nov  3 10:15:04 mail dovecot: auth-worker(2451): pam(ana@example.com,192.0.2.44,<Hs7bQw>): Password mismatch`,
			user: "ana@example.com",
			ip:   "192.0.2.44",
		},
		{
			name: "auth process with a session id",
			line: `Nov  3 10:15:04 mail dovecot: auth: Info: passwd-file(joe@example.com,192.0.2.7,<K2p9Lm>): unknown user`,
			user: "joe@example.com",
			ip:   "192.0.2.7",
		},
		// The forms that already worked must keep working.
		{
			name: "auth process, no session id",
			line: `Nov  3 10:15:04 mail dovecot: auth: passwd-file(sales@example.com,203.0.113.5): Password mismatch`,
			user: "sales@example.com",
			ip:   "203.0.113.5",
		},
		{
			name: "imap-login",
			line: `Nov  3 10:15:04 mail dovecot: imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<sales@example.com>, method=PLAIN, rip=203.0.113.5, lip=10.0.0.1, TLS`,
			user: "sales@example.com",
			ip:   "203.0.113.5",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			obs, ok := observeMailLine(c.line)
			if !ok {
				t.Fatalf("line not detected at all:\n  %s", c.line)
			}
			if obs.IP != c.ip {
				t.Errorf("ip = %q, want %q", obs.IP, c.ip)
			}
			if obs.User != c.user {
				t.Errorf("target_user = %q, want %q — this is the field the customer "+
					"opens an SSH session to find", obs.User, c.user)
			}
			if obs.Reason != "mail_brute_force" {
				t.Errorf("reason = %q, want mail_brute_force", obs.Reason)
			}
		})
	}
}

// The worker logs a great deal that is not an authentication failure. Widening
// the pattern to reach it must not turn routine chatter into a ban.
func TestDovecotAuthWorkerChatterIsNotAnAttack(t *testing.T) {
	benign := []string{
		`Nov  3 10:15:04 mail dovecot: auth-worker(2451): conn unix:auth-worker (pid=2450,uid=0): Connected`,
		`Nov  3 10:15:04 mail dovecot: auth-worker(2451): Warning: Request 1.2 timed out`,
		`Nov  3 10:15:04 mail dovecot: auth: Debug: passwd-file(sales@example.com,203.0.113.5): lookup`,
		`Nov  3 10:15:04 mail dovecot: imap(sales@example.com)<2451><Hs7bQw>: Logged out bytes=123/456`,
	}
	for _, line := range benign {
		if _, ok := observeMailLine(line); ok {
			t.Errorf("benign line treated as an attack:\n  %s", line)
		}
	}
}

// A Postfix line whose only trailing token is the base64 challenge carries no
// username, and must not be made to look as though it does — reporting it
// would be reading the server's "Password:" prompt back as a credential.
//
// This says nothing about Postfix in general: when the mechanism reaches the
// auth backend the same warning carries sasl_username, and we read it. Scope
// the claim to the line shape, which is what the old name got wrong.
func TestPostfixSASLFailureWithoutSaslUsernameHasNoUsername(t *testing.T) {
	line := `Nov  3 10:15:04 mail postfix/smtpd[2460]: warning: unknown[203.0.113.5]: SASL LOGIN authentication failed: UGFzc3dvcmQ6`

	obs, ok := observeMailLine(line)
	if !ok {
		t.Fatal("Postfix SASL failure should still be detected")
	}
	if obs.User != "" {
		t.Errorf("target_user = %q, want empty: this line shape carries no account", obs.User)
	}
	if obs.IP != "203.0.113.5" || obs.Method != "LOGIN" || obs.Protocol != "smtp" {
		t.Errorf("unexpected observation: %+v", obs)
	}
}

// Reading the auth-worker line means one failed SMTP AUTH now appears twice in
// the log: once named by Dovecot, once unnamed by Postfix. Counting both would
// halve the effective ban threshold — an IP would be banned on its third real
// attempt against a threshold of five — so the pair must count once.
func TestOneSMTPAuthFailureCountsOnce(t *testing.T) {
	// onEvent is dispatched on a goroutine, so collect through a channel
	// rather than reading a slice the watcher may not have written yet.
	got := make(chan map[string]string, 8)
	w := testWatcher(func(ip, reason, sev string, d map[string]string) {
		got <- d
	})

	// One attempt, as the log actually writes it.
	w.processLine(`Nov  3 10:15:04 mail dovecot: auth-worker(2451): passwd-file(sales@example.com,203.0.113.5): Password mismatch`)
	w.processLine(`Nov  3 10:15:04 mail postfix/smtpd[2460]: warning: unknown[203.0.113.5]: SASL LOGIN authentication failed: UGFzc3dvcmQ6`)

	var first map[string]string
	select {
	case first = <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("no event reported for a failed login")
	}

	if first["target_user"] != "sales@example.com" {
		t.Errorf("the surviving event lost the mailbox: %v", first)
	}

	select {
	case extra := <-got:
		t.Errorf("one failed login produced a second event: %v", extra)
	case <-time.After(250 * time.Millisecond):
	}
	if n := len(w.attempts["203.0.113.5"]); n != 1 {
		t.Errorf("attempts counted = %d, want 1 — the ban threshold depends on this", n)
	}
}

// The same pair, with the Postfix half carrying sasl_username — which is what
// it does on 312 of 341 failures on the reporting MSP's server, so this is the
// common shape and the one above is the exception.
//
// This is a regression test for the fix itself. Reading sasl_username broke the
// pairing it was added alongside: the echo was recognised by having no user, so
// the moment it had one, both halves counted and the ban threshold halved.
// TestOneSMTPAuthFailureCountsOnce passed throughout, because its Postfix line
// is the challenge-only shape that still carries no name.
func TestOneSMTPAuthFailureCountsOnceWhenPostfixNamesTheAccount(t *testing.T) {
	got := make(chan map[string]string, 8)
	w := testWatcher(func(ip, reason, sev string, d map[string]string) {
		got <- d
	})

	w.processLine(`Nov  5 06:33:23 mail dovecot: auth-worker(2451): passwd-file(sales@example.com,203.0.113.5): Password mismatch`)
	w.processLine(`Nov  5 06:33:23 mail postfix/smtpd[2460]: warning: unknown[203.0.113.5]: SASL PLAIN authentication failed: (reason unavailable), sasl_username=sales@example.com`)

	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("no event reported for a failed login")
	}
	select {
	case extra := <-got:
		t.Errorf("one failed login produced a second event: %v", extra)
	case <-time.After(250 * time.Millisecond):
	}
	if n := len(w.attempts["203.0.113.5"]); n != 1 {
		t.Errorf("attempts counted = %d, want 1 — the ban threshold depends on this", n)
	}
}

// Pairing is per-IP, so one account attacked from two hosts is two attempts
// however each log line happens to spell it.
//
// The MSP saw this shape and asked whether the bare spelling meant we had cut
// the domain off: john.magill.uk from one IP, john.magill.uk@rainbowvapes.co.uk
// from another, a second apart. Neither value is trimmed — each is what its own
// log line carried — and the two must never collapse into one attempt.
func TestSameAccountFromTwoIPsIsTwoAttempts(t *testing.T) {
	w := testWatcher(func(ip, reason, sev string, d map[string]string) {})

	w.processLine(`Nov  5 06:33:09 mail postfix/smtpd[2460]: warning: unknown[72.205.174.51]: SASL PLAIN authentication failed: (reason unavailable), sasl_username=john.magill.uk@rainbowvapes.co.uk`)
	w.processLine(`Nov  5 06:33:23 mail postfix/smtpd[2461]: warning: unknown[203.128.10.90]: SASL PLAIN authentication failed: (reason unavailable), sasl_username=john.magill.uk`)

	if n := len(w.attempts["72.205.174.51"]); n != 1 {
		t.Errorf("qualified-spelling IP attempts = %d, want 1", n)
	}
	if n := len(w.attempts["203.128.10.90"]); n != 1 {
		t.Errorf("bare-spelling IP attempts = %d, want 1", n)
	}
}

// A bare local part is read out whole, not produced by trimming a domain. The
// MSP hosts eleven mail domains, so if we were cutting at the "@" the value
// would silently merge distinct mailboxes.
func TestBareSaslUsernameIsNotATrimmedDomain(t *testing.T) {
	qualified := `Nov  5 06:33:09 mail postfix/smtpd[2460]: warning: unknown[203.0.113.5]: SASL PLAIN authentication failed: (reason unavailable), sasl_username=john.magill.uk@rainbowvapes.co.uk`
	bare := `Nov  5 06:33:23 mail postfix/smtpd[2461]: warning: unknown[203.0.113.5]: SASL PLAIN authentication failed: (reason unavailable), sasl_username=john.magill.uk`

	obs, ok := observeMailLine(qualified)
	if !ok {
		t.Fatal("qualified line not detected")
	}
	if obs.User != "john.magill.uk@rainbowvapes.co.uk" {
		t.Errorf("target_user = %q, want the domain kept intact", obs.User)
	}

	obs, ok = observeMailLine(bare)
	if !ok {
		t.Fatal("bare line not detected")
	}
	if obs.User != "john.magill.uk" {
		t.Errorf("target_user = %q, want the line's own value verbatim", obs.User)
	}
}

// Pairing is one-for-one, not a time bucket: a fast attacker must still have
// every attempt counted.
func TestFastAttackerKeepsEveryAttempt(t *testing.T) {
	w := testWatcher(func(ip, reason, sev string, d map[string]string) {})

	for i := 0; i < 4; i++ {
		w.processLine(`Nov  3 10:15:04 mail dovecot: auth-worker(2451): passwd-file(sales@example.com,203.0.113.5): Password mismatch`)
		w.processLine(`Nov  3 10:15:04 mail postfix/smtpd[2460]: warning: unknown[203.0.113.5]: SASL LOGIN authentication failed: UGFzc3dvcmQ6`)
	}

	if n := len(w.attempts["203.0.113.5"]); n != 4 {
		t.Errorf("attempts counted = %d, want 4: four real attempts, eight log lines", n)
	}
}

// A Postfix failure with no Dovecot line in front of it is a whole attempt on
// its own — the common case on hosts that do not use Dovecot for SASL, and the
// behaviour that existed before any of this.
func TestUnpairedPostfixFailureStillCounts(t *testing.T) {
	w := testWatcher(func(ip, reason, sev string, d map[string]string) {})

	w.processLine(`Nov  3 10:15:04 mail postfix/smtpd[2460]: warning: unknown[203.0.113.5]: SASL LOGIN authentication failed: UGFzc3dvcmQ6`)
	w.processLine(`Nov  3 10:15:05 mail postfix/smtpd[2461]: warning: unknown[203.0.113.5]: SASL LOGIN authentication failed: UGFzc3dvcmQ6`)

	if n := len(w.attempts["203.0.113.5"]); n != 2 {
		t.Errorf("attempts counted = %d, want 2", n)
	}
}

// An IMAP failure is a different attempt and must never absorb an SMTP one.
func TestImapFailureDoesNotSuppressAnSMTPAttempt(t *testing.T) {
	w := testWatcher(func(ip, reason, sev string, d map[string]string) {})

	w.processLine(`Nov  3 10:15:04 mail dovecot: imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<sales@example.com>, method=PLAIN, rip=203.0.113.5, lip=10.0.0.1, TLS`)
	w.processLine(`Nov  3 10:15:04 mail postfix/smtpd[2460]: warning: unknown[203.0.113.5]: SASL LOGIN authentication failed: UGFzc3dvcmQ6`)

	if n := len(w.attempts["203.0.113.5"]); n != 2 {
		t.Errorf("attempts counted = %d, want 2: an IMAP attempt and an SMTP attempt are two attempts", n)
	}
}

// testWatcher builds a MailWatcher wired for assertions, without touching the
// filesystem: NewMailWatcher returns nil when there is no mail log, which there
// is not on a build machine.
func testWatcher(onEvent EventFunc) *MailWatcher {
	w := &MailWatcher{
		threshold: 5,
		window:    5 * time.Minute,
		attempts:  make(map[string][]time.Time),
		banned:    make(map[string]bool),
		whitelist: make(map[string]bool),
		namedSMTP: make(map[string][]time.Time),
		onBan:     func(ip, reason string, attempts int) {},
	}
	w.SetOnEvent(onEvent)

	return w
}
