package modsecurity

// Startup event decisions.
//
// This exists because the first version of the mismatch report was unreachable
// on exactly the hosts it was written for. It was nested inside the error branch
// of Setup():
//
//	if err := engine.Setup(); err != nil {
//	    if m := Mismatch(engine); m != "" { ... }   // only when Setup FAILED
//	} else {
//	    report "modsecurity_enabled", status active  // every other time
//	}
//
// Setup() only fails on I/O — writing the rule files. On a mismatched host it
// succeeds, because writing ModSecurity rules into Apache works perfectly well
// when Apache is listening on :8080 and nginx is serving the public ports. So
// the mismatch was never reported, and the host was told its WAF was "active"
// instead: the precise false reassurance the check was built to remove.
//
// Shipped in v1.4.111 and measured the same hour: 9 modsecurity_enabled events
// across the fleet, 0 mismatch reports.
//
// Separating the decision from the probing follows what Mismatch and
// describeMismatch already do, and it means the ordering can be tested without
// a web server — which is what was missing.

// EventType names what the agent should tell the panel at startup.
type EventType string

const (
	// EventNone means say nothing.
	EventNone EventType = ""

	// EventMismatch means ModSecurity is loaded somewhere that cannot see this
	// host's public traffic.
	EventMismatch EventType = "waf_disabled"

	// EventEnabled means ModSecurity is loaded in the server that serves traffic
	// and our rules are in place.
	EventEnabled EventType = "modsecurity_enabled"
)

// StartupEvent is what to report, given the mismatch description and whatever
// Setup() returned.
type StartupEvent struct {
	Type   EventType
	Reason string
	Detail string
}

// DecideStartupEvent orders the two findings.
//
// A mismatch outranks everything: it is true whether or not the rule files were
// written, and it is the one a customer needs to act on. Reporting "active"
// alongside it would contradict it, so the mismatch is returned alone.
//
// A Setup failure with no mismatch is reported as nothing rather than as a
// mismatch — the rules could not be written, which is a local problem worth a
// log line, and claiming the WAF is guarding the wrong door would be a guess.
func DecideStartupEvent(mismatch string, setupErr error) StartupEvent {
	if mismatch != "" {
		return StartupEvent{
			Type:   EventMismatch,
			Reason: "modsecurity_not_on_serving_webserver",
			Detail: mismatch,
		}
	}

	if setupErr != nil {
		return StartupEvent{Type: EventNone}
	}

	return StartupEvent{Type: EventEnabled, Detail: "active"}
}
