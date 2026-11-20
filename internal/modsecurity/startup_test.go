package modsecurity

import (
	"errors"
	"testing"
)

// TestAMismatchIsReportedEvenWhenSetupSucceeds is the regression test for the
// v1.4.111 defect: the mismatch report was nested inside Setup()'s error branch,
// and Setup() succeeds on a mismatched host, so the report never ran.
func TestAMismatchIsReportedEvenWhenSetupSucceeds(t *testing.T) {
	ev := DecideStartupEvent("Apache has ModSecurity but nginx serves :80", nil)

	if ev.Type != EventMismatch {
		t.Fatalf("a mismatch with a successful Setup must still be reported, got %q", ev.Type)
	}
	if ev.Reason != "modsecurity_not_on_serving_webserver" {
		t.Errorf("reason = %q", ev.Reason)
	}
	if ev.Detail == "" {
		t.Error("the detail must carry the description, or the customer cannot act on it")
	}
}

// TestAMismatchIsNeverReportedAsActive is the other half, and the one that did
// real harm: on a mismatched host the old code fell through to the else branch
// and told the customer their WAF was active.
func TestAMismatchIsNeverReportedAsActive(t *testing.T) {
	for _, setupErr := range []error{nil, errors.New("write static rules: read-only file system")} {
		ev := DecideStartupEvent("Apache has ModSecurity but nginx serves :80", setupErr)
		if ev.Type == EventEnabled {
			t.Fatalf("setupErr=%v: a mismatched host must never be told its WAF is active", setupErr)
		}
	}
}

func TestNoMismatchAndCleanSetupReportsEnabled(t *testing.T) {
	ev := DecideStartupEvent("", nil)
	if ev.Type != EventEnabled {
		t.Fatalf("got %q, want %q", ev.Type, EventEnabled)
	}
	if ev.Detail != "active" {
		t.Errorf("detail = %q", ev.Detail)
	}
}

// TestASetupFailureAloneClaimsNothing: not being able to write the rule files is
// a local problem. Calling it a mismatch would be a guess, and calling it active
// would be a lie.
func TestASetupFailureAloneClaimsNothing(t *testing.T) {
	ev := DecideStartupEvent("", errors.New("write static rules: permission denied"))
	if ev.Type != EventNone {
		t.Fatalf("got %q, want no event", ev.Type)
	}
}
