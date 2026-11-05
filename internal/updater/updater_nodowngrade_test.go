package updater

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestIsNewerNeverDowngrade pins that isNewer/compareSemver never treats an
// older (or equal) "latest" version as newer than the currently running one.
//
// Panel side (AgentService.php:92) may offer an older global latest_agent_version
// after a pin is cleared; this guard is what makes that harmless (no downgrade path
// exists).
func TestIsNewerNeverDowngrade(t *testing.T) {
	cases := []struct {
		current string
		latest  string
		want    bool
	}{
		{"1.4.95", "1.4.94", false},
		{"1.4.95", "1.4.95", false},
		{"1.4.94", "1.4.95", true},
		{"1.4.99", "1.4.100", true},
		{"1.4.100", "1.4.99", false},
		{"v1.4.95", "1.4.94", false},
		{"1.4.95", "v1.4.96", true},
		{"2.0.0", "1.9.99", false},
	}

	for _, c := range cases {
		got := isNewer(c.current, c.latest)
		if got != c.want {
			t.Errorf("isNewer(%q, %q) = %v, want %v", c.current, c.latest, got, c.want)
		}
	}
}

// TestCheckAndUpdateIgnoresOlderLatest pins that CheckAndUpdate makes no HTTP
// request and reports no event when the offered "latest" version is not newer
// than the currently running one — the no-downgrade guard at the entry point
// callers actually use.
//
// Panel side (AgentService.php:92) may offer an older global latest_agent_version
// after a pin is cleared; this guard is what makes that harmless (no downgrade path
// exists).
func TestCheckAndUpdateIgnoresOlderLatest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected download request %s", r.URL.Path)
	}))
	defer srv.Close()

	reporter := func(eventType, severity string, details map[string]string) {
		t.Errorf("unexpected event reported: type=%s severity=%s details=%v", eventType, severity, details)
	}

	// Offered "latest" is older than current: must not touch srv or report anything.
	CheckAndUpdate("1.4.95", "1.4.94", srv.URL, reporter)

	// Offered "latest" equals current: same guard, same expectation.
	CheckAndUpdate("1.4.95", "1.4.95", srv.URL, reporter)
}
