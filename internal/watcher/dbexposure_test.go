package watcher

import (
	"strings"
	"testing"

	"github.com/defensia/agent/internal/monitor"
)

// The regression this file exists for. A customer disputed a critical
// "MySQL/MariaDB is exposed publicly on port 3306" alert on 28-oct-2026 and we
// could not settle it, because the event carried only that sentence — no bind
// address. Every payload must now carry the evidence for its own claim.
func TestDBExposureDetailsCarryTheEvidence(t *testing.T) {
	d := DBExposure{
		Port:     3306,
		Service:  "MySQL/MariaDB",
		Bind:     "0.0.0.0",
		Exposure: monitor.ExposureWildcard,
	}

	got := d.Details()

	for _, key := range []string{"warning", "service", "port", "bind", "exposure"} {
		if got[key] == "" {
			t.Errorf("details[%q] is empty — the finding cannot be verified without it", key)
		}
	}
	if got["bind"] != "0.0.0.0" {
		t.Errorf("details[bind] = %q, want 0.0.0.0", got["bind"])
	}
	if got["port"] != "3306" {
		t.Errorf("details[port] = %q, want 3306", got["port"])
	}
	if got["exposure"] != "wildcard" {
		t.Errorf("details[exposure] = %q, want wildcard", got["exposure"])
	}
}

func TestDBExposureSeverityFollowsExposure(t *testing.T) {
	cases := []struct {
		exposure monitor.Exposure
		want     string
	}{
		{monitor.ExposureWildcard, "critical"},
		{monitor.ExposurePublic, "critical"},
		{monitor.ExposurePrivate, "warning"},
		{monitor.ExposureLoopback, "info"},
	}

	for _, c := range cases {
		d := DBExposure{Port: 3306, Service: "MySQL/MariaDB", Exposure: c.exposure}
		if got := d.Severity(); got != c.want {
			t.Errorf("exposure %q → severity %q, want %q", c.exposure, got, c.want)
		}
	}
}

// A private bind is reachable from its network, so staying silent would be wrong —
// but calling it "publicly exposed" is also wrong, and that false claim is what
// makes an operator stop trusting the alerts.
func TestDBExposureWordingDoesNotOverclaim(t *testing.T) {
	private := DBExposure{
		Port:     3306,
		Service:  "MySQL/MariaDB",
		Bind:     "192.168.1.10",
		Exposure: monitor.ExposurePrivate,
	}.Warning()

	if strings.Contains(private, "publicly") || strings.Contains(private, "internet") {
		t.Errorf("a private bind must not be described as public: %q", private)
	}
	if !strings.Contains(private, "192.168.1.10") {
		t.Errorf("the warning must name the bind address: %q", private)
	}

	loopback := DBExposure{
		Port:     3306,
		Service:  "MySQL/MariaDB",
		Bind:     "127.0.0.1",
		Exposure: monitor.ExposureLoopback,
	}.Warning()

	if strings.Contains(loopback, "exposed") {
		t.Errorf("a loopback bind must not read as exposed: %q", loopback)
	}

	wildcard := DBExposure{
		Port:     3306,
		Service:  "MySQL/MariaDB",
		Bind:     "0.0.0.0",
		Exposure: monitor.ExposureWildcard,
	}.Warning()

	if !strings.Contains(wildcard, "0.0.0.0") {
		t.Errorf("the warning must name the bind address: %q", wildcard)
	}
}

func TestDBServiceName(t *testing.T) {
	if got := DBServiceName(3306); got != "MySQL/MariaDB" {
		t.Errorf("DBServiceName(3306) = %q", got)
	}
	// Must never return an empty string: the caller prints it to an operator.
	if got := DBServiceName(9999); got == "" {
		t.Error("DBServiceName of an unknown port returned an empty name")
	}
}
