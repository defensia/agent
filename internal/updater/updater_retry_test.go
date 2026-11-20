package updater

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRetryDue(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "marker")
	now := time.Now()

	if !retryDue(marker, now, 0) {
		t.Fatal("missing marker should allow retry")
	}

	if err := os.WriteFile(marker, []byte("1.4.76 1"), 0644); err != nil {
		t.Fatal(err)
	}
	if retryDue(marker, now.Add(time.Minute), 1) {
		t.Fatal("retry one minute after a failed attempt should be blocked")
	}
	if !retryDue(marker, now.Add(failedUpdateRetryInterval+time.Second), 1) {
		t.Fatal("retry after the interval should be allowed")
	}

	// A second consecutive failure doubles the wait, so the interval that was
	// enough after one failure is no longer enough after two.
	if retryDue(marker, now.Add(failedUpdateRetryInterval+time.Second), 2) {
		t.Fatal("after two failures, one interval should no longer be enough")
	}
}

// TestRetryBackoffDoublesAndCaps pins the schedule. The cap matters as much as
// the doubling: without it the shift would overflow the duration on a host that
// has been failing for a long time.
func TestRetryBackoffDoublesAndCaps(t *testing.T) {
	for _, c := range []struct {
		attempts int
		want     time.Duration
	}{
		{0, time.Hour},
		{1, time.Hour},
		{2, 2 * time.Hour},
		{3, 4 * time.Hour},
		{4, 8 * time.Hour},
		{5, 16 * time.Hour},
		{6, 16 * time.Hour},
		{99, 16 * time.Hour},
	} {
		if got := retryBackoff(c.attempts); got != c.want {
			t.Errorf("retryBackoff(%d) = %v, want %v", c.attempts, got, c.want)
		}
	}
}

// TestReadAttemptMarkerAcceptsTheOldFormat matters for the rollout itself: every
// agent in the fleet that has ever attempted an update has a marker on disk in
// the version-only format, written by the code this change replaces. Reading one
// as "no attempt" would hand those hosts a free extra attempt; failing to read it
// would hand them an unbounded number.
func TestReadAttemptMarkerAcceptsTheOldFormat(t *testing.T) {
	dir := t.TempDir()

	for _, c := range []struct {
		name         string
		content      string
		wantVersion  string
		wantAttempts int
	}{
		{"old format, version only", "1.4.110\n", "1.4.110", 1},
		{"new format", "1.4.110 3\n", "1.4.110", 3},
		{"no trailing newline", "1.4.110 2", "1.4.110", 2},
		{"unparseable count falls back to one", "1.4.110 x", "1.4.110", 1},
		{"zero count falls back to one", "1.4.110 0", "1.4.110", 1},
		{"empty file", "", "", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			marker := filepath.Join(dir, "marker-"+c.name)
			if err := os.WriteFile(marker, []byte(c.content), 0644); err != nil {
				t.Fatal(err)
			}

			version, attempts := readAttemptMarker(marker)
			if version != c.wantVersion || attempts != c.wantAttempts {
				t.Errorf("got (%q, %d), want (%q, %d)", version, attempts, c.wantVersion, c.wantAttempts)
			}
		})
	}
}

func TestReadAttemptMarkerOnMissingFile(t *testing.T) {
	version, attempts := readAttemptMarker(filepath.Join(t.TempDir(), "absent"))
	if version != "" || attempts != 0 {
		t.Fatalf("missing marker: got (%q, %d), want (%q, 0)", version, attempts, "")
	}
}

// failingMirror serves 404 to everything, so CheckAndUpdate fails at the very
// first step — fetching the checksum — which is the shape of failure the old
// code could not record.
func failingMirror(t *testing.T) string {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	// The fallback mirror is tried automatically whenever the primary fails, and
	// it is the real defensia.cloud. Point it at the same dead server, or this
	// test downloads from production every time it runs.
	originalFallback := fallbackDownloadBase
	fallbackDownloadBase = srv.URL
	t.Cleanup(func() { fallbackDownloadBase = originalFallback })

	return srv.URL
}

func useTempMarker(t *testing.T) string {
	t.Helper()

	marker := filepath.Join(t.TempDir(), ".last-update-attempt")
	original := updateAttemptMarker
	updateAttemptMarker = marker
	t.Cleanup(func() { updateAttemptMarker = original })

	return marker
}

// TestAFailedAttemptIsRecordedBeforeItCanFail is the regression test for the
// update loop seen on a customer's host on 19-20 Nov 2026: 63 consecutive failed
// attempts in twelve hours, the closest pair six seconds apart.
//
// The retry interval existed at the time and was never reached. The marker it
// reads was written at the end of CheckAndUpdate, just before the restart, so
// any failure before that point — checksum, download, pre-flight check — returned
// without leaving a trace, and the next heartbeat found a clean slate and tried
// again. The interval only ever gated failures that happened after the new binary
// was already installed.
//
// So this asserts the ordering, not the interval: after a first-step failure, the
// marker exists.
func TestAFailedAttemptIsRecordedBeforeItCanFail(t *testing.T) {
	marker := useTempMarker(t)

	var failures int
	reporter := func(eventType, severity string, details map[string]string) {
		if eventType == "update_failed" {
			failures++
		}
	}

	CheckAndUpdate("1.4.109", "1.4.110", failingMirror(t), reporter)

	if failures != 1 {
		t.Fatalf("expected the failed attempt to be reported once, got %d", failures)
	}

	version, attempts := readAttemptMarker(marker)
	if version != "1.4.110" || attempts != 1 {
		t.Fatalf("after one failed attempt the marker should read (1.4.110, 1), got (%q, %d)", version, attempts)
	}
}

// TestAnImmediateSecondAttemptIsRefused is the other half: recording the attempt
// is only useful if the gate then honours it. Together these two tests fail on
// the old code — the first because no marker was written, the second because the
// missing marker let every heartbeat straight through.
func TestAnImmediateSecondAttemptIsRefused(t *testing.T) {
	marker := useTempMarker(t)
	mirror := failingMirror(t)

	var events int
	reporter := func(eventType, severity string, details map[string]string) { events++ }

	CheckAndUpdate("1.4.109", "1.4.110", mirror, reporter)
	first := events
	if first == 0 {
		t.Fatal("the first attempt should have reported something")
	}

	CheckAndUpdate("1.4.109", "1.4.110", mirror, reporter)
	if events != first {
		t.Fatalf("a second attempt moments later reported %d more events; it should have been refused", events-first)
	}

	if _, attempts := readAttemptMarker(marker); attempts != 1 {
		t.Fatalf("the refused attempt should not count as one: got %d", attempts)
	}

	// Backdate the marker past the first interval: now the retry is due, and the
	// attempt counter advances.
	past := time.Now().Add(-failedUpdateRetryInterval - time.Minute)
	if err := os.Chtimes(marker, past, past); err != nil {
		t.Fatal(err)
	}

	CheckAndUpdate("1.4.109", "1.4.110", mirror, reporter)
	if events == first {
		t.Fatal("once the interval has passed the attempt should go through")
	}
	if _, attempts := readAttemptMarker(marker); attempts != 2 {
		t.Fatalf("the second real attempt should be counted: got %d", attempts)
	}
}

// TestItStopsTryingAndSaysSo covers the cap. A host that cannot install a
// version is not going to start being able to on the next heartbeat, and every
// attempt costs it a 9.3 MB download. It must go quiet — but not silently: the
// panel needs one critical event naming the host as stuck.
func TestItStopsTryingAndSaysSo(t *testing.T) {
	marker := useTempMarker(t)
	mirror := failingMirror(t)

	writeAttemptMarker(marker, "1.4.110", maxUpdateAttempts)

	var exhausted, other int
	reporter := func(eventType, severity string, details map[string]string) {
		if details["reason"] == "attempts_exhausted" {
			exhausted++
			if severity != "critical" {
				t.Errorf("a stuck host should be reported critical, got %q", severity)
			}
			if !strings.Contains(details["target_version"], "1.4.110") {
				t.Errorf("the event should name the version it gave up on, got %v", details)
			}

			return
		}
		other++
	}

	CheckAndUpdate("1.4.109", "1.4.110", mirror, reporter)

	if exhausted != 1 {
		t.Fatalf("expected exactly one attempts_exhausted event, got %d", exhausted)
	}
	if other != 0 {
		t.Fatalf("expected no download to be attempted after giving up, got %d other events", other)
	}

	// And it stays quiet from here, however often it is asked.
	for range 5 {
		CheckAndUpdate("1.4.109", "1.4.110", mirror, reporter)
	}
	if exhausted != 1 {
		t.Fatalf("the give-up event should be reported once, not on every check: got %d", exhausted)
	}
	if other != 0 {
		t.Fatalf("expected silence after giving up, got %d other events", other)
	}

	// A different target version is a clean slate: the panel has moved on, and
	// whatever was wrong with the old one may not apply.
	CheckAndUpdate("1.4.109", "1.4.111", mirror, reporter)
	if other == 0 {
		t.Fatal("a new target version should be attempted despite the previous one being exhausted")
	}
	if v, attempts := readAttemptMarker(marker); v != "1.4.111" || attempts != 1 {
		t.Fatalf("the new target should start from one attempt: got (%q, %d)", v, attempts)
	}
}

// TestASuccessfulUpdateResetsTheCounter: once the agent is running the version
// the marker was written for, the attempt history is spent. Without this a host
// that needed three tries to reach 1.4.110 would arrive at 1.4.111 with three
// failures already against it.
func TestASuccessfulUpdateResetsTheCounter(t *testing.T) {
	marker := useTempMarker(t)
	mirror := failingMirror(t)

	writeAttemptMarker(marker, "1.4.110", 4)

	// The agent is now running 1.4.110: the attempt worked.
	CheckAndUpdate("1.4.110", "1.4.111", mirror, func(string, string, map[string]string) {})

	if v, attempts := readAttemptMarker(marker); v != "1.4.111" || attempts != 1 {
		t.Fatalf("after a success the next target starts from one attempt: got (%q, %d)", v, attempts)
	}
}

// TestDescribePreflightKillSeparatesOurTimeoutFromTheHost is the test that would
// have stopped a wrong diagnosis from shipping.
//
// exec returns the identical string "signal: killed" whether our own context
// deadline fired or the host sent SIGKILL, and the two have opposite fixes:
// ours means the timeout is too tight, theirs means the timeout is irrelevant.
// A customer host was killed 3 and 7 seconds into a 30 second budget and it was
// read as our timeout for a full day.
func TestDescribePreflightKillSeparatesOurTimeoutFromTheHost(t *testing.T) {
	killed := errors.New("signal: killed")

	for _, c := range []struct {
		name    string
		ctxErr  error
		runErr  error
		elapsed time.Duration
		want    string
	}{
		{
			name:    "our deadline fired",
			ctxErr:  context.DeadlineExceeded,
			runErr:  killed,
			elapsed: 120 * time.Second,
			want:    "our_timeout",
		},
		{
			// The farma009 shape: same error string, no deadline, 3 seconds in.
			name:    "the host killed it long before our deadline",
			ctxErr:  nil,
			runErr:  killed,
			elapsed: 3 * time.Second,
			want:    "external_sigkill",
		},
		{
			name:    "a different signal",
			ctxErr:  nil,
			runErr:  errors.New("signal: segmentation fault"),
			elapsed: time.Second,
			want:    "external_signal",
		},
		{
			name:    "ran fine but printed the wrong thing",
			ctxErr:  nil,
			runErr:  nil,
			elapsed: 40 * time.Millisecond,
			want:    "none_bad_output",
		},
		{
			name:    "exited non-zero",
			ctxErr:  nil,
			runErr:  errors.New("exit status 1"),
			elapsed: 50 * time.Millisecond,
			want:    "exited_nonzero",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := describePreflightKill(c.ctxErr, c.runErr, c.elapsed); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}
