package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defensia/agent/internal/api"
	"github.com/defensia/agent/internal/firewall"
)

func boolp(b bool) *bool { return &b }
func intp(i int) *int    { return &i }

// --- buildCSFHeartbeat ----------------------------------------------------

func TestBuildCSFHeartbeatNil(t *testing.T) {
	fields, paused := buildCSFHeartbeat(nil, false)
	if fields != nil {
		t.Errorf("fields = %v, want nil", fields)
	}
	if paused != nil {
		t.Errorf("paused = %v, want nil", paused)
	}
}

func TestBuildCSFHeartbeatPresent(t *testing.T) {
	snap := &firewall.CSFSnapshot{
		Installed:       true,
		Version:         "14.20",
		Fork:            "upstream",
		ForkEvidence:    []string{"config.server.com in downloadservers"},
		PortsIn:         "20,21,22,80,443",
		PortsOut:        "20,21,22,25,80,443",
		Testing:         boolp(false),
		AutoUpdates:     boolp(true),
		LFDaemon:        boolp(true),
		LFDRunning:      boolp(true),
		IPv6:            boolp(false),
		AutoUpdatesCron: true,
		DownloadServers: []string{"configserver.com"},
		DenyIPLimit:     intp(200),
		DenyTempIPLimit: intp(100),
		Deny:            firewall.CSFList{Total: 5, Truncated: false},
		Allow:           firewall.CSFList{Total: 2, Truncated: true},
		ListsHash:       "abc123",
		CollectedAt:     time.Now(),
	}

	fields, paused := buildCSFHeartbeat(snap, false)
	if fields == nil {
		t.Fatal("fields = nil, want populated")
	}
	if !fields.CSFInstalled {
		t.Error("CSFInstalled = false, want true")
	}
	if fields.CSFVersion == nil || *fields.CSFVersion != "14.20" {
		t.Errorf("CSFVersion = %v, want *\"14.20\"", fields.CSFVersion)
	}
	if fields.CSFDenyCount == nil || *fields.CSFDenyCount != 5 {
		t.Errorf("CSFDenyCount = %v, want *5", fields.CSFDenyCount)
	}
	if fields.CSFAllowCount == nil || *fields.CSFAllowCount != 2 {
		t.Errorf("CSFAllowCount = %v, want *2", fields.CSFAllowCount)
	}
	if fields.CSFListsTruncated == nil || !*fields.CSFListsTruncated {
		t.Errorf("CSFListsTruncated = %v, want *true (Allow.Truncated)", fields.CSFListsTruncated)
	}
	if fields.CSFDownloadServers == nil {
		t.Error("CSFDownloadServers = nil, want non-nil")
	}
	if paused == nil || *paused != false {
		t.Errorf("paused = %v, want *false", paused)
	}
}

func TestBuildCSFHeartbeatRemoved(t *testing.T) {
	snap := &firewall.CSFSnapshot{Installed: false, CollectedAt: time.Now()}
	fields, paused := buildCSFHeartbeat(snap, false)
	if fields == nil {
		t.Fatal("fields = nil, want populated with CSFInstalled:false")
	}
	if fields.CSFInstalled {
		t.Error("CSFInstalled = true, want false")
	}
	if fields.CSFVersion != nil || fields.CSFPortsIn != nil || fields.CSFPortsOut != nil ||
		fields.CSFDenyCount != nil || fields.CSFAllowCount != nil || fields.CSFFork != nil ||
		fields.CSFTesting != nil || fields.CSFAutoUpdates != nil || fields.CSFAutoUpdatesCron != nil ||
		fields.CSFLFDaemon != nil || fields.CSFLFDRunning != nil || fields.CSFIPv6 != nil ||
		fields.CSFDenyIPLimit != nil || fields.CSFDenyTempIPLimit != nil ||
		fields.CSFListsHash != nil || fields.CSFListsTruncated != nil {
		t.Error("expected every other csf_ field nil when removed")
	}
	if paused != nil {
		t.Errorf("paused = %v, want nil (removed != paused)", paused)
	}
}

func TestBuildCSFHeartbeatPaused(t *testing.T) {
	snap := &firewall.CSFSnapshot{Installed: true, Version: "14.20"}
	fields, paused := buildCSFHeartbeat(snap, true)
	if fields != nil {
		t.Errorf("fields = %v, want nil (snapshot ignored while paused)", fields)
	}
	if paused == nil || *paused != true {
		t.Errorf("paused = %v, want *true", paused)
	}
}

// --- onHeartbeatSuccess ----------------------------------------------------

func TestRemovalAckAfterSuccessfulHeartbeat(t *testing.T) {
	orig := ackCSFRemovalFn
	defer func() { ackCSFRemovalFn = orig }()

	var calls int
	ackCSFRemovalFn = func() { calls++ }

	onHeartbeatSuccess(&firewall.CSFSnapshot{Installed: false})
	if calls != 1 {
		t.Fatalf("removed snapshot: calls = %d, want 1", calls)
	}

	calls = 0
	onHeartbeatSuccess(&firewall.CSFSnapshot{Installed: true})
	if calls != 0 {
		t.Fatalf("present snapshot: calls = %d, want 0", calls)
	}

	calls = 0
	onHeartbeatSuccess(nil)
	if calls != 0 {
		t.Fatalf("nil snapshot: calls = %d, want 0", calls)
	}
}

// --- csfListsUploader: hash gating -----------------------------------------

func TestListsUploaderHashGating(t *testing.T) {
	var uploadCount int
	fakeNow := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)

	u := &csfListsUploader{
		upload: func(api.CSFListsRequest) error { uploadCount++; return nil },
		now:    func() time.Time { return fakeNow },
	}
	snap := func(hash string) *firewall.CSFSnapshot {
		return &firewall.CSFSnapshot{Installed: true, ListsHash: hash, CollectedAt: fakeNow}
	}

	u.maybeUpload(snap("hash1"), false)
	if uploadCount != 1 {
		t.Fatalf("first snapshot: uploadCount = %d, want 1", uploadCount)
	}

	fakeNow = fakeNow.Add(10 * time.Minute)
	u.maybeUpload(snap("hash1"), false)
	if uploadCount != 1 {
		t.Fatalf("same hash +10m: uploadCount = %d, want still 1", uploadCount)
	}

	fakeNow = fakeNow.Add(51 * time.Minute) // +61m total from first upload
	u.maybeUpload(snap("hash1"), false)
	if uploadCount != 2 {
		t.Fatalf("same hash +61m: uploadCount = %d, want 2", uploadCount)
	}

	u.maybeUpload(snap("hash2"), false)
	if uploadCount != 3 {
		t.Fatalf("new hash: uploadCount = %d, want 3", uploadCount)
	}

	u.maybeUpload(snap("hash2"), true) // paused
	if uploadCount != 3 {
		t.Fatalf("paused: uploadCount = %d, want still 3", uploadCount)
	}

	u.maybeUpload(nil, false)
	if uploadCount != 3 {
		t.Fatalf("nil snapshot: uploadCount = %d, want still 3", uploadCount)
	}
}

// --- csfListsUploader: backoff ----------------------------------------------

func TestListsUploaderBackoff(t *testing.T) {
	fakeNow := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	snap := &firewall.CSFSnapshot{Installed: true, ListsHash: "h", CollectedAt: fakeNow}

	cases := []struct {
		name string
		err  error
		want time.Duration
	}{
		{"404", &api.HTTPError{Status: http.StatusNotFound}, 6 * time.Hour},
		{"405", &api.HTTPError{Status: http.StatusMethodNotAllowed}, 6 * time.Hour},
		{"429", &api.HTTPError{Status: http.StatusTooManyRequests, RetryAfter: 90 * time.Second}, 90 * time.Second},
		{"413", &api.HTTPError{Status: http.StatusRequestEntityTooLarge}, 60 * time.Minute},
		{"422", &api.HTTPError{Status: http.StatusUnprocessableEntity}, 60 * time.Minute},
		{"network", errors.New("dial tcp: connection refused"), 2 * time.Minute},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := &csfListsUploader{
				upload: func(api.CSFListsRequest) error { return tc.err },
				now:    func() time.Time { return fakeNow },
			}
			u.maybeUpload(snap, false)

			want := fakeNow.Add(tc.want)
			if !u.backoffUntil.Equal(want) {
				t.Errorf("backoffUntil = %v, want %v", u.backoffUntil, want)
			}

			var calls int
			u.upload = func(api.CSFListsRequest) error { calls++; return nil }
			u.maybeUpload(snap, false)
			if calls != 0 {
				t.Errorf("immediate retry: upload called %d times, want 0 (still backing off)", calls)
			}
		})
	}

	// Success resets the backoff and advances lastHash/lastAt.
	u := &csfListsUploader{now: func() time.Time { return fakeNow }}
	u.upload = func(api.CSFListsRequest) error { return errors.New("boom") }
	u.maybeUpload(snap, false)
	if u.backoffUntil.IsZero() {
		t.Fatal("expected backoff set after failure")
	}

	fakeNow = fakeNow.Add(3 * time.Minute) // past the 2-minute network backoff
	u.upload = func(api.CSFListsRequest) error { return nil }
	u.maybeUpload(snap, false)
	if !u.backoffUntil.IsZero() {
		t.Errorf("backoffUntil = %v, want zero after success", u.backoffUntil)
	}
	if u.lastHash != snap.ListsHash {
		t.Errorf("lastHash = %q, want %q", u.lastHash, snap.ListsHash)
	}
}

// --- buildCSFListsRequest: body cap -----------------------------------------

func TestListsUploaderBodyCap(t *testing.T) {
	makeEntries := func(n int) []firewall.CSFListEntry {
		value := strings.Repeat("9", 255)
		comment := strings.Repeat("c", 200)
		entries := make([]firewall.CSFListEntry, n)
		for i := range entries {
			entries[i] = firewall.CSFListEntry{Value: value, Kind: "ip", Comment: comment}
		}
		return entries
	}

	snap := &firewall.CSFSnapshot{
		Installed:   true,
		ListsHash:   "deadbeef",
		CollectedAt: time.Now(),
		Deny:        firewall.CSFList{Entries: makeEntries(1000), Total: 1000},
		Allow:       firewall.CSFList{Entries: makeEntries(1000), Total: 1000},
	}

	req := buildCSFListsRequest(snap)

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(data) > 512*1024 {
		t.Errorf("marshalled size = %d bytes, want <= 512 KiB", len(data))
	}
	if req.Deny.Total != 1000 || req.Allow.Total != 1000 {
		t.Errorf("Totals = deny:%d allow:%d, want 1000/1000 (unchanged by trimming)", req.Deny.Total, req.Allow.Total)
	}
	if !req.Deny.Truncated && !req.Allow.Truncated {
		t.Error("expected at least one list Truncated after trimming")
	}
}

// --- handleCSFPortActions ---------------------------------------------------

func withPortActionSeams(t *testing.T, paused bool, spc func(context.Context, firewall.PortChangeRequest, firewall.PortChangeOptions) firewall.PortChangeResult) {
	t.Helper()
	origSPC, origPaused := safePortChange, csfPausedFn
	t.Cleanup(func() { safePortChange, csfPausedFn = origSPC, origPaused })
	csfPausedFn = func() bool { return paused }
	if spc != nil {
		safePortChange = spc
	}
}

func TestHandleCSFPortActionsEchoActionID(t *testing.T) {
	withPortActionSeams(t, false, func(context.Context, firewall.PortChangeRequest, firewall.PortChangeOptions) firewall.PortChangeResult {
		return firewall.PortChangeResult{Result: "applied"}
	})

	var mu sync.Mutex
	var got []api.EventRequest
	done := make(chan struct{})
	reporter := func(events []api.EventRequest) error {
		mu.Lock()
		got = append(got, events...)
		mu.Unlock()
		close(done)
		return nil
	}

	handleCSFPortActions(reporter, []api.CSFPortAction{{ID: "abc", Port: 8080, Direction: "in", Action: "add"}}, firewall.PortChangeOptions{})

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for port action result")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1", len(got))
	}
	e := got[0]
	if e.Type != "csf_port_changed" || e.Severity != "info" {
		t.Errorf("Type/Severity = %s/%s, want csf_port_changed/info", e.Type, e.Severity)
	}
	if e.Details["action_id"] != "abc" {
		t.Errorf("action_id = %q, want \"abc\"", e.Details["action_id"])
	}
	if e.Details["result"] != "applied" {
		t.Errorf("result = %q, want \"applied\"", e.Details["result"])
	}
	if e.Details["rolled_back"] != "false" {
		t.Errorf("rolled_back = %q, want \"false\"", e.Details["rolled_back"])
	}
	if e.Details["port"] != "8080" {
		t.Errorf("port = %q, want \"8080\"", e.Details["port"])
	}
}

func TestHandleCSFPortActionsNoIDOldPanel(t *testing.T) {
	withPortActionSeams(t, false, func(context.Context, firewall.PortChangeRequest, firewall.PortChangeOptions) firewall.PortChangeResult {
		return firewall.PortChangeResult{Result: "applied"}
	})

	done := make(chan api.EventRequest, 1)
	reporter := func(events []api.EventRequest) error { done <- events[0]; return nil }

	handleCSFPortActions(reporter, []api.CSFPortAction{{Port: 9090, Direction: "out", Action: "add"}}, firewall.PortChangeOptions{})

	select {
	case e := <-done:
		if _, ok := e.Details["action_id"]; ok {
			t.Errorf("Details has action_id = %q, want no key at all", e.Details["action_id"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}
}

func TestHandleCSFPortActionsSeverities(t *testing.T) {
	cases := []struct {
		name         string
		result       firewall.PortChangeResult
		wantType     string
		wantSeverity string
	}{
		{"rejected", firewall.PortChangeResult{Result: "rejected", Reason: "ssh_port_in_use"}, "csf_port_error", "warning"},
		{"failed_rolled_back", firewall.PortChangeResult{Result: "failed", Reason: "health_check_failed", RolledBack: true}, "csf_port_error", "warning"},
		{"rollback_failed", firewall.PortChangeResult{Result: "rollback_failed", Reason: "rollback_failed", Err: errors.New(strings.Repeat("x", 400))}, "csf_port_error", "critical"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			withPortActionSeams(t, false, func(context.Context, firewall.PortChangeRequest, firewall.PortChangeOptions) firewall.PortChangeResult {
				return tc.result
			})

			done := make(chan api.EventRequest, 1)
			reporter := func(events []api.EventRequest) error { done <- events[0]; return nil }

			handleCSFPortActions(reporter, []api.CSFPortAction{{Port: 2222, Direction: "in", Action: "remove"}}, firewall.PortChangeOptions{})

			select {
			case e := <-done:
				if e.Type != tc.wantType || e.Severity != tc.wantSeverity {
					t.Errorf("Type/Severity = %s/%s, want %s/%s", e.Type, e.Severity, tc.wantType, tc.wantSeverity)
				}
				if tc.name == "failed_rolled_back" && e.Details["rolled_back"] != "true" {
					t.Errorf("rolled_back = %q, want \"true\"", e.Details["rolled_back"])
				}
				if tc.name == "rollback_failed" && len(e.Details["error"]) > 300 {
					t.Errorf("Details.error length = %d, want <= 300", len(e.Details["error"]))
				}
			case <-time.After(2 * time.Second):
				t.Fatal("timed out")
			}
		})
	}
}

func TestHandleCSFPortActionsPausedRejected(t *testing.T) {
	var spcCalls int
	withPortActionSeams(t, true, func(context.Context, firewall.PortChangeRequest, firewall.PortChangeOptions) firewall.PortChangeResult {
		spcCalls++
		return firewall.PortChangeResult{Result: "applied"}
	})

	actions := []api.CSFPortAction{
		{Port: 80, Direction: "in", Action: "add"},
		{Port: 443, Direction: "in", Action: "add"},
	}

	var mu sync.Mutex
	var got []api.EventRequest
	var count int
	done := make(chan struct{})
	reporter := func(events []api.EventRequest) error {
		mu.Lock()
		got = append(got, events...)
		count++
		if count == len(actions) {
			close(done)
		}
		mu.Unlock()
		return nil
	}

	handleCSFPortActions(reporter, actions, firewall.PortChangeOptions{})

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}

	mu.Lock()
	defer mu.Unlock()
	if spcCalls != 0 {
		t.Errorf("SafePortChange called %d times, want 0 (kill switch on)", spcCalls)
	}
	for _, e := range got {
		if e.Type != "csf_port_error" || e.Details["reason"] != "integration_disabled" {
			t.Errorf("event = %+v, want csf_port_error with reason integration_disabled", e)
		}
	}
}

func TestHandleCSFPortActionsSequential(t *testing.T) {
	var mu sync.Mutex
	var order []int
	withPortActionSeams(t, false, func(_ context.Context, req firewall.PortChangeRequest, _ firewall.PortChangeOptions) firewall.PortChangeResult {
		mu.Lock()
		order = append(order, req.Port)
		mu.Unlock()
		time.Sleep(10 * time.Millisecond)
		return firewall.PortChangeResult{Result: "applied"}
	})

	var count int
	done := make(chan struct{})
	reporter := func(events []api.EventRequest) error {
		mu.Lock()
		count++
		if count == 2 {
			close(done)
		}
		mu.Unlock()
		return nil
	}

	start := time.Now()
	handleCSFPortActions(reporter, []api.CSFPortAction{
		{Port: 1111, Direction: "in", Action: "add"},
		{Port: 2222, Direction: "in", Action: "add"},
	}, firewall.PortChangeOptions{})
	elapsed := time.Since(start)
	if elapsed > 5*time.Millisecond {
		t.Errorf("handleCSFPortActions blocked for %v, want a near-instant return", elapsed)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(order) != 2 || order[0] != 1111 || order[1] != 2222 {
		t.Errorf("order = %v, want [1111 2222]", order)
	}
}

// --- applyCSFIntegrationFlag -------------------------------------------------

func TestApplyCSFIntegrationFlag(t *testing.T) {
	orig := setCSFPausedFn
	defer func() { setCSFPausedFn = orig }()

	var calls []bool
	setCSFPausedFn = func(p bool) error {
		calls = append(calls, p)
		return nil
	}

	applyCSFIntegrationFlag(nil)
	if len(calls) != 0 {
		t.Fatalf("nil: calls = %v, want none", calls)
	}

	applyCSFIntegrationFlag(boolp(true))
	if len(calls) != 1 || calls[0] != true {
		t.Fatalf("*true: calls = %v, want [true]", calls)
	}

	calls = nil
	applyCSFIntegrationFlag(boolp(false))
	if len(calls) != 1 || calls[0] != false {
		t.Fatalf("*false: calls = %v, want [false]", calls)
	}
}

// --- panelPortFromServerURL --------------------------------------------------

func TestPanelPortFromServerURL(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"https://panel.example:8443", 8443},
		{"https://panel.example", 443},
		{"http://x", 80},
		{"", 0},
	}
	for _, tc := range cases {
		if got := panelPortFromServerURL(tc.in); got != tc.want {
			t.Errorf("panelPortFromServerURL(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
