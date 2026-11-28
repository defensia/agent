package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- test fixtures and helpers -------------------------------------------

// fakeTime is an injectable (c.now, c.sleep) pair: sleep both records the
// requested duration (for assertion) and advances the fake clock by it, so
// a scripted sequence of failures/backoffs behaves exactly as it would in
// production without a single real sleep. Every pipeline test but the one
// that deliberately proves a real wall-clock deadline (see
// TestShutdownReturnsWithinDeadlineEvenIfServerHangs) uses this instead of
// the real clock.
type fakeTime struct {
	mu    sync.Mutex
	t     time.Time
	waits []time.Duration
}

func (f *fakeTime) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeTime) sleep(d time.Duration) {
	f.mu.Lock()
	f.waits = append(f.waits, d)
	f.t = f.t.Add(d)
	f.mu.Unlock()
}

func (f *fakeTime) advance(d time.Duration) {
	f.mu.Lock()
	f.t = f.t.Add(d)
	f.mu.Unlock()
}

func newFakeTime() *fakeTime {
	return &fakeTime{t: time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)}
}

func loadFixtureSync(t *testing.T) *EventAggregationSync {
	t.Helper()
	data, err := os.ReadFile("testdata/contracts/sync_event_aggregation.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var s EventAggregationSync
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return &s
}

// testBotEvent builds a bot-classifier event. Repeated calls with the same
// typ/sev share an aggregation key (same domain/bot_slug/user_agent/ip).
func testBotEvent(typ, sev string) EventRequest {
	return EventRequest{
		Type:     typ,
		Severity: sev,
		SourceIP: "203.0.113.11",
		Details: map[string]string{
			"domain": "example.test", "bot_slug": "labbot", "user_agent": "LabBot/1.0",
		},
		OccurredAt: time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC).Format(time.RFC3339),
	}
}

// testWebEvent builds a request-path-driven event sharing an aggregation
// key with other calls using the same typ/sev/uri.
func testWebEvent(typ, sev, uri string) EventRequest {
	return EventRequest{
		Type:     typ,
		Severity: sev,
		SourceIP: "203.0.113.10",
		Details: map[string]string{
			"domain": "example.test", "uri": uri,
		},
		OccurredAt: time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC).Format(time.RFC3339),
	}
}

func testCriticalEvent(typ string) EventRequest {
	return EventRequest{
		Type:       typ,
		Severity:   "critical",
		Details:    map[string]string{"domain": "example.test"},
		OccurredAt: time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC).Format(time.RFC3339),
	}
}

// batchOf returns n independent, validly-shaped events for exercising
// sendWithRetry directly; content is irrelevant to that method, but each
// is tagged with its original index so a test can tell which ones a
// partial-rejection retry actually resent.
func batchOf(n int) []EventRequest {
	out := make([]EventRequest, n)
	for i := range out {
		out[i] = testCriticalEvent("malware_realtime")
		out[i].Details["idx"] = strconv.Itoa(i)
	}
	return out
}

// eventsServer records every decoded request body's "events" array.
func eventsServer(t *testing.T, handler func(w http.ResponseWriter, bodyEvents []map[string]any)) (*httptest.Server, func() [][]map[string]any) {
	t.Helper()
	var mu sync.Mutex
	var bodies [][]map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Events []map[string]any `json:"events"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &payload)

		mu.Lock()
		bodies = append(bodies, payload.Events)
		mu.Unlock()

		if handler != nil {
			handler(w, payload.Events)
		} else {
			w.WriteHeader(http.StatusCreated)
		}
	}))

	return srv, func() [][]map[string]any {
		mu.Lock()
		defer mu.Unlock()
		out := make([][]map[string]any, len(bodies))
		copy(out, bodies)
		return out
	}
}

// --- AggregationConfigFromSync: the capability handshake -----------------

func TestAggregationConfigFromSyncFixtureValues(t *testing.T) {
	s := loadFixtureSync(t)
	cfg := AggregationConfigFromSync(s)

	if !cfg.Enabled {
		t.Fatal("the panel's enabled fixture should decode to an enabled config")
	}
	if cfg.BotWindow != 60*time.Second {
		t.Errorf("BotWindow = %s, want 60s", cfg.BotWindow)
	}
	if cfg.WebWindow != 30*time.Second {
		t.Errorf("WebWindow = %s, want 30s", cfg.WebWindow)
	}
	if cfg.MaxKeys != 10000 {
		t.Errorf("MaxKeys = %d, want 10000", cfg.MaxKeys)
	}
	if cfg.MaxCount != 1000 {
		t.Errorf("MaxCount = %d, want 1000", cfg.MaxCount)
	}
	want := map[string]bool{"bot_crawl": true}
	if !reflect.DeepEqual(cfg.PanelTypes, want) {
		t.Errorf("PanelTypes = %v, want %v", cfg.PanelTypes, want)
	}
}

func TestAggregationConfigFromSyncRequiresBothSupportedAndEnabled(t *testing.T) {
	cases := []struct {
		name string
		sync *EventAggregationSync
	}{
		{"nil (old panel, key absent)", nil},
		{"supported but not enabled", &EventAggregationSync{Supported: true, Enabled: false, BotWindowSeconds: 60, WebWindowSeconds: 30, Types: []string{"bot_crawl"}}},
		{"enabled but not supported", &EventAggregationSync{Supported: false, Enabled: true, BotWindowSeconds: 60, WebWindowSeconds: 30, Types: []string{"bot_crawl"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := AggregationConfigFromSync(tc.sync)
			if cfg.Enabled {
				t.Errorf("Enabled = true, want false (pass-through)")
			}
		})
	}
}

func TestAggregationConfigFromSyncEnvForceOff(t *testing.T) {
	t.Setenv("DEFENSIA_EVENT_AGGREGATION", "off")
	cfg := AggregationConfigFromSync(loadFixtureSync(t))
	if cfg.Enabled {
		t.Fatal("DEFENSIA_EVENT_AGGREGATION=off must force pass-through even against an enabled fixture")
	}
}

func TestAggregationConfigFromSyncNilAndEmptyTypesDiffer(t *testing.T) {
	nilTypes := AggregationConfigFromSync(&EventAggregationSync{Supported: true, Enabled: true, BotWindowSeconds: 60, WebWindowSeconds: 30})
	if nilTypes.PanelTypes != nil {
		t.Errorf("a sync with no types key should decode to a nil PanelTypes (agent's own allowlist unrestricted), got %v", nilTypes.PanelTypes)
	}

	emptyTypes := AggregationConfigFromSync(&EventAggregationSync{Supported: true, Enabled: true, BotWindowSeconds: 60, WebWindowSeconds: 30, Types: []string{}})
	if emptyTypes.PanelTypes == nil || len(emptyTypes.PanelTypes) != 0 {
		t.Errorf("an explicit empty types list should decode to a non-nil, empty PanelTypes (aggregates nothing), got %v", emptyTypes.PanelTypes)
	}
}

// --- pass-through: everything short of the full handshake ----------------

// assertAggregationDisabledPassesThrough queues 10 identical bot_unknown
// events under sync and asserts every single one reaches the server
// individually, with no count field -- today's behaviour, unconditionally.
func assertAggregationDisabledPassesThrough(t *testing.T, sync *EventAggregationSync) {
	t.Helper()

	srv, bodies := eventsServer(t, nil)
	defer srv.Close()

	c := New(srv.URL, "token")
	c.ConfigureAggregation(AggregationConfigFromSync(sync))

	for i := 0; i < 10; i++ {
		c.QueueEvent(testBotEvent("bot_unknown", "info"))
	}

	batch := c.drainQueued()
	if len(batch) != 10 {
		t.Fatalf("expected all 10 events queued individually (pass-through), got %d", len(batch))
	}
	for _, e := range batch {
		if e.Count != 0 {
			t.Errorf("a pass-through event carries Count=%d, want 0 (never aggregated)", e.Count)
		}
	}

	c.sendWithRetry(batch, c.now().Add(time.Hour))

	got := bodies()
	if len(got) != 1 || len(got[0]) != 10 {
		t.Fatalf("server received %v requests, want one request of 10 events", got)
	}
	for _, e := range got[0] {
		if _, ok := e["count"]; ok {
			t.Errorf("server-received event has a count field, want none on pass-through: %v", e)
		}
	}
}

func TestPanelSilentPassesThrough(t *testing.T) {
	assertAggregationDisabledPassesThrough(t, nil)
}

func TestSupportedTrueEnabledFalsePassesThrough(t *testing.T) {
	assertAggregationDisabledPassesThrough(t, &EventAggregationSync{
		Supported: true, Enabled: false,
		BotWindowSeconds: 60, WebWindowSeconds: 30, MaxKeys: 10000, MaxCount: 1000,
		Types: []string{"bot_crawl"},
	})
}

func TestSupportedFalseEnabledTruePassesThrough(t *testing.T) {
	assertAggregationDisabledPassesThrough(t, &EventAggregationSync{
		Supported: false, Enabled: true,
		BotWindowSeconds: 60, WebWindowSeconds: 30, MaxKeys: 10000, MaxCount: 1000,
		Types: []string{"bot_crawl"},
	})
}

func TestEnvOverrideForcesOffEvenWithEnabledFixture(t *testing.T) {
	t.Setenv("DEFENSIA_EVENT_AGGREGATION", "off")
	assertAggregationDisabledPassesThrough(t, loadFixtureSync(t))
}

func TestEnvOverrideReflectedInPipelineStats(t *testing.T) {
	t.Setenv("DEFENSIA_EVENT_AGGREGATION", "off")
	c := New("http://unused.invalid", "token")
	c.ConfigureAggregation(AggregationConfigFromSync(loadFixtureSync(t)))
	if c.EventPipelineStats().AggregationEnabled {
		t.Fatal("AggregationEnabled should be false when DEFENSIA_EVENT_AGGREGATION=off, even against the enabled fixture")
	}
}

// --- the fixture, decoded and enabled, actually rolls events up ----------

func TestFixtureEnabledRollsUpAfterWindow(t *testing.T) {
	srv, bodies := eventsServer(t, nil)
	defer srv.Close()

	c := New(srv.URL, "token")
	ft := newFakeTime()
	c.now, c.sleep = ft.now, ft.sleep

	c.ConfigureAggregation(AggregationConfigFromSync(loadFixtureSync(t)))

	for i := 0; i < 10; i++ {
		c.QueueEvent(testBotEvent("bot_crawl", "info"))
	}
	if n := len(c.drainQueued()); n != 0 {
		t.Fatalf("expected nothing queued yet (trailing aggregate held pending), got %d", n)
	}

	ft.advance(61 * time.Second) // past the fixture's 60s bot window

	due := c.agg.FlushDue(ft.now())
	if len(due) != 1 {
		t.Fatalf("FlushDue returned %d events, want 1 rollup", len(due))
	}
	c.sendWithRetry(due, ft.now().Add(time.Hour))

	got := bodies()
	if len(got) != 1 || len(got[0]) != 1 {
		t.Fatalf("server received %v, want one request with one event", got)
	}
	count, _ := got[0][0]["count"].(float64)
	if int(count) != 10 {
		t.Errorf("count = %v, want 10", got[0][0]["count"])
	}
}

// --- the inherited decision: PanelTypes restrict-only, gate wins ---------

func TestPanelTypesRestrictOnlyNarrowsAgentCandidateSet(t *testing.T) {
	c := New("http://unused.invalid", "token")
	ft := newFakeTime()
	c.now, c.sleep = ft.now, ft.sleep

	// The real panel contract fixture: types=["bot_crawl"] only.
	c.ConfigureAggregation(AggregationConfigFromSync(loadFixtureSync(t)))

	// bot_crawl is in the panel's narrow allowlist: held pending, not queued.
	for i := 0; i < 3; i++ {
		c.QueueEvent(testBotEvent("bot_crawl", "info"))
	}
	if n := len(c.drainQueued()); n != 0 {
		t.Fatalf("bot_crawl: expected 0 queued (aggregating under the panel's allowlist), got %d", n)
	}

	// env_probe is one of the agent's own 14 structural candidate types
	// (eventtypes.go aggregatableTypes), but the panel's Types list does
	// not name it. PanelTypes can only restrict, never extend, so it must
	// pass through individually even though the agent is structurally
	// willing to aggregate it.
	for i := 0; i < 3; i++ {
		c.QueueEvent(testWebEvent("env_probe", "warning", "/.env"))
	}
	passed := c.drainQueued()
	if len(passed) != 3 {
		t.Fatalf("env_probe: expected all 3 queued individually (not in the panel's types), got %d", len(passed))
	}
	for _, e := range passed {
		if e.Count != 0 {
			t.Errorf("env_probe event was aggregated (Count=%d) despite not being in the panel's types list", e.Count)
		}
	}
}

func TestNeverAggregateGateWinsOverPanelTypes(t *testing.T) {
	c := New("http://unused.invalid", "token")
	ft := newFakeTime()
	c.now, c.sleep = ft.now, ft.sleep

	locked := []string{
		"malware_realtime", "malware_blocked", "malware_quarantined",
		"malware_scan_started", "malware_scan_progress", "malware_scan_completed",
		"rce_attempt", "web_shell", "ban_created", "sigma_detection",
	}

	// A panel that named every locked type in Types would itself be a bug
	// (plan 04's panel never does this), but the agent's own gate must win
	// regardless of what any panel ever sends: ShouldAggregate checks
	// lockedNeverAggregate before ever consulting PanelTypes.
	panelTypes := make(map[string]bool, len(locked))
	for _, typ := range locked {
		panelTypes[typ] = true
	}
	c.ConfigureAggregation(AggregationConfig{
		Enabled: true, BotWindow: 60 * time.Second, WebWindow: 30 * time.Second,
		MaxKeys: 10000, MaxCount: 1000, PanelTypes: panelTypes,
	})

	for _, typ := range locked {
		for i := 0; i < 2; i++ {
			c.QueueEvent(EventRequest{
				Type:       typ,
				Severity:   "warning", // deliberately non-critical: isolates the locked-type gate from the severity gate
				Details:    map[string]string{"domain": "example.test"},
				OccurredAt: ft.now().Format(time.RFC3339),
			})
		}
	}

	got := c.drainQueued()
	if len(got) != len(locked)*2 {
		t.Fatalf("locked types: expected %d individually-reported events, got %d (never-aggregate gate must win over panel types)", len(locked)*2, len(got))
	}
	for _, e := range got {
		if e.Count != 0 {
			t.Errorf("a locked type was aggregated (Count=%d): %+v", e.Count, e)
		}
	}
}

func TestCriticalSeverityNeverAggregatesEvenWhenTypeIsAllowed(t *testing.T) {
	c := New("http://unused.invalid", "token")
	ft := newFakeTime()
	c.now, c.sleep = ft.now, ft.sleep

	c.ConfigureAggregation(AggregationConfig{
		Enabled: true, BotWindow: 60 * time.Second, WebWindow: 30 * time.Second,
		MaxKeys: 10000, MaxCount: 1000, PanelTypes: map[string]bool{"bot_crawl": true},
	})

	for i := 0; i < 3; i++ {
		c.QueueEvent(testBotEvent("bot_crawl", "critical"))
	}

	got := c.drainQueued()
	if len(got) != 3 {
		t.Fatalf("critical bot_crawl events: expected 3 individually-reported (critical never aggregates), got %d", len(got))
	}
}

// --- turning aggregation off flushes pending work immediately ------------

func TestConfigureAggregationFlushesPendingImmediatelyOnDisable(t *testing.T) {
	c := New("http://unused.invalid", "token")
	ft := newFakeTime()
	c.now, c.sleep = ft.now, ft.sleep

	c.ConfigureAggregation(AggregationConfig{
		Enabled: true, BotWindow: 60 * time.Second, WebWindow: 30 * time.Second,
		MaxKeys: 10000, MaxCount: 1000, PanelTypes: map[string]bool{"bot_crawl": true},
	})

	for i := 0; i < 5; i++ {
		c.QueueEvent(testBotEvent("bot_crawl", "info"))
	}
	if n := len(c.drainQueued()); n != 0 {
		t.Fatalf("expected the 5 events held pending (trailing, window not closed), got %d queued", n)
	}

	c.ConfigureAggregation(AggregationConfig{}) // disable

	delivered := c.drainQueued()
	if len(delivered) != 1 {
		t.Fatalf("expected the pending aggregate delivered immediately on disable, got %d events", len(delivered))
	}
	if delivered[0].Count != 5 {
		t.Errorf("Count = %d, want 5", delivered[0].Count)
	}
	if c.EventPipelineStats().AggregationEnabled {
		t.Error("AggregationEnabled should be false after disabling")
	}
}

// --- sendWithRetry: bounded retry, every loss counted ---------------------

func TestSendWithRetrySucceedsAfterTwoTransientFailures(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	c := New(srv.URL, "token")
	ft := newFakeTime()
	c.now, c.sleep = ft.now, ft.sleep

	batch := batchOf(5)
	c.sendWithRetry(batch, ft.now().Add(time.Hour))

	if got := atomic.LoadInt32(&n); got != 3 {
		t.Fatalf("server received %d requests, want 3", got)
	}

	stats := c.EventPipelineStats()
	if stats.Retries != 2 {
		t.Errorf("Retries = %d, want 2", stats.Retries)
	}
	if stats.DroppedSendFailed != 0 {
		t.Errorf("DroppedSendFailed = %d, want 0", stats.DroppedSendFailed)
	}
	if stats.BatchesSent != 1 || stats.EventsSent != 5 {
		t.Errorf("BatchesSent=%d EventsSent=%d, want 1 and 5", stats.BatchesSent, stats.EventsSent)
	}

	want := []time.Duration{1 * time.Second, 2 * time.Second}
	if !reflect.DeepEqual(ft.waits, want) {
		t.Errorf("recorded sleeps = %v, want %v", ft.waits, want)
	}
}

func TestSendWithRetryHonoursRetryAfter(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) == 1 {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	c := New(srv.URL, "token")
	ft := newFakeTime()
	c.now, c.sleep = ft.now, ft.sleep

	c.sendWithRetry(batchOf(2), ft.now().Add(time.Hour))

	want := []time.Duration{7 * time.Second}
	if !reflect.DeepEqual(ft.waits, want) {
		t.Errorf("recorded sleeps = %v, want %v (Retry-After must win over the exponential backoff)", ft.waits, want)
	}
}

func TestSendWithRetryDropsAfterThreeAttemptsAndMovesOn(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := New(srv.URL, "token")
	ft := newFakeTime()
	c.now, c.sleep = ft.now, ft.sleep

	batch := batchOf(4)
	c.sendWithRetry(batch, ft.now().Add(time.Hour))

	if got := atomic.LoadInt32(&n); got != 3 {
		t.Fatalf("server received %d requests, want 3 (maxSendAttempts)", got)
	}
	if got := c.EventPipelineStats().DroppedSendFailed; got != 4 {
		t.Errorf("DroppedSendFailed = %d, want 4", got)
	}

	// The consumer must go on to the next batch: an independent second
	// sendWithRetry call still behaves normally after the first dropped.
	var n2 int32
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n2, 1)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv2.Close()
	c.baseURL = srv2.URL

	c.sendWithRetry(batchOf(2), ft.now().Add(time.Hour))
	if got := atomic.LoadInt32(&n2); got != 1 {
		t.Fatalf("second batch: server received %d requests, want 1", got)
	}
	if got := c.EventPipelineStats().BatchesSent; got != 1 {
		t.Errorf("BatchesSent = %d, want 1 (the first batch was dropped, not sent)", got)
	}
}

func TestSendWithRetry422PartialRejectionResendsRemainder(t *testing.T) {
	srv, bodies := eventsServer(t, func(w http.ResponseWriter, bodyEvents []map[string]any) {
		if len(bodyEvents) == 3 {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"errors":{"events.1.type":["The selected events.1.type is invalid."]}}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
	})
	defer srv.Close()

	c := New(srv.URL, "token")
	ft := newFakeTime()
	c.now, c.sleep = ft.now, ft.sleep

	batch := batchOf(3)
	c.sendWithRetry(batch, ft.now().Add(time.Hour))

	got := bodies()
	if len(got) != 2 {
		t.Fatalf("server received %d requests, want 2", len(got))
	}
	if len(got[0]) != 3 {
		t.Errorf("first request had %d events, want 3", len(got[0]))
	}
	if len(got[1]) != 2 {
		t.Fatalf("second request had %d events, want 2 (batch size - 1)", len(got[1]))
	}

	seenIdx := map[string]bool{}
	for _, e := range got[1] {
		details, _ := e["details"].(map[string]any)
		if idx, ok := details["idx"].(string); ok {
			seenIdx[idx] = true
		}
	}
	if seenIdx["1"] {
		t.Error("second request still includes the rejected index 1 event")
	}
	if !seenIdx["0"] || !seenIdx["2"] {
		t.Errorf("second request missing expected remainder indexes 0/2: %v", seenIdx)
	}

	if got := c.EventPipelineStats().DroppedRejected; got != 1 {
		t.Errorf("DroppedRejected = %d, want 1", got)
	}
	if got := c.EventPipelineStats().BatchesSent; got != 1 {
		t.Errorf("BatchesSent = %d, want 1", got)
	}
}

func TestSendWithRetry401NoRetry(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := New(srv.URL, "token")
	ft := newFakeTime()
	c.now, c.sleep = ft.now, ft.sleep

	batch := batchOf(3)
	c.sendWithRetry(batch, ft.now().Add(time.Hour))

	if got := atomic.LoadInt32(&n); got != 1 {
		t.Fatalf("server received %d requests, want 1 (no retry on 401)", got)
	}
	if got := c.EventPipelineStats().DroppedRejected; got != 3 {
		t.Errorf("DroppedRejected = %d, want 3", got)
	}
	if len(ft.waits) != 0 {
		t.Errorf("recorded sleeps = %v, want none (permanent failure never retries)", ft.waits)
	}
}

// --- a full queue is counted, not silently discarded ----------------------

func TestQueueEventDropsWhenQueueFull(t *testing.T) {
	c := New("http://unused.invalid", "token")

	for i := 0; i < eventQueueSize+1; i++ {
		c.QueueEvent(testCriticalEvent("malware_realtime"))
	}

	if got := c.EventPipelineStats().DroppedQueueFull; got != 1 {
		t.Errorf("DroppedQueueFull = %d, want 1", got)
	}
}

// --- Shutdown: flush and drain within the deadline, no silent loss -------

func TestShutdownFlushesPendingAggregateAndQueuedEvents(t *testing.T) {
	srv, bodies := eventsServer(t, nil)
	defer srv.Close()

	c := New(srv.URL, "token")
	ft := newFakeTime()
	c.now, c.sleep = ft.now, ft.sleep

	c.ConfigureAggregation(AggregationConfig{
		Enabled: true, BotWindow: 60 * time.Second, WebWindow: 30 * time.Second,
		MaxKeys: 10000, MaxCount: 1000, PanelTypes: map[string]bool{"bot_crawl": true},
	})

	// 1 pending trailing aggregate, held inside the Aggregator.
	c.QueueEvent(testBotEvent("bot_crawl", "info"))

	// 3 queued, unaggregated critical events (consumer never started, so
	// these sit in c.eventCh until Shutdown drains them).
	for i := 0; i < 3; i++ {
		c.QueueEvent(testCriticalEvent("malware_realtime"))
	}

	c.Shutdown(2 * time.Second)

	got := bodies()
	total := 0
	for _, batch := range got {
		total += len(batch)
	}
	if total != 4 {
		t.Fatalf("server received %d events across %d requests, want 4 (1 pending aggregate + 3 queued)", total, len(got))
	}
}

func TestShutdownReturnsWithinDeadlineEvenIfServerHangs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	c := New(srv.URL, "token")
	// Deliberately the REAL clock/sleep here: this test proves Shutdown's
	// wall-clock deadline against a genuinely slow server. Every other
	// sendWithRetry/Shutdown test above uses the fake clock for the
	// backoff schedule instead.

	c.ConfigureAggregation(AggregationConfig{
		Enabled: true, BotWindow: 60 * time.Second, WebWindow: 30 * time.Second,
		MaxKeys: 10000, MaxCount: 1000, PanelTypes: map[string]bool{"bot_crawl": true},
	})
	c.QueueEvent(testBotEvent("bot_crawl", "info"))
	for i := 0; i < 3; i++ {
		c.QueueEvent(testCriticalEvent("malware_realtime"))
	}

	start := time.Now()
	c.Shutdown(2 * time.Second)
	elapsed := time.Since(start)

	if elapsed > 3*time.Second {
		t.Fatalf("Shutdown took %s, want roughly its 2s deadline, not the server's 5s hang", elapsed)
	}
	if got := c.EventPipelineStats().DroppedSendFailed; got != 4 {
		t.Errorf("DroppedSendFailed = %d, want 4 (all 4 events never got a response in time)", got)
	}
}

func TestShutdownWithRunningConsumerDrainsEverything(t *testing.T) {
	srv, bodies := eventsServer(t, nil)
	defer srv.Close()

	c := New(srv.URL, "token")
	c.StartEventConsumer()

	for i := 0; i < 3; i++ {
		c.QueueEvent(testCriticalEvent("malware_realtime"))
	}

	c.Shutdown(5 * time.Second)

	got := bodies()
	total := 0
	for _, batch := range got {
		total += len(batch)
	}
	if total != 3 {
		t.Fatalf("server received %d events, want 3", total)
	}
}

// --- the heartbeat wire contract: exactly 12 keys -------------------------

func TestEventPipelineStatsHasExactlyTwelveContractKeys(t *testing.T) {
	c := New("http://unused.invalid", "token")

	data, err := json.Marshal(c.EventPipelineStats())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	want := []string{
		"aggregation_enabled", "queue_depth", "queue_capacity",
		"dropped_queue_full", "dropped_send_failed", "dropped_rejected",
		"aggregated_in", "aggregated_out", "passthrough_overflow",
		"batches_sent", "events_sent", "retries",
	}
	sort.Strings(want)

	got := make([]string, 0, len(m))
	for k := range m {
		got = append(got, k)
	}
	sort.Strings(got)

	if !reflect.DeepEqual(got, want) {
		t.Errorf("event_pipeline keys = %v, want %v", got, want)
	}
}
