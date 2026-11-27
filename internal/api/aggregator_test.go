package api

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// t0 is the fixed instant every test in this file anchors its timestamps
// to. Every time value is passed explicitly to Add/FlushDue/FlushAll/
// Configure — there is no wall-clock dependency and no sleeping anywhere
// in this file.
var aggT0 = time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)

func newEnabledAggregator(t *testing.T, cfg AggregationConfig) *Aggregator {
	t.Helper()
	a := NewAggregator()
	a.Configure(cfg, aggT0)
	return a
}

func TestAggregatorDisabled(t *testing.T) {
	a := NewAggregator()
	if a.Enabled() {
		t.Fatal("zero-value Aggregator should be disabled")
	}

	e := EventRequest{
		Type:     "bot_crawl",
		Severity: "info",
		SourceIP: "203.0.113.5",
		Details: map[string]string{
			"domain": "example.test", "uri": "/", "user_agent": "UA/1.0",
		},
		OccurredAt: fmtTime(aggT0),
	}

	got := a.Add(e, aggT0)
	if len(got) != 1 {
		t.Fatalf("Add on disabled aggregator returned %d events, want 1", len(got))
	}
	if !reflect.DeepEqual(got[0], e) {
		t.Errorf("Add on disabled aggregator changed the event:\n got  %+v\n want %+v", got[0], e)
	}

	if out := a.FlushDue(aggT0.Add(time.Hour)); out != nil {
		t.Errorf("FlushDue on disabled aggregator = %v, want nil", out)
	}
	if out := a.FlushAll(aggT0); out != nil {
		t.Errorf("FlushAll on disabled aggregator = %v, want nil", out)
	}
}

func TestAggregatorTrailingRollup(t *testing.T) {
	a := newEnabledAggregator(t, AggregationConfig{Enabled: true, BotWindow: 60 * time.Second, WebWindow: 30 * time.Second})

	for i := 0; i < 40; i++ {
		now := aggT0.Add(time.Duration(i) * 59 * time.Second / 39) // i=0 -> +0s, i=39 -> +59s
		e := EventRequest{
			Type:     "bot_unknown",
			Severity: "info",
			SourceIP: "203.0.113.11",
			Details: map[string]string{
				"domain": "example.test", "user_agent": "LabAggBot/1.0 (+bot)", "uri": "/",
			},
			OccurredAt: fmtTime(now),
		}
		if got := a.Add(e, now); got != nil {
			t.Fatalf("Add occurrence %d returned %v, want nil (trailing, still inside window)", i, got)
		}
	}

	if out := a.FlushDue(aggT0.Add(59 * time.Second)); out != nil {
		t.Fatalf("FlushDue(t0+59s) = %v, want nil (window not yet closed)", out)
	}

	out := a.FlushDue(aggT0.Add(60 * time.Second))
	if len(out) != 1 {
		t.Fatalf("FlushDue(t0+60s) returned %d events, want 1", len(out))
	}
	got := out[0]
	if got.Count != 40 {
		t.Errorf("Count = %d, want 40", got.Count)
	}
	if got.FirstSeen != fmtTime(aggT0) {
		t.Errorf("FirstSeen = %s, want %s", got.FirstSeen, fmtTime(aggT0))
	}
	if got.LastSeen != fmtTime(aggT0.Add(59*time.Second)) {
		t.Errorf("LastSeen = %s, want %s", got.LastSeen, fmtTime(aggT0.Add(59*time.Second)))
	}
	if got.OccurredAt != got.FirstSeen {
		t.Errorf("OccurredAt = %s, want %s (= FirstSeen)", got.OccurredAt, got.FirstSeen)
	}
}

func TestAggregatorTrailingSingleOccurrence(t *testing.T) {
	a := newEnabledAggregator(t, AggregationConfig{Enabled: true, BotWindow: 60 * time.Second, WebWindow: 30 * time.Second})

	e := EventRequest{
		Type:     "bot_unknown",
		Severity: "info",
		SourceIP: "203.0.113.12",
		Details: map[string]string{
			"domain": "example.test", "user_agent": "UA/1.0", "uri": "/only",
		},
		OccurredAt: fmtTime(aggT0),
	}

	if got := a.Add(e, aggT0); got != nil {
		t.Fatalf("Add single trailing occurrence = %v, want nil", got)
	}

	out := a.FlushDue(aggT0.Add(60 * time.Second))
	if len(out) != 1 {
		t.Fatalf("FlushDue returned %d events, want 1", len(out))
	}
	if !reflect.DeepEqual(out[0], e) {
		t.Errorf("single trailing occurrence at flush:\n got  %+v\n want %+v (identical to input)", out[0], e)
	}
}

func TestAggregatorLeadingRollup(t *testing.T) {
	a := newEnabledAggregator(t, AggregationConfig{Enabled: true, BotWindow: 60 * time.Second, WebWindow: 30 * time.Second})

	first := EventRequest{
		Type:     "env_probe",
		Severity: "warning",
		SourceIP: "203.0.113.10",
		Details: map[string]string{
			"domain": "example.test", "uri": "/.env", "user_agent": "Mozilla/5.0",
		},
		OccurredAt: fmtTime(aggT0),
	}
	firstDetailsSnapshot := map[string]string{}
	for k, v := range first.Details {
		firstDetailsSnapshot[k] = v
	}

	got := a.Add(first, aggT0)
	if len(got) != 1 {
		t.Fatalf("Add first leading occurrence returned %d events, want 1", len(got))
	}
	if !reflect.DeepEqual(got[0], first) {
		t.Errorf("first leading occurrence returned changed:\n got  %+v\n want %+v", got[0], first)
	}

	var secondTime, lastTime time.Time
	for i := 1; i <= 11; i++ {
		now := aggT0.Add(time.Duration(i) * time.Second)
		if i == 1 {
			secondTime = now
		}
		lastTime = now
		e := EventRequest{
			Type:     "env_probe",
			Severity: "warning",
			SourceIP: "203.0.113.10",
			Details: map[string]string{
				"domain": "example.test", "uri": "/.env", "user_agent": "Mozilla/5.0",
			},
			OccurredAt: fmtTime(now),
		}
		if got := a.Add(e, now); got != nil {
			t.Fatalf("Add occurrence %d returned %v, want nil (leading, already sent)", i+1, got)
		}
	}

	out := a.FlushDue(aggT0.Add(30 * time.Second))
	if len(out) != 1 {
		t.Fatalf("FlushDue(t0+30s) returned %d events, want 1", len(out))
	}
	rollup := out[0]
	if rollup.Count != 11 {
		t.Errorf("Count = %d, want 11", rollup.Count)
	}
	if rollup.FirstSeen != fmtTime(secondTime) {
		t.Errorf("FirstSeen = %s, want %s (2nd occurrence)", rollup.FirstSeen, fmtTime(secondTime))
	}
	if rollup.LastSeen != fmtTime(lastTime) {
		t.Errorf("LastSeen = %s, want %s", rollup.LastSeen, fmtTime(lastTime))
	}
	if rollup.OccurredAt != rollup.FirstSeen {
		t.Errorf("OccurredAt = %s, want %s (= FirstSeen)", rollup.OccurredAt, rollup.FirstSeen)
	}
	if rollup.Details["rollup"] != "true" {
		t.Errorf("Details[rollup] = %q, want \"true\"", rollup.Details["rollup"])
	}
	for k, v := range firstDetailsSnapshot {
		if rollup.Details[k] != v {
			t.Errorf("rollup Details[%s] = %q, want %q (equal to first event's)", k, rollup.Details[k], v)
		}
	}

	if !reflect.DeepEqual(first.Details, firstDetailsSnapshot) {
		t.Errorf("the first event's own Details map was mutated: %+v, want %+v", first.Details, firstDetailsSnapshot)
	}
}

func TestAggregatorLeadingSingleOccurrenceNoRollup(t *testing.T) {
	a := newEnabledAggregator(t, AggregationConfig{Enabled: true, BotWindow: 60 * time.Second, WebWindow: 30 * time.Second})

	e := EventRequest{
		Type: "env_probe", Severity: "warning", SourceIP: "203.0.113.20",
		Details: map[string]string{"domain": "example.test", "uri": "/x"}, OccurredAt: fmtTime(aggT0),
	}

	got := a.Add(e, aggT0)
	if len(got) != 1 {
		t.Fatalf("Add returned %d events, want 1", len(got))
	}

	out := a.FlushDue(aggT0.Add(30 * time.Second))
	if out != nil {
		t.Errorf("FlushDue after a single leading occurrence = %v, want nil (no rollup)", out)
	}
}

func TestAggregatorKeySeparation(t *testing.T) {
	base := func() EventRequest {
		return EventRequest{
			Type:     "env_probe",
			Severity: "info",
			SourceIP: "203.0.113.30",
			Details:  map[string]string{"domain": "a.test", "uri": "/x"},
		}
	}

	cases := map[string]func(e *EventRequest){
		"ip":       func(e *EventRequest) { e.SourceIP = "203.0.113.31" },
		"type":     func(e *EventRequest) { e.Type = "config_probe" },
		"severity": func(e *EventRequest) { e.Severity = "warning" },
		"domain":   func(e *EventRequest) { e.Details["domain"] = "b.test" },
		"uri":      func(e *EventRequest) { e.Details["uri"] = "/y" },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := newEnabledAggregator(t, AggregationConfig{Enabled: true, BotWindow: 60 * time.Second, WebWindow: 30 * time.Second})

			a.Add(base(), aggT0)
			e2 := base()
			mutate(&e2)
			a.Add(e2, aggT0)

			if got := a.Stats().Keys; got != 2 {
				t.Errorf("Stats().Keys = %d, want 2 (distinct keys for %s)", got, name)
			}
		})
	}

	t.Run("bot_slug_or_user_agent", func(t *testing.T) {
		a := newEnabledAggregator(t, AggregationConfig{Enabled: true, BotWindow: 60 * time.Second, WebWindow: 30 * time.Second})

		e1 := EventRequest{Type: "bot_unknown", Severity: "info", SourceIP: "203.0.113.40",
			Details: map[string]string{"domain": "a.test", "bot_slug": "slugA", "user_agent": "UA-A"}}
		e2 := EventRequest{Type: "bot_unknown", Severity: "info", SourceIP: "203.0.113.40",
			Details: map[string]string{"domain": "a.test", "bot_slug": "slugB", "user_agent": "UA-A"}}
		e3 := EventRequest{Type: "bot_unknown", Severity: "info", SourceIP: "203.0.113.40",
			Details: map[string]string{"domain": "a.test", "bot_slug": "slugA", "user_agent": "UA-B"}}

		a.Add(e1, aggT0)
		a.Add(e2, aggT0)
		a.Add(e3, aggT0)

		if got := a.Stats().Keys; got != 3 {
			t.Errorf("Stats().Keys = %d, want 3 (bot_slug and user_agent both separate keys)", got)
		}
	})

	t.Run("target_port", func(t *testing.T) {
		// aggregatableTypes is bot/web only today, so there is no real
		// event type that reaches keyFor's port-fallback branch through
		// ShouldAggregate; this exercises keyFor directly to prove the
		// fallback itself separates distinct ports (and nil) correctly,
		// should a future type ever reach it.
		port1, port2 := 80, 443
		k1 := keyFor(EventRequest{Type: "other_net_type", Severity: "info", SourceIP: "203.0.113.50", TargetPort: &port1})
		k2 := keyFor(EventRequest{Type: "other_net_type", Severity: "info", SourceIP: "203.0.113.50", TargetPort: &port2})
		k3 := keyFor(EventRequest{Type: "other_net_type", Severity: "info", SourceIP: "203.0.113.50", TargetPort: nil})
		if k1 == k2 || k1 == k3 || k2 == k3 {
			t.Errorf("keyFor did not separate by target_port: %+v / %+v / %+v", k1, k2, k3)
		}
	})
}

func TestAggregatorBotSampleURIs(t *testing.T) {
	a := newEnabledAggregator(t, AggregationConfig{Enabled: true, BotWindow: 60 * time.Second, WebWindow: 30 * time.Second})

	uris := []string{"/", "/a", "/b", "/c", "/d", "/e", "/f"} // 7 distinct, only first 5 kept
	for i, uri := range uris {
		now := aggT0.Add(time.Duration(i) * time.Second)
		e := EventRequest{
			Type: "bot_crawl", Severity: "info", SourceIP: "203.0.113.60",
			Details: map[string]string{
				"domain": "example.test", "bot_slug": "lab-bot", "user_agent": "LabBot/1.0", "uri": uri,
			},
			OccurredAt: fmtTime(now),
		}
		a.Add(e, now)
	}

	out := a.FlushDue(aggT0.Add(60 * time.Second))
	if len(out) != 1 {
		t.Fatalf("FlushDue returned %d events, want 1", len(out))
	}
	want := strings.Join(uris[:5], "\n")
	if got := out[0].Details["sample_uris"]; got != want {
		t.Errorf("sample_uris = %q, want %q", got, want)
	}

	// Web rows must never carry sample_uris.
	webEvent := EventRequest{
		Type: "env_probe", Severity: "info", SourceIP: "203.0.113.61",
		Details: map[string]string{"domain": "example.test", "uri": "/x"}, OccurredAt: fmtTime(aggT0),
	}
	a.Add(webEvent, aggT0)
	a.Add(webEvent, aggT0.Add(1*time.Second))
	webOut := a.FlushDue(aggT0.Add(90 * time.Second))
	if len(webOut) != 1 {
		t.Fatalf("FlushDue (web) returned %d events, want 1", len(webOut))
	}
	if v, ok := webOut[0].Details["sample_uris"]; ok {
		t.Errorf("web row has sample_uris = %q, want absent", v)
	}
}

func TestAggregatorMaxCountForcesEmit(t *testing.T) {
	t.Run("trailing", func(t *testing.T) {
		a := newEnabledAggregator(t, AggregationConfig{Enabled: true, BotWindow: 60 * time.Second, WebWindow: 30 * time.Second, MaxCount: 10})

		var lastOut []EventRequest
		for i := 0; i < 10; i++ {
			now := aggT0.Add(time.Duration(i) * time.Second)
			e := EventRequest{
				Type: "bot_unknown", Severity: "info", SourceIP: "203.0.113.70",
				Details:    map[string]string{"domain": "example.test", "user_agent": "UA/1.0", "uri": "/"},
				OccurredAt: fmtTime(now),
			}
			lastOut = a.Add(e, now)
		}
		if len(lastOut) != 1 {
			t.Fatalf("Add on the 10th occurrence returned %d events, want 1 (MaxCount reached)", len(lastOut))
		}
		if lastOut[0].Count != 10 {
			t.Errorf("Count = %d, want 10", lastOut[0].Count)
		}
		if got := a.Stats().Keys; got != 0 {
			t.Errorf("Stats().Keys = %d, want 0 (key reset after MaxCount emit)", got)
		}
	})

	t.Run("leading", func(t *testing.T) {
		a := newEnabledAggregator(t, AggregationConfig{Enabled: true, BotWindow: 60 * time.Second, WebWindow: 30 * time.Second, MaxCount: 10})

		var lastOut []EventRequest
		for i := 0; i < 10; i++ {
			now := aggT0.Add(time.Duration(i) * time.Second)
			e := EventRequest{
				Type: "env_probe", Severity: "warning", SourceIP: "203.0.113.71",
				Details: map[string]string{"domain": "example.test", "uri": "/.env"}, OccurredAt: fmtTime(now),
			}
			got := a.Add(e, now)
			if i == 0 {
				if len(got) != 1 {
					t.Fatalf("first leading occurrence returned %d events, want 1", len(got))
				}
				continue
			}
			lastOut = got
		}
		if len(lastOut) != 1 {
			t.Fatalf("Add on the 10th occurrence returned %d events, want 1 (MaxCount reached)", len(lastOut))
		}
		if lastOut[0].Count != 9 {
			t.Errorf("Count = %d, want 9 (MaxCount - 1 for a leading rollup)", lastOut[0].Count)
		}
		if got := a.Stats().Keys; got != 0 {
			t.Errorf("Stats().Keys = %d, want 0 (key reset after MaxCount emit)", got)
		}
	})
}

// TestAggregatorMaxKeysOverflow constructs the Aggregator's internal state
// directly (this file is part of package api) rather than via Configure,
// because Configure clamps MaxKeys to a floor of 100 for production safety
// (see TestAggregatorConfigureClamping) — the plan's own MaxKeys=3 overflow
// scenario needs to exercise Add's overflow handling in isolation from that
// clamp policy.
func TestAggregatorMaxKeysOverflow(t *testing.T) {
	a := &Aggregator{
		entries:   make(map[aggKey]*aggEntry),
		enabled:   true,
		botWindow: 60 * time.Second,
		webWindow: 30 * time.Second,
		maxKeys:   3,
		maxCount:  1000,
	}

	for i := 0; i < 4; i++ {
		e := EventRequest{
			Type: "env_probe", Severity: "info", SourceIP: fmt.Sprintf("203.0.113.%d", 80+i),
			Details: map[string]string{"domain": "example.test", "uri": "/x"}, OccurredAt: fmtTime(aggT0),
		}
		got := a.Add(e, aggT0)
		if i < 3 {
			if got != nil {
				t.Fatalf("Add for distinct key %d returned %v, want nil (trailing, within MaxKeys)", i, got)
			}
			continue
		}
		if len(got) != 1 || !reflect.DeepEqual(got[0], e) {
			t.Fatalf("Add for the 4th distinct key = %v, want [%v] (passthrough overflow)", got, e)
		}
	}

	if got := a.Stats().PassthroughOverflow; got != 1 {
		t.Errorf("Stats().PassthroughOverflow = %d, want 1", got)
	}
	if got := a.Stats().Keys; got != 3 {
		t.Errorf("Stats().Keys = %d, want 3 (MaxKeys)", got)
	}
}

func TestAggregatorFlushAll(t *testing.T) {
	a := newEnabledAggregator(t, AggregationConfig{Enabled: true, BotWindow: 300 * time.Second, WebWindow: 300 * time.Second})

	for i := 0; i < 3; i++ {
		e := EventRequest{
			Type: "env_probe", Severity: "info", SourceIP: fmt.Sprintf("203.0.113.%d", 90+i),
			Details: map[string]string{"domain": "example.test", "uri": "/x"}, OccurredAt: fmtTime(aggT0),
		}
		a.Add(e, aggT0)
	}

	if out := a.FlushDue(aggT0.Add(1 * time.Second)); out != nil {
		t.Fatalf("FlushDue shortly after Add = %v, want nil (window not due)", out)
	}

	out := a.FlushAll(aggT0.Add(1 * time.Second))
	if len(out) != 3 {
		t.Fatalf("FlushAll returned %d events, want 3", len(out))
	}
	if got := a.Stats().Keys; got != 0 {
		t.Errorf("Stats().Keys after FlushAll = %d, want 0", got)
	}
}

func TestAggregatorConfigureDisabling(t *testing.T) {
	a := newEnabledAggregator(t, AggregationConfig{Enabled: true, BotWindow: 300 * time.Second, WebWindow: 300 * time.Second})

	e := EventRequest{
		Type: "env_probe", Severity: "info", SourceIP: "203.0.113.95",
		Details: map[string]string{"domain": "example.test", "uri": "/x"}, OccurredAt: fmtTime(aggT0),
	}
	if got := a.Add(e, aggT0); got != nil {
		t.Fatalf("Add = %v, want nil (held for aggregation)", got)
	}

	pending := a.Configure(AggregationConfig{Enabled: false}, aggT0.Add(1*time.Second))
	if len(pending) != 1 || !reflect.DeepEqual(pending[0], e) {
		t.Fatalf("Configure(disabled) returned %v, want [%v] (the pending entry)", pending, e)
	}
	if a.Enabled() {
		t.Error("Enabled() = true after Configure(disabled)")
	}

	got := a.Add(e, aggT0.Add(2*time.Second))
	if len(got) != 1 || !reflect.DeepEqual(got[0], e) {
		t.Fatalf("Add after disabling = %v, want [%v] (passthrough)", got, e)
	}
}

func TestAggregatorConfigureClamping(t *testing.T) {
	t.Run("windows clamp into [5s,300s]", func(t *testing.T) {
		a := newEnabledAggregator(t, AggregationConfig{Enabled: true, BotWindow: 1 * time.Second, WebWindow: 1000 * time.Second})
		if a.botWindow != 5*time.Second {
			t.Errorf("botWindow = %s, want 5s (clamped up)", a.botWindow)
		}
		if a.webWindow != 300*time.Second {
			t.Errorf("webWindow = %s, want 300s (clamped down)", a.webWindow)
		}
	})

	t.Run("MaxKeys 0 defaults to 10000", func(t *testing.T) {
		a := newEnabledAggregator(t, AggregationConfig{Enabled: true, BotWindow: 60 * time.Second, WebWindow: 30 * time.Second})
		if a.maxKeys != 10000 {
			t.Errorf("maxKeys = %d, want 10000 (default)", a.maxKeys)
		}
	})

	t.Run("MaxKeys clamps into [100,100000]", func(t *testing.T) {
		low := newEnabledAggregator(t, AggregationConfig{Enabled: true, BotWindow: 60 * time.Second, WebWindow: 30 * time.Second, MaxKeys: 3})
		if low.maxKeys != 100 {
			t.Errorf("maxKeys = %d, want 100 (clamped up from 3)", low.maxKeys)
		}

		high := newEnabledAggregator(t, AggregationConfig{Enabled: true, BotWindow: 60 * time.Second, WebWindow: 30 * time.Second, MaxKeys: 999999})
		if high.maxKeys != 100000 {
			t.Errorf("maxKeys = %d, want 100000 (clamped down)", high.maxKeys)
		}
	})

	t.Run("MaxCount 0 defaults to 1000", func(t *testing.T) {
		a := newEnabledAggregator(t, AggregationConfig{Enabled: true, BotWindow: 60 * time.Second, WebWindow: 30 * time.Second})
		if a.maxCount != 1000 {
			t.Errorf("maxCount = %d, want 1000 (default)", a.maxCount)
		}
	})

	t.Run("MaxCount clamps into [10,100000]", func(t *testing.T) {
		a := newEnabledAggregator(t, AggregationConfig{Enabled: true, BotWindow: 60 * time.Second, WebWindow: 30 * time.Second, MaxCount: 1})
		if a.maxCount != 10 {
			t.Errorf("maxCount = %d, want 10 (clamped up from 1)", a.maxCount)
		}
	})

	t.Run("window <= 0 forces Enabled false", func(t *testing.T) {
		a := newEnabledAggregator(t, AggregationConfig{Enabled: true, BotWindow: 0, WebWindow: 30 * time.Second})
		if a.Enabled() {
			t.Error("Enabled() = true, want false (BotWindow <= 0 is the kill switch)")
		}
	})
}

func TestAggregatorStatsCounters(t *testing.T) {
	a := newEnabledAggregator(t, AggregationConfig{Enabled: true, BotWindow: 60 * time.Second, WebWindow: 30 * time.Second})

	for i := 0; i < 3; i++ {
		e := EventRequest{
			Type: "bot_unknown", Severity: "info", SourceIP: "203.0.113.100",
			Details:    map[string]string{"domain": "example.test", "user_agent": "UA", "uri": "/"},
			OccurredAt: fmtTime(aggT0),
		}
		a.Add(e, aggT0.Add(time.Duration(i)*time.Second))
	}

	leadE := EventRequest{
		Type: "env_probe", Severity: "warning", SourceIP: "203.0.113.101",
		Details: map[string]string{"domain": "example.test", "uri": "/x"}, OccurredAt: fmtTime(aggT0),
	}
	a.Add(leadE, aggT0)

	critE := EventRequest{Type: "malware_realtime", Severity: "critical", SourceIP: "203.0.113.102"}
	a.Add(critE, aggT0)

	stats := a.Stats()
	if stats.In != 5 {
		t.Errorf("In = %d, want 5", stats.In)
	}
	if stats.Out != 2 {
		t.Errorf("Out = %d, want 2 (leading immediate return + critical passthrough)", stats.Out)
	}

	// The leading env_probe entry only ever saw 1 occurrence, so FlushAll
	// has nothing left to emit for it; only the trailing bot_unknown entry
	// (3 occurrences) is still pending.
	out := a.FlushAll(aggT0.Add(time.Minute))
	if len(out) != 1 {
		t.Fatalf("FlushAll returned %d events, want 1", len(out))
	}
	if out[0].Count != 3 {
		t.Errorf("flushed Count = %d, want 3", out[0].Count)
	}

	final := a.Stats()
	if want := stats.Out + uint64(len(out)); final.Out != want {
		t.Errorf("Out after FlushAll = %d, want %d", final.Out, want)
	}
}

func TestAggregatorConcurrency(t *testing.T) {
	a := newEnabledAggregator(t, AggregationConfig{
		Enabled: true, BotWindow: 300 * time.Second, WebWindow: 300 * time.Second,
		MaxCount: 100000, MaxKeys: 100000,
	})

	const goroutines = 50
	const perGoroutine = 200
	const keys = 5

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				k := (g*perGoroutine + i) % keys
				e := EventRequest{
					Type: "bot_unknown", Severity: "info",
					SourceIP:   fmt.Sprintf("203.0.113.%d", 110+k),
					Details:    map[string]string{"domain": "example.test", "user_agent": "UA", "uri": "/"},
					OccurredAt: fmtTime(aggT0),
				}
				a.Add(e, aggT0)
			}
		}(g)
	}
	wg.Wait()

	out := a.FlushAll(aggT0.Add(time.Hour))
	total := 0
	for _, e := range out {
		if e.Count == 0 {
			total++
		} else {
			total += e.Count
		}
	}
	if total != goroutines*perGoroutine {
		t.Errorf("total Count across flushed entries = %d, want %d", total, goroutines*perGoroutine)
	}
}

// TestContractScenarioMatchesPanelFixture replays the scripted scenario
// from the plan through a real Aggregator and asserts the collected
// output matches the panel's contract fixture exactly (semantic JSON
// equality, order-independent).
func TestContractScenarioMatchesPanelFixture(t *testing.T) {
	a := newEnabledAggregator(t, AggregationConfig{Enabled: true, BotWindow: 60 * time.Second, WebWindow: 30 * time.Second})

	var collected []EventRequest

	// env_probe: first occurrence, then 11 more at seconds 2,4,7,10,13,16,19,22,25,27,29.
	envSeconds := []int{0, 2, 4, 7, 10, 13, 16, 19, 22, 25, 27, 29}
	for _, s := range envSeconds {
		now := aggT0.Add(time.Duration(s) * time.Second)
		e := EventRequest{
			Type:     "env_probe",
			Severity: "warning",
			SourceIP: "203.0.113.10",
			Details: map[string]string{
				"domain": "example.test", "uri": "/.env", "user_agent": "Mozilla/5.0",
			},
			OccurredAt: fmtTime(now),
		}
		collected = append(collected, a.Add(e, now)...)
	}

	// bot_unknown: 40 occurrences spread across seconds 0..59, uris cycling / /a /b.
	botURIs := []string{"/", "/a", "/b"}
	for i := 0; i < 40; i++ {
		sec := i * 59 / 39
		now := aggT0.Add(time.Duration(sec) * time.Second)
		e := EventRequest{
			Type:     "bot_unknown",
			Severity: "info",
			SourceIP: "203.0.113.11",
			Details: map[string]string{
				"domain": "example.test", "user_agent": "LabAggBot/1.0 (+bot)", "uri": botURIs[i%len(botURIs)],
			},
			OccurredAt: fmtTime(now),
		}
		collected = append(collected, a.Add(e, now)...)
	}

	// malware_realtime: critical, always individual, no source_ip in this scenario.
	malwareNow := aggT0.Add(5 * time.Second)
	malwareEvent := EventRequest{
		Type:     "malware_realtime",
		Severity: "critical",
		Details: map[string]string{
			"domain": "example.test", "file": "/var/www/example.test/x.php", "signature": "lab-test",
		},
		OccurredAt: fmtTime(malwareNow),
	}
	collected = append(collected, a.Add(malwareEvent, malwareNow)...)

	collected = append(collected, a.FlushDue(aggT0.Add(30*time.Second))...)
	collected = append(collected, a.FlushDue(aggT0.Add(60*time.Second))...)

	gotJSON, err := json.Marshal(collected)
	if err != nil {
		t.Fatalf("marshal collected events: %v", err)
	}
	var gotMaps []map[string]any
	if err := json.Unmarshal(gotJSON, &gotMaps); err != nil {
		t.Fatalf("unmarshal collected events: %v", err)
	}

	wantRaw, err := os.ReadFile(filepath.Join("testdata", "contracts", "events_aggregated_batch.json"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	var fixture struct {
		Events []map[string]any `json:"events"`
	}
	if err := json.Unmarshal(wantRaw, &fixture); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	sortEventMapsByTypeAndOccurredAt(gotMaps)
	sortEventMapsByTypeAndOccurredAt(fixture.Events)

	if !reflect.DeepEqual(gotMaps, fixture.Events) {
		t.Errorf("aggregator output does not match the panel fixture:\n got  %+v\n want %+v", gotMaps, fixture.Events)
	}
}

func sortEventMapsByTypeAndOccurredAt(events []map[string]any) {
	sort.Slice(events, func(i, j int) bool {
		ti, _ := events[i]["type"].(string)
		tj, _ := events[j]["type"].(string)
		if ti != tj {
			return ti < tj
		}
		oi, _ := events[i]["occurred_at"].(string)
		oj, _ := events[j]["occurred_at"].(string)
		return oi < oj
	})
}
