package api

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

// Aggregator merges repeated low-value events into rollup rows so a noisy,
// legitimate source (a crawler re-hitting the same bot signature, a scanner
// re-probing the same path) does not cost one wire event per occurrence.
//
// Aggregation happens strictly after scoring and bans have already been
// decided elsewhere in the pipeline — merging rows never changes whether an
// IP gets banned or an alert fires, only how many wire-identical rows are
// sent for the same decision. Criticals, and the locked never-aggregate
// types in eventtypes.go, never pass through here at all (see ShouldAggregate);
// an aggregated row is never the only record of something that mattered.
//
// Every key gets exactly one time window, anchored at the moment of its
// first occurrence (not sliding, not reset by later occurrences): this
// keeps worst-case latency bounded and makes the window math trivial to
// reason about. Within that window, "leading" severities (anything other
// than info) emit their first occurrence immediately and unchanged — this
// is what keeps alert latency at zero for anything that matters enough to
// alert on — and only the remainder (if any) becomes a single rollup row at
// window close. "Trailing" severities (info) hold everything until window
// close, since there is nothing time-sensitive about a crawler.
type Aggregator struct {
	mu sync.Mutex

	enabled    bool
	botWindow  time.Duration
	webWindow  time.Duration
	maxKeys    int
	maxCount   int
	panelTypes map[string]bool

	entries map[aggKey]*aggEntry
	counts  aggCounts
}

// aggKey identifies one aggregation bucket. target encodes the
// type-specific dimension that must stay distinct: domain+URI for web
// attack types (the same probe hitting two paths is two findings), or
// domain+bot_slug+user_agent for bot types (the URI varies per request and
// is instead sampled into details.sample_uris).
type aggKey struct {
	typ, sev, ip, target string
}

// aggEntry is the in-memory state for one aggKey. first anchors the
// window deadline; second is the timestamp of the *second* occurrence,
// which becomes a leading rollup's FirstSeen (the first occurrence was
// already emitted on its own, so the rollup only ever covers occurrence 2..N).
type aggEntry struct {
	first, second, last time.Time
	count               int
	sample              EventRequest
	uris                []string
	leading             bool
	deadline            time.Time
}

type aggCounts struct {
	In, Out, PassthroughOverflow uint64
}

// AggregationConfig configures an Aggregator. The zero value disables
// aggregation entirely (NewAggregator returns an Aggregator already in
// this state, so aggregation is opt-in).
type AggregationConfig struct {
	Enabled   bool
	BotWindow time.Duration
	WebWindow time.Duration
	MaxKeys   int
	MaxCount  int
	// PanelTypes, when non-nil, restricts which of the agent's own
	// aggregatableTypes are actually enabled right now. It can only
	// restrict, never extend: a type absent from aggregatableTypes is
	// never aggregated no matter what PanelTypes says. nil means "every
	// type the agent itself allows".
	PanelTypes map[string]bool
}

// AggregatorStats is a snapshot of the Aggregator's lifetime counters plus
// its current live key count.
type AggregatorStats struct {
	In, Out, PassthroughOverflow uint64
	Keys                         int
}

// NewAggregator returns a disabled Aggregator: Add passes every event
// through unchanged until Configure enables it. This is the zero-value
// safe default — aggregation must be explicitly turned on.
func NewAggregator() *Aggregator {
	return &Aggregator{
		entries: make(map[aggKey]*aggEntry),
	}
}

// Enabled reports whether the Aggregator is currently aggregating.
func (a *Aggregator) Enabled() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.enabled
}

// Stats returns a snapshot of the Aggregator's counters.
func (a *Aggregator) Stats() AggregatorStats {
	a.mu.Lock()
	defer a.mu.Unlock()
	return AggregatorStats{
		In:                  a.counts.In,
		Out:                 a.counts.Out,
		PassthroughOverflow: a.counts.PassthroughOverflow,
		Keys:                len(a.entries),
	}
}

// Configure applies a new configuration, flushing every entry pending
// under the OLD configuration first (returned to the caller to send) so
// nothing is silently carried over against windows that may no longer
// apply. Clamps: BotWindow/WebWindow to [5s, 300s] when enabling;
// MaxKeys to [100, 100000] (0 means "use the default of 10000"); MaxCount
// to [10, 100000] (0 means "use the default of 1000"). A BotWindow or
// WebWindow of zero or less forces Enabled to false regardless of
// cfg.Enabled — this is the aggregation kill switch.
func (a *Aggregator) Configure(cfg AggregationConfig, now time.Time) []EventRequest {
	a.mu.Lock()
	defer a.mu.Unlock()

	_ = now // kept for interface symmetry with FlushAll; flushing on reconfigure is unconditional

	pending := a.flushAllLocked()

	enabled := cfg.Enabled && cfg.BotWindow > 0 && cfg.WebWindow > 0

	botWindow := cfg.BotWindow
	webWindow := cfg.WebWindow
	if enabled {
		botWindow = clampDuration(botWindow, 5*time.Second, 300*time.Second)
		webWindow = clampDuration(webWindow, 5*time.Second, 300*time.Second)
	}

	maxKeys := cfg.MaxKeys
	if maxKeys == 0 {
		maxKeys = 10000
	} else {
		maxKeys = clampInt(maxKeys, 100, 100000)
	}

	maxCount := cfg.MaxCount
	if maxCount == 0 {
		maxCount = 1000
	} else {
		maxCount = clampInt(maxCount, 10, 100000)
	}

	a.enabled = enabled
	a.botWindow = botWindow
	a.webWindow = webWindow
	a.maxKeys = maxKeys
	a.maxCount = maxCount
	a.panelTypes = cfg.PanelTypes

	a.counts.Out += uint64(len(pending))
	return pending
}

// Add offers one event to the aggregator. It returns the events (zero,
// one, or occasionally more via the caller's own batching — always zero
// or one from this method) that should be sent to the server right now;
// anything held for later aggregation is returned later, from FlushDue or
// FlushAll.
func (a *Aggregator) Add(e EventRequest, now time.Time) []EventRequest {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.counts.In++

	if !a.enabled || !ShouldAggregate(e, a.panelTypes) {
		a.counts.Out++
		return []EventRequest{e}
	}

	key := keyFor(e)
	entry, ok := a.entries[key]
	if !ok {
		if len(a.entries) >= a.maxKeys {
			a.counts.PassthroughOverflow++
			a.counts.Out++
			return []EventRequest{e}
		}

		sample := e
		sample.Details = cloneDetails(e.Details)

		var uris []string
		if isBotType(e.Type) {
			if uri := e.Details["uri"]; uri != "" {
				uris = []string{uri}
			}
		}

		leading := e.Severity != "info"
		a.entries[key] = &aggEntry{
			first:    now,
			last:     now,
			count:    1,
			sample:   sample,
			uris:     uris,
			leading:  leading,
			deadline: now.Add(a.windowFor(e.Type)),
		}

		if leading {
			a.counts.Out++
			return []EventRequest{e}
		}
		return nil
	}

	entry.count++
	if entry.count == 2 {
		entry.second = now
	}
	entry.last = now
	mergeBotFields(entry.sample.Details, e.Details)
	if isBotType(e.Type) {
		collectURI(entry, e.Details["uri"])
	}

	if entry.count >= a.maxCount {
		built := a.build(entry)
		delete(a.entries, key)
		if built != nil {
			a.counts.Out++
			return []EventRequest{*built}
		}
		return nil
	}

	return nil
}

// FlushDue emits and clears every entry whose window has closed as of now.
//
// This is a plain O(n) scan over the live entry map rather than a
// deadline-ordered heap. That is an acceptable complexity tradeoff at
// MaxKeys <= 100000 as long as the caller invokes FlushDue roughly once per
// second (the agent's existing eventFlushEvery-style ticker cadence): the
// scan cost is bounded by the configured key cap, not by event volume, and
// a heap would add complexity (deadline updates on every Add) for a
// workload where the entry count is already the thing being bounded.
func (a *Aggregator) FlushDue(now time.Time) []EventRequest {
	a.mu.Lock()
	defer a.mu.Unlock()

	var out []EventRequest
	for key, entry := range a.entries {
		if entry.deadline.After(now) {
			continue
		}
		if built := a.build(entry); built != nil {
			out = append(out, *built)
		}
		delete(a.entries, key)
	}
	a.counts.Out += uint64(len(out))
	return out
}

// FlushAll emits and clears every pending entry regardless of window —
// used on shutdown so nothing aggregated-but-not-yet-sent is lost.
func (a *Aggregator) FlushAll(now time.Time) []EventRequest {
	a.mu.Lock()
	defer a.mu.Unlock()

	_ = now // flushing everything is, by definition, independent of the current time

	out := a.flushAllLocked()
	a.counts.Out += uint64(len(out))
	return out
}

// flushAllLocked is FlushAll's body, factored out so Configure can reuse it
// without double-locking or double-counting Stats().Out (callers add the
// returned length to a.counts.Out themselves).
func (a *Aggregator) flushAllLocked() []EventRequest {
	var out []EventRequest
	for key, entry := range a.entries {
		if built := a.build(entry); built != nil {
			out = append(out, *built)
		}
		delete(a.entries, key)
	}
	return out
}

// build turns one aggEntry into the single EventRequest that represents
// it, or nil if there is nothing worth emitting (a leading entry whose
// first occurrence was already sent and that never saw a second one).
func (a *Aggregator) build(entry *aggEntry) *EventRequest {
	if entry.leading {
		if entry.count <= 1 {
			return nil
		}
		out := entry.sample
		out.Details = cloneDetails(entry.sample.Details)
		if out.Details == nil {
			out.Details = map[string]string{}
		}
		out.Details["rollup"] = "true"
		if isBotType(out.Type) {
			if sampleURIs := joinURIs(entry.uris); sampleURIs != "" {
				out.Details["sample_uris"] = sampleURIs
			}
		}
		out.Count = entry.count - 1
		out.FirstSeen = fmtTime(entry.second)
		out.LastSeen = fmtTime(entry.last)
		out.OccurredAt = out.FirstSeen
		return &out
	}

	// Trailing: the whole window collapses into one row, preserving the
	// first event's own OccurredAt (it is still the first thing that
	// happened), with Count/FirstSeen/LastSeen only set once there is more
	// than one occurrence to report — a lone trailing event must come out
	// byte-identical to what went in.
	out := entry.sample
	out.Details = cloneDetails(entry.sample.Details)
	if entry.count > 1 {
		out.Count = entry.count
		out.FirstSeen = fmtTime(entry.first)
		out.LastSeen = fmtTime(entry.last)
	}
	if isBotType(out.Type) && (len(entry.uris) > 1 || entry.count > 1) {
		if out.Details == nil {
			out.Details = map[string]string{}
		}
		if sampleURIs := joinURIs(entry.uris); sampleURIs != "" {
			out.Details["sample_uris"] = sampleURIs
		}
	}
	return &out
}

// windowFor returns the configured window for t's family: bot types noise
// over a longer window (they are volume, not urgency); everything else
// (web attack types, by construction the only other aggregatable family)
// uses the shorter window.
func (a *Aggregator) windowFor(t string) time.Duration {
	if isBotType(t) {
		return a.botWindow
	}
	return a.webWindow
}

// keyFor computes the aggregation key for e. target is the type-specific
// dimension that must stay distinct within (type, severity, source_ip):
// domain+URI for web types, domain+bot_slug+user_agent for bot types, and
// domain+target_port as a defensive fallback for any future aggregatable
// type that is neither (aggregatableTypes is a subset of botTypes∪webTypes
// today, so this branch is not reachable from real traffic, but the key
// function must not panic or silently collapse distinct targets if that
// invariant is ever loosened).
func keyFor(e EventRequest) aggKey {
	domain := e.Details["domain"]

	var target string
	switch {
	case isWebType(e.Type):
		target = domain + "|" + e.Details["uri"]
	case isBotType(e.Type):
		target = domain + "|" + e.Details["bot_slug"] + "|" + e.Details["user_agent"]
	default:
		portPart := "-"
		if e.TargetPort != nil {
			portPart = strconv.Itoa(*e.TargetPort)
		}
		target = domain + "|" + portPart
	}

	return aggKey{typ: e.Type, sev: e.Severity, ip: e.SourceIP, target: target}
}

// mergeBotFields copies the bot classifier's mutable fields from the
// newest event's details into the aggregate's running sample, so the
// eventual rollup/trailing row reflects the latest score/action rather
// than a stale one from the first occurrence.
func mergeBotFields(dst, src map[string]string) {
	if dst == nil || src == nil {
		return
	}
	for _, k := range []string{"bot_score", "bot_action"} {
		if v, ok := src[k]; ok {
			dst[k] = v
		}
	}
}

// collectURI records uri into entry's sample set for a bot-type entry: up
// to 5 distinct URIs, kept in first-seen order, used to build
// details.sample_uris at build time.
func collectURI(entry *aggEntry, uri string) {
	if uri == "" || len(entry.uris) >= 5 {
		return
	}
	for _, u := range entry.uris {
		if u == uri {
			return
		}
	}
	entry.uris = append(entry.uris, uri)
}

// joinURIs renders up to the first 5 collected URIs (already capped by
// collectURI) as a newline-joined sample, or "" if there is nothing to show.
func joinURIs(uris []string) string {
	if len(uris) == 0 {
		return ""
	}
	n := len(uris)
	if n > 5 {
		n = 5
	}
	return strings.Join(uris[:n], "\n")
}

// cloneDetails returns an independent copy of src (nil in, nil out) so an
// aggregate entry's internal state can be mutated without ever reaching
// back into a map the caller still holds a reference to.
func cloneDetails(src map[string]string) map[string]string {
	if src == nil {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// fmtTime renders t as the RFC3339 UTC string the wire format and the
// panel fixtures both expect for first_seen/last_seen/occurred_at.
func fmtTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

func clampDuration(d, min, max time.Duration) time.Duration {
	if d < min {
		return min
	}
	if d > max {
		return max
	}
	return d
}

func clampInt(n, min, max int) int {
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}
