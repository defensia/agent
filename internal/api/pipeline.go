package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"sync/atomic"
	"time"
)

// Phase 19 AGG-02/AGG-04: wires the Aggregator into the event queue behind
// an explicit panel capability handshake, and fixes the three places the
// event pipeline used to lose data silently — a full queue, a batch the
// server rejected, and a batch still in flight at shutdown. See
// ConfigureAggregation, sendWithRetry and Shutdown below.

// SetClock overrides the Client's notion of "now", for replay/load
// testing; production uses time.Now (the default set by New). A load
// test replaying a day of recorded traffic needs event timestamps,
// window deadlines and retry/backoff math to all advance on the
// replayed clock, not the wall clock the replay itself runs on.
func (c *Client) SetClock(now func() time.Time) {
	c.now = now
}

// EventAggregationSync is the config.event_aggregation block the panel
// advertises on every sync (plan 04's contract). Its mere presence with
// Supported=true is the signal an old panel — which never sends this key
// at all — can never produce; see AggregationConfigFromSync.
type EventAggregationSync struct {
	Supported        bool     `json:"supported"`
	Enabled          bool     `json:"enabled"`
	BotWindowSeconds int      `json:"bot_window_seconds"`
	WebWindowSeconds int      `json:"web_window_seconds"`
	MaxKeys          int      `json:"max_keys"`
	MaxCount         int      `json:"max_count"`
	Types            []string `json:"types"`
}

// AggregationConfigFromSync decodes the panel's sync block into an
// AggregationConfig. The agent aggregates ONLY when s is non-nil,
// Supported and Enabled are both true, and the local
// DEFENSIA_EVENT_AGGREGATION env var is not "off" — any other combination
// (missing key, supported=false, enabled=false, or the env override)
// yields the zero-value AggregationConfig, which disables the Aggregator
// (pass-through, today's behaviour).
//
// s.Types, when non-nil, becomes AggregationConfig.PanelTypes: a nil Types
// slice (key absent) leaves PanelTypes nil ("whatever the agent itself
// allows"), while an empty slice becomes an empty, non-nil map, which
// restricts aggregation to nothing at all. PanelTypes can only ever
// restrict the agent's own aggregatableTypes (eventtypes.go), never extend
// it — see ShouldAggregate.
func AggregationConfigFromSync(s *EventAggregationSync) AggregationConfig {
	if s == nil || !s.Supported || !s.Enabled || os.Getenv("DEFENSIA_EVENT_AGGREGATION") == "off" {
		return AggregationConfig{}
	}

	cfg := AggregationConfig{
		Enabled:   true,
		BotWindow: time.Duration(s.BotWindowSeconds) * time.Second,
		WebWindow: time.Duration(s.WebWindowSeconds) * time.Second,
		MaxKeys:   s.MaxKeys,
		MaxCount:  s.MaxCount,
	}

	if s.Types != nil {
		types := make(map[string]bool, len(s.Types))
		for _, t := range s.Types {
			types[t] = true
		}
		cfg.PanelTypes = types
	}

	return cfg
}

// ConfigureAggregation applies cfg to the Aggregator and enqueues anything
// the reconfigure flushed (entries pending under the old configuration —
// see Aggregator.Configure), so turning aggregation off at runtime delivers
// every pending aggregate immediately instead of waiting for a window that
// will never close. Logs once, only when the enabled state actually
// changes, so a sync that reports identical config every five minutes does
// not spam the log.
func (c *Client) ConfigureAggregation(cfg AggregationConfig) {
	wasEnabled := c.agg.Enabled()

	pending := c.agg.Configure(cfg, c.now())
	for _, e := range pending {
		c.enqueue(e)
	}

	nowEnabled := c.agg.Enabled()
	if nowEnabled != wasEnabled {
		log.Printf("[api] event aggregation enabled=%v bot=%s web=%s types=%d", nowEnabled, cfg.BotWindow, cfg.WebWindow, len(cfg.PanelTypes))
	}
}

// EventPipelineStats is the heartbeat's event_pipeline block (plan 04's
// contract): exactly these 12 keys, always present (no omitempty on any
// field), so the panel can tell a reporting-zero agent from one that never
// upgraded to report this block at all via the enclosing *EventPipelineStats
// pointer on HeartbeatRequest being nil.
type EventPipelineStats struct {
	AggregationEnabled  bool   `json:"aggregation_enabled"`
	QueueDepth          int    `json:"queue_depth"`
	QueueCapacity       int    `json:"queue_capacity"`
	DroppedQueueFull    uint64 `json:"dropped_queue_full"`
	DroppedSendFailed   uint64 `json:"dropped_send_failed"`
	DroppedRejected     uint64 `json:"dropped_rejected"`
	AggregatedIn        uint64 `json:"aggregated_in"`
	AggregatedOut       uint64 `json:"aggregated_out"`
	PassthroughOverflow uint64 `json:"passthrough_overflow"`
	BatchesSent         uint64 `json:"batches_sent"`
	EventsSent          uint64 `json:"events_sent"`
	Retries             uint64 `json:"retries"`
}

// EventPipelineStats snapshots the event queue, aggregator and delivery
// counters for the heartbeat.
func (c *Client) EventPipelineStats() *EventPipelineStats {
	aggStats := c.agg.Stats()
	return &EventPipelineStats{
		AggregationEnabled:  c.agg.Enabled(),
		QueueDepth:          len(c.eventCh),
		QueueCapacity:       eventQueueSize,
		DroppedQueueFull:    atomic.LoadUint64(&c.droppedQueueFull),
		DroppedSendFailed:   atomic.LoadUint64(&c.droppedSendFailed),
		DroppedRejected:     atomic.LoadUint64(&c.droppedRejected),
		AggregatedIn:        aggStats.In,
		AggregatedOut:       aggStats.Out,
		PassthroughOverflow: aggStats.PassthroughOverflow,
		BatchesSent:         atomic.LoadUint64(&c.batchesSent),
		EventsSent:          atomic.LoadUint64(&c.eventsSent),
		Retries:             atomic.LoadUint64(&c.retries),
	}
}

// maxSendAttempts bounds sendWithRetry: at most this many attempts at one
// batch (the original send plus two retries), regardless of deadline.
const maxSendAttempts = 3

// maxRetryBackoff is the ceiling for both the computed exponential backoff
// and a server-supplied Retry-After.
const maxRetryBackoff = 30 * time.Second

// eventIndexPattern extracts the batch index from a Laravel 422 field
// error line of the form "events.3.type: the selected ... is invalid.".
var eventIndexPattern = regexp.MustCompile(`^events\.(\d+)\.`)

// sendWithRetry delivers batch, retrying bounded transient failures and
// counting every event that is ultimately not delivered. It never silently
// discards a batch (phase 19 AGG-04):
//
//   - success: batchesSent++, eventsSent += len(batch).
//   - 422 naming specific events.N.* indexes: those indexes are dropped
//     (droppedRejected), and the remainder is resent once more (consuming
//     one of the maxSendAttempts budget) — unless 422 named none or all of
//     the batch, in which case the whole batch is dropped and sending
//     stops (resending an unparseable or wholesale rejection can only
//     repeat it).
//   - any other permanent (4xx except 429) response: the whole batch is
//     dropped (droppedRejected) and sending stops — the payload itself is
//     wrong, not the timing.
//   - a transient failure (5xx, 429, or a transport/context error): waits
//     Retry-After if the server sent one, else an exponential backoff
//     (1s, 2s, 4s, ... capped at 30s), then retries — unless this was
//     already the last attempt or waiting would cross deadline, in which
//     case the whole remaining batch is dropped (droppedSendFailed) and
//     sending stops.
//
// deadline bounds how far retry waits are allowed to push into the future;
// it does not bound the duration of any single HTTP attempt beyond what
// postEvents itself derives from it (see postEvents). Callers that have no
// real deadline (ordinary periodic flushes) pass one far in the future, so
// maxSendAttempts — not deadline — is what actually stops retrying.
func (c *Client) sendWithRetry(batch []EventRequest, deadline time.Time) {
	if len(batch) == 0 {
		return
	}

	for attempt := 1; attempt <= maxSendAttempts; attempt++ {
		err := c.postEvents(batch, deadline)
		if err == nil {
			atomic.AddUint64(&c.batchesSent, 1)
			atomic.AddUint64(&c.eventsSent, uint64(len(batch)))
			return
		}

		var he *HTTPError
		if errors.As(err, &he) {
			if he.Status == http.StatusUnprocessableEntity {
				bad := parseRejectedIndexes(he.FieldErrors(), len(batch))
				if len(bad) > 0 && len(bad) < len(batch) {
					batch = removeIndexes(batch, bad)
					atomic.AddUint64(&c.droppedRejected, uint64(len(bad)))
					continue
				}
				atomic.AddUint64(&c.droppedRejected, uint64(len(batch)))
				log.Printf("[api] event batch rejected (422, %d events dropped): %s", len(batch), he.Message())
				return
			}

			if he.Permanent() {
				atomic.AddUint64(&c.droppedRejected, uint64(len(batch)))
				log.Printf("[api] event batch rejected (%d, %d events dropped): %s", he.Status, len(batch), he.Message())
				return
			}

			atomic.AddUint64(&c.retries, 1)
			wait := he.RetryAfter
			if wait <= 0 {
				wait = retryBackoff(attempt)
			}
			if wait > maxRetryBackoff {
				wait = maxRetryBackoff
			}
			if attempt >= maxSendAttempts || c.now().Add(wait).After(deadline) {
				break
			}
			c.sleep(wait)
			continue
		}

		// Non-HTTP error: transport failure or a context deadline tripped
		// by postEvents — treated the same as a transient 5xx.
		atomic.AddUint64(&c.retries, 1)
		wait := retryBackoff(attempt)
		if attempt >= maxSendAttempts || c.now().Add(wait).After(deadline) {
			break
		}
		c.sleep(wait)
	}

	atomic.AddUint64(&c.droppedSendFailed, uint64(len(batch)))
	log.Printf("[api] event batch dropped after retries (%d events, dropped_send_failed=%d total)", len(batch), atomic.LoadUint64(&c.droppedSendFailed))
}

// retryBackoff is the exponential backoff schedule for attempt (1-based):
// 1s, 2s, 4s, ... capped at maxRetryBackoff.
func retryBackoff(attempt int) time.Duration {
	d := time.Duration(1<<uint(attempt-1)) * time.Second
	if d > maxRetryBackoff {
		return maxRetryBackoff
	}
	return d
}

// parseRejectedIndexes extracts the distinct, in-range batch indexes named
// by a Laravel 422's field errors (e.g. "events.3.type: ..."), sorted.
func parseRejectedIndexes(fieldErrors []string, batchLen int) []int {
	seen := make(map[int]bool)
	for _, line := range fieldErrors {
		m := eventIndexPattern.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		idx, err := strconv.Atoi(m[1])
		if err != nil || idx < 0 || idx >= batchLen {
			continue
		}
		seen[idx] = true
	}

	indexes := make([]int, 0, len(seen))
	for idx := range seen {
		indexes = append(indexes, idx)
	}
	sort.Ints(indexes)
	return indexes
}

// removeIndexes returns batch with the given (0-based) indexes removed,
// preserving order.
func removeIndexes(batch []EventRequest, indexes []int) []EventRequest {
	remove := make(map[int]bool, len(indexes))
	for _, idx := range indexes {
		remove[idx] = true
	}

	out := make([]EventRequest, 0, len(batch)-len(indexes))
	for i, e := range batch {
		if !remove[i] {
			out = append(out, e)
		}
	}
	return out
}

// postEvents sends one events batch, bounding the HTTP attempt itself by
// the time remaining until deadline (not by deadline as an absolute
// instant — translating it to a relative timeout here means this works
// correctly whether c.now is the real clock or a test's fake one: the
// context's own deadline arithmetic always runs on real wall-clock time).
// A deadline already passed yields a near-zero timeout, so the attempt
// fails fast rather than hanging.
func (c *Client) postEvents(batch []EventRequest, deadline time.Time) error {
	data, err := json.Marshal(map[string]any{"events": batch})
	if err != nil {
		return err
	}

	remaining := deadline.Sub(c.now())
	if remaining < 0 {
		remaining = 0
	}

	ctx, cancel := context.WithTimeout(context.Background(), remaining)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/agent/events", bytes.NewReader(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return &HTTPError{
			Status:     resp.StatusCode,
			Body:       string(b),
			RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), c.now()),
		}
	}

	return nil
}

// shutdownRequest is sent on Client.stopCh to ask eventConsumerLoop to
// flush everything pending (aggregator + queue) within deadline and signal
// done when finished.
type shutdownRequest struct {
	deadline time.Time
	done     chan struct{}
}

// Shutdown flushes every pending aggregate and queued event, within
// timeout, before returning. Safe to call whether or not
// StartEventConsumer was ever called: with no consumer running it flushes
// synchronously; with one running it asks the consumer goroutine to do it
// (so there is never a second goroutine racing the consumer's batch slice)
// and waits for it to finish or for timeout, whichever comes first — a
// consumer stuck mid-request (e.g. a server that never responds) still
// returns control to the caller at timeout, counting whatever did not get
// out the door as dropped_send_failed.
func (c *Client) Shutdown(timeout time.Duration) {
	deadline := c.now().Add(timeout)

	if !c.consumerRunning.Load() {
		pending := c.agg.FlushAll(c.now())
		pending = append(pending, c.drainQueued()...)
		for i := 0; i < len(pending); i += eventBatchSize {
			end := i + eventBatchSize
			if end > len(pending) {
				end = len(pending)
			}
			c.sendWithRetry(pending[i:end], deadline)
		}
		return
	}

	done := make(chan struct{})
	select {
	case c.stopCh <- shutdownRequest{deadline: deadline, done: done}:
	case <-time.After(timeout):
		// The consumer loop is not (or no longer) listening on stopCh —
		// nothing more this call can safely do within its own deadline.
		return
	}

	select {
	case <-done:
	case <-time.After(timeout):
	}
}

// drainQueued empties c.eventCh without blocking.
func (c *Client) drainQueued() []EventRequest {
	var out []EventRequest
	for {
		select {
		case e := <-c.eventCh:
			out = append(out, e)
		default:
			return out
		}
	}
}
