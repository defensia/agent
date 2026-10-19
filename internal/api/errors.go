package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// HTTPError is returned for every non-2xx API response. It keeps the status and
// the raw body so callers can tell a permanent rejection apart from something
// worth retrying, and can show the operator what the server actually said.
type HTTPError struct {
	Status int
	Body   string

	// RetryAfter is the parsed Retry-After header, or 0 when the response
	// carried none.
	RetryAfter time.Duration
}

// Error keeps the wording the client used before HTTPError existed, so log
// output and support transcripts stay comparable across versions.
func (e *HTTPError) Error() string {
	return fmt.Sprintf("server returned %d: %s", e.Status, e.Body)
}

// Permanent reports whether resending the identical request could ever succeed.
// Every 4xx except 429 is permanent: the server refused the payload, not the
// timing, so a retry can only burn the caller's rate budget and bury the real
// cause under a later "too many requests".
func (e *HTTPError) Permanent() bool {
	return e.Status >= 400 && e.Status < 500 && e.Status != http.StatusTooManyRequests
}

// Message returns the server's human-readable explanation: the "message" field
// of a JSON error body, or the trimmed raw body when it is not JSON.
func (e *HTTPError) Message() string {
	var payload struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal([]byte(e.Body), &payload); err == nil && payload.Message != "" {
		return payload.Message
	}
	return strings.TrimSpace(e.Body)
}

// FieldErrors returns the per-field validation messages of a Laravel 422 body,
// flattened to "field: message" lines and sorted so output is deterministic.
// Returns nil when the body carries no "errors" object.
func (e *HTTPError) FieldErrors() []string {
	var payload struct {
		Errors map[string][]string `json:"errors"`
	}
	if err := json.Unmarshal([]byte(e.Body), &payload); err != nil || len(payload.Errors) == 0 {
		return nil
	}

	var lines []string
	for field, msgs := range payload.Errors {
		for _, msg := range msgs {
			lines = append(lines, field+": "+msg)
		}
	}
	sort.Strings(lines)
	return lines
}

// parseRetryAfter reads a Retry-After header in either of its two legal forms:
// a delay in seconds, or an HTTP date. Returns 0 when absent or unparseable.
// now is injected so the date form is testable.
func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}

	if secs, err := strconv.Atoi(value); err == nil {
		if secs <= 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}

	if when, err := http.ParseTime(value); err == nil {
		if d := when.Sub(now); d > 0 {
			return d
		}
	}

	return 0
}
