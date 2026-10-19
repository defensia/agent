package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPErrorPermanent(t *testing.T) {
	tests := []struct {
		status        int
		wantPermanent bool
	}{
		{status: 400, wantPermanent: true},
		{status: 401, wantPermanent: true},
		{status: 403, wantPermanent: true},
		{status: 404, wantPermanent: true},
		{status: 422, wantPermanent: true},
		// 429 is the one 4xx that time alone can clear.
		{status: 429, wantPermanent: false},
		{status: 500, wantPermanent: false},
		{status: 502, wantPermanent: false},
		{status: 503, wantPermanent: false},
	}

	for _, tc := range tests {
		err := &HTTPError{Status: tc.status}
		if got := err.Permanent(); got != tc.wantPermanent {
			t.Errorf("status %d: Permanent() = %v, want %v", tc.status, got, tc.wantPermanent)
		}
	}
}

func TestHTTPErrorMessage(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "laravel validation body",
			body: `{"message":"The os version field is required.","errors":{"os_version":["The os version field is required."]}}`,
			want: "The os version field is required.",
		},
		{
			name: "laravel multi-error body",
			body: `{"message":"The name field is required. (and 1 more error)","errors":{}}`,
			want: "The name field is required. (and 1 more error)",
		},
		{
			name: "plain text body",
			body: "  502 Bad Gateway\n",
			want: "502 Bad Gateway",
		},
		{
			name: "json without a message field",
			body: `{"error":"nope"}`,
			want: `{"error":"nope"}`,
		},
		{
			name: "empty body",
			body: "",
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := &HTTPError{Status: 422, Body: tc.body}
			if got := err.Message(); got != tc.want {
				t.Errorf("Message() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestHTTPErrorFieldErrors(t *testing.T) {
	// Two rejected fields, deliberately out of alphabetical order in the body,
	// to pin the sorted output.
	err := &HTTPError{
		Status: 422,
		Body:   `{"message":"x","errors":{"os_version":["The os version field is required."],"ip_address":["The ip address field must be a valid IP address."]}}`,
	}

	got := err.FieldErrors()
	want := []string{
		"ip_address: The ip address field must be a valid IP address.",
		"os_version: The os version field is required.",
	}

	if len(got) != len(want) {
		t.Fatalf("FieldErrors() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}

	if lines := (&HTTPError{Status: 429, Body: `{"message":"Too Many Requests"}`}).FieldErrors(); lines != nil {
		t.Errorf("a body with no errors object should yield nil, got %v", lines)
	}
	if lines := (&HTTPError{Status: 502, Body: "not json"}).FieldErrors(); lines != nil {
		t.Errorf("a non-JSON body should yield nil, got %v", lines)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name  string
		value string
		want  time.Duration
	}{
		{name: "delay in seconds", value: "30", want: 30 * time.Second},
		{name: "the panel's hour-long limit", value: "3600", want: time.Hour},
		{name: "surrounding whitespace", value: " 15 ", want: 15 * time.Second},
		{name: "http date in the future", value: "Mon, 19 Oct 2026 12:05:00 GMT", want: 5 * time.Minute},
		{name: "http date in the past", value: "Mon, 19 Oct 2026 11:00:00 GMT", want: 0},
		{name: "absent", value: "", want: 0},
		{name: "zero seconds", value: "0", want: 0},
		{name: "negative seconds", value: "-5", want: 0},
		{name: "unparseable", value: "soon", want: 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseRetryAfter(tc.value, now); got != tc.want {
				t.Errorf("parseRetryAfter(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

// post must surface the status, the body and Retry-After as a typed error, so
// callers can classify the response instead of matching on a string.
func TestPostReturnsTypedHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "17")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"message":"Too Many Requests"}`))
	}))
	defer srv.Close()

	client := New(srv.URL, "")
	_, err := client.Register(RegisterRequest{})
	if err == nil {
		t.Fatal("expected an error from a 429 response")
	}

	httpErr, ok := err.(*HTTPError)
	if !ok {
		t.Fatalf("error is %T, want *HTTPError", err)
	}
	if httpErr.Status != http.StatusTooManyRequests {
		t.Errorf("Status = %d, want 429", httpErr.Status)
	}
	if httpErr.RetryAfter != 17*time.Second {
		t.Errorf("RetryAfter = %v, want 17s", httpErr.RetryAfter)
	}
	if got := httpErr.Message(); got != "Too Many Requests" {
		t.Errorf("Message() = %q, want %q", got, "Too Many Requests")
	}
	if httpErr.Permanent() {
		t.Error("a 429 must not be classified as permanent")
	}
}

// A 422 from the real endpoint shape must come back permanent and legible.
func TestPostReturnsPermanentErrorOnValidationFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"The os version field is required.","errors":{"os_version":["The os version field is required."]}}`))
	}))
	defer srv.Close()

	client := New(srv.URL, "")
	_, err := client.Register(RegisterRequest{})

	httpErr, ok := err.(*HTTPError)
	if !ok {
		t.Fatalf("error is %T, want *HTTPError", err)
	}
	if !httpErr.Permanent() {
		t.Error("a 422 must be permanent — retrying it burns the hourly budget")
	}
	if httpErr.RetryAfter != 0 {
		t.Errorf("RetryAfter = %v, want 0 when no header is sent", httpErr.RetryAfter)
	}
	if len(httpErr.FieldErrors()) != 1 {
		t.Errorf("FieldErrors() = %v, want one line", httpErr.FieldErrors())
	}
}
