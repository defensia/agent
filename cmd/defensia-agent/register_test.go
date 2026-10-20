package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/defensia/agent/internal/api"
)

// requiredFields are the seven values the panel validates as `required`. None
// may ever leave the agent empty: an empty one is a 422 that costs an attempt
// against a budget of five per hour.
func requiredFields(req api.RegisterRequest) map[string]string {
	return map[string]string{
		"install_token": req.InstallToken,
		"name":          req.Name,
		"hostname":      req.Hostname,
		"ip_address":    req.IPAddress,
		"os":            req.OS,
		"os_version":    req.OSVersion,
		"version":       req.Version,
	}
}

func TestBuildRegisterRequestNeverLeavesARequiredFieldEmpty(t *testing.T) {
	token := strings.Repeat("a", installTokenLength)

	tests := []struct {
		name         string
		agentName    string
		hostname     string
		osi          osInfo
		ip           string
		agentVersion string
		want         map[string]string // only the fields worth asserting exactly
	}{
		{
			name:         "everything detected",
			agentName:    "web-01",
			hostname:     "web-01.example.com",
			osi:          osInfo{name: "ubuntu", version: "24.04"},
			ip:           "203.0.113.10",
			agentVersion: "1.4.78",
			want: map[string]string{
				"name": "web-01", "hostname": "web-01.example.com",
				"os": "ubuntu", "os_version": "24.04", "ip_address": "203.0.113.10",
			},
		},
		{
			// The incident's latent bug: ID present, VERSION_ID absent.
			name:         "os-release with ID and no VERSION_ID",
			agentName:    "arch-box",
			hostname:     "arch-box",
			osi:          osInfo{name: "arch", version: ""},
			ip:           "203.0.113.11",
			agentVersion: "1.4.78",
			want:         map[string]string{"os": "arch", "os_version": "unknown"},
		},
		{
			name:         "no hostname falls back to the agent name",
			agentName:    "vultr-node",
			hostname:     "",
			osi:          osInfo{name: "debian", version: "12"},
			ip:           "203.0.113.12",
			agentVersion: "1.4.78",
			want:         map[string]string{"name": "vultr-node", "hostname": "vultr-node"},
		},
		{
			name:         "no agent name falls back to the hostname",
			agentName:    "",
			hostname:     "db-02",
			osi:          osInfo{name: "rocky", version: "9"},
			ip:           "203.0.113.13",
			agentVersion: "1.4.78",
			want:         map[string]string{"name": "db-02", "hostname": "db-02"},
		},
		{
			name:         "undetectable IP becomes a valid placeholder",
			agentName:    "ip-less",
			hostname:     "ip-less",
			osi:          osInfo{name: "alpine", version: "3.20"},
			ip:           "",
			agentVersion: "1.4.78",
			want:         map[string]string{"ip_address": "0.0.0.0"},
		},
		{
			name:         "garbage IP is not forwarded to the panel",
			agentName:    "bad-ip",
			hostname:     "bad-ip",
			osi:          osInfo{name: "alpine", version: "3.20"},
			ip:           "not-an-ip",
			agentVersion: "1.4.78",
			want:         map[string]string{"ip_address": "0.0.0.0"},
		},
		{
			name:         "IPv6 address is preserved",
			agentName:    "v6",
			hostname:     "v6",
			osi:          osInfo{name: "debian", version: "12"},
			ip:           "2001:db8::1",
			agentVersion: "1.4.78",
			want:         map[string]string{"ip_address": "2001:db8::1"},
		},
		{
			name:         "nothing detected at all",
			agentName:    "",
			hostname:     "",
			osi:          osInfo{},
			ip:           "",
			agentVersion: "",
			want: map[string]string{
				"name": "unknown-host", "hostname": "unknown-host",
				"os": "linux", "os_version": "unknown",
				"ip_address": "0.0.0.0", "version": "unknown",
			},
		},
		{
			name:         "whitespace-only detection counts as empty",
			agentName:    "  ",
			hostname:     "\t",
			osi:          osInfo{name: " ", version: "  "},
			ip:           " ",
			agentVersion: " ",
			want: map[string]string{
				"name": "unknown-host", "os": "linux",
				"os_version": "unknown", "version": "unknown",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := buildRegisterRequest(tc.agentName, tc.hostname, token, tc.osi, tc.ip, tc.agentVersion)

			for field, value := range requiredFields(req) {
				if value == "" {
					t.Errorf("required field %q is empty — the panel answers this with a 422", field)
				}
			}

			for field, want := range tc.want {
				if got := requiredFields(req)[field]; got != want {
					t.Errorf("%s = %q, want %q", field, got, want)
				}
			}
		})
	}
}

func TestValidateInstallToken(t *testing.T) {
	valid := strings.Repeat("x", installTokenLength)

	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "exact length", raw: valid, want: valid},
		{name: "trailing newline from a copy-paste", raw: valid + "\n", want: valid},
		{name: "surrounding whitespace", raw: "  " + valid + "  ", want: valid},
		{name: "empty", raw: "", wantErr: true},
		{name: "whitespace only", raw: "   ", wantErr: true},
		{name: "truncated", raw: strings.Repeat("x", 63), wantErr: true},
		{name: "too long", raw: strings.Repeat("x", 65), wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateInstallToken(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %q, got token %q", tc.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("token = %q, want %q", got, tc.want)
			}
		})
	}
}

// fakeRegistrar records every attempt and replays a scripted sequence.
type fakeRegistrar struct {
	responses []error // one per attempt; nil means success
	calls     int
}

func (f *fakeRegistrar) Register(req api.RegisterRequest) (*api.RegisterResponse, error) {
	f.calls++
	if f.calls <= len(f.responses) {
		if err := f.responses[f.calls-1]; err != nil {
			return nil, err
		}
	}
	return &api.RegisterResponse{}, nil
}

func httpErr(status int, body string, retryAfter time.Duration) *api.HTTPError {
	return &api.HTTPError{Status: status, Body: body, RetryAfter: retryAfter}
}

const validationBody = `{"message":"The os version field is required.","errors":{"os_version":["The os version field is required."]}}`

func TestRegisterRetryPolicy(t *testing.T) {
	tests := []struct {
		name       string
		responses  []error
		wantCalls  int
		wantSleeps []time.Duration
		wantErr    bool
	}{
		{
			name:      "success on the first attempt",
			responses: []error{nil},
			wantCalls: 1,
		},
		{
			// The core of the incident: a 422 is permanent, so retrying it only
			// spends the hourly budget and buries the cause under a 429.
			name:      "422 is not retried",
			responses: []error{httpErr(422, validationBody, 0)},
			wantCalls: 1,
			wantErr:   true,
		},
		{
			name:      "401 invalid token is not retried",
			responses: []error{httpErr(401, `{"message":"Invalid or expired install token."}`, 0)},
			wantCalls: 1,
			wantErr:   true,
		},
		{
			name:      "403 server limit is not retried",
			responses: []error{httpErr(403, `{"message":"Server limit reached."}`, 0)},
			wantCalls: 1,
			wantErr:   true,
		},
		{
			name:       "429 with a short Retry-After is retried after exactly that long",
			responses:  []error{httpErr(429, `{"message":"Too Many Requests"}`, 3*time.Second), nil},
			wantCalls:  2,
			wantSleeps: []time.Duration{3 * time.Second},
		},
		{
			name:       "429 with no Retry-After uses the default wait",
			responses:  []error{httpErr(429, `{"message":"Too Many Requests"}`, 0), nil},
			wantCalls:  2,
			wantSleeps: []time.Duration{registerRetryWait},
		},
		{
			// The panel's limiter can ask for an hour. Waiting that long inside
			// an installer is indistinguishable from a hang.
			name:      "429 with an hour-long Retry-After fails fast",
			responses: []error{httpErr(429, `{"message":"Too Many Requests"}`, time.Hour)},
			wantCalls: 1,
			wantErr:   true,
		},
		{
			name:       "5xx is retried with backoff",
			responses:  []error{httpErr(502, "bad gateway", 0), httpErr(502, "bad gateway", 0), nil},
			wantCalls:  3,
			wantSleeps: []time.Duration{2 * time.Second, 4 * time.Second},
		},
		{
			name:       "transport errors are retried",
			responses:  []error{errors.New("dial tcp: connection refused"), nil},
			wantCalls:  2,
			wantSleeps: []time.Duration{2 * time.Second},
		},
		{
			// One install run must never spend the five attempts the panel
			// allows per hour, or retrying can never succeed.
			name: "a run never exceeds the attempt cap",
			responses: []error{
				httpErr(502, "x", 0), httpErr(502, "x", 0), httpErr(502, "x", 0),
				httpErr(502, "x", 0), httpErr(502, "x", 0),
			},
			wantCalls:  registerMaxAttempts,
			wantSleeps: []time.Duration{2 * time.Second, 4 * time.Second},
			wantErr:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := &fakeRegistrar{responses: tc.responses}
			var sleeps []time.Duration

			_, err := registerWithRetry(client, api.RegisterRequest{}, func(d time.Duration) {
				sleeps = append(sleeps, d)
			})

			if tc.wantErr && err == nil {
				t.Fatal("expected registration to fail")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if client.calls != tc.wantCalls {
				t.Errorf("made %d requests, want %d", client.calls, tc.wantCalls)
			}
			if client.calls > registerMaxAttempts {
				t.Errorf("made %d requests, over the cap of %d", client.calls, registerMaxAttempts)
			}
			if len(sleeps) != len(tc.wantSleeps) {
				t.Fatalf("slept %v, want %v", sleeps, tc.wantSleeps)
			}
			for i, want := range tc.wantSleeps {
				if sleeps[i] != want {
					t.Errorf("sleep %d = %v, want %v", i, sleeps[i], want)
				}
			}
		})
	}
}

func TestReportRegistrationFailureShowsTheServersMessage(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantAll  []string
		wantNone []string
	}{
		{
			name: "422 names the rejected field",
			err:  httpErr(422, validationBody, 0),
			wantAll: []string{
				"HTTP 422",
				"The os version field is required.",
				"os_version",
				"tickets/create",
			},
		},
		{
			name: "422 on a mis-sized install token is readable",
			err:  httpErr(422, `{"message":"The install token field must be 64 characters.","errors":{"install_token":["The install token field must be 64 characters."]}}`, 0),
			wantAll: []string{
				"HTTP 422",
				"The install token field must be 64 characters.",
				"install_token",
			},
		},
		{
			name: "401 points at a fresh token",
			err:  httpErr(401, `{"message":"Invalid or expired install token.","reason":"token_not_found"}`, 0),
			wantAll: []string{
				"HTTP 401",
				"Invalid or expired install token.",
				"account/agents",
			},
		},
		{
			name:    "403 points at billing",
			err:     httpErr(403, `{"message":"Server limit reached. Add more servers from the Billing page."}`, 0),
			wantAll: []string{"HTTP 403", "Server limit reached.", "Billing"},
		},
		{
			// The 429 must not be allowed to read as the root cause.
			name:    "429 says the earlier failure is the real one",
			err:     httpErr(429, `{"message":"Too Many Requests"}`, 42*time.Minute),
			wantAll: []string{"HTTP 429", "42m", "failed for a different reason"},
		},
		{
			name:     "transport failure explains itself without a status",
			err:      errors.New("dial tcp 1.2.3.4:443: i/o timeout"),
			wantAll:  []string{"could not reach the Defensia API", "i/o timeout", "outbound HTTPS"},
			wantNone: []string{"HTTP "},
		},
		{
			name:    "a non-JSON body is still shown",
			err:     httpErr(502, "<html>502 Bad Gateway</html>", 0),
			wantAll: []string{"HTTP 502", "502 Bad Gateway"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			reportRegistrationFailure(&buf, tc.err)
			out := buf.String()

			for _, want := range tc.wantAll {
				if !strings.Contains(out, want) {
					t.Errorf("output is missing %q\n--- output ---\n%s", want, out)
				}
			}
			for _, unwanted := range tc.wantNone {
				if strings.Contains(out, unwanted) {
					t.Errorf("output should not contain %q\n--- output ---\n%s", unwanted, out)
				}
			}
		})
	}
}

// The error must survive wrapping, since registerWithRetry returns it through
// several layers before reportRegistrationFailure classifies it.
func TestHTTPErrorSurvivesWrapping(t *testing.T) {
	wrapped := fmt.Errorf("registering agent: %w", httpErr(422, validationBody, 0))

	var httpError *api.HTTPError
	if !errors.As(wrapped, &httpError) {
		t.Fatal("a wrapped *api.HTTPError should still be recoverable with errors.As")
	}
	if httpError.Status != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want 422", httpError.Status)
	}
	if !httpError.Permanent() {
		t.Error("422 must be classified as permanent")
	}
}

// TestParseOSRelease covers the distros whose os-release shape produced the
// empty os_version that the panel rejects with a 422.
func TestParseOSRelease(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantName    string
		wantVersion string
	}{
		{
			name:        "ubuntu has both fields",
			content:     "NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n",
			wantName:    "ubuntu",
			wantVersion: "24.04",
		},
		{
			// Arch ships ID with no VERSION_ID at all. This is the shape that
			// used to send os_version:"" and get a 422.
			name:        "arch has ID and no VERSION_ID",
			content:     "NAME=\"Arch Linux\"\nID=arch\nPRETTY_NAME=\"Arch Linux\"\nBUILD_ID=rolling\n",
			wantName:    "arch",
			wantVersion: "unknown",
		},
		{
			name:        "gentoo has ID and no VERSION_ID",
			content:     "NAME=Gentoo\nID=gentoo\nPRETTY_NAME=\"Gentoo Linux\"\n",
			wantName:    "gentoo",
			wantVersion: "unknown",
		},
		{
			name:        "empty VERSION_ID value",
			content:     "ID=debian\nVERSION_ID=\n",
			wantName:    "debian",
			wantVersion: "unknown",
		},
		{
			name:        "quoted empty VERSION_ID value",
			content:     "ID=debian\nVERSION_ID=\"\"\n",
			wantName:    "debian",
			wantVersion: "unknown",
		},
		{
			name:        "VERSION_ID with no ID",
			content:     "VERSION_ID=\"9\"\n",
			wantName:    "linux",
			wantVersion: "9",
		},
		{
			name:        "a file with neither field",
			content:     "PRETTY_NAME=\"Some Linux\"\n",
			wantName:    "linux",
			wantVersion: "unknown",
		},
		{
			name:        "an empty file",
			content:     "",
			wantName:    "linux",
			wantVersion: "unknown",
		},
		{
			name:        "no trailing newline on the last line",
			content:     "ID=alpine\nVERSION_ID=3.20.3",
			wantName:    "alpine",
			wantVersion: "3.20.3",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseOSRelease(tc.content)

			if got.version == "" {
				t.Error("version is empty — the panel rejects an empty os_version with a 422")
			}
			if got.name != tc.wantName {
				t.Errorf("name = %q, want %q", got.name, tc.wantName)
			}
			if got.version != tc.wantVersion {
				t.Errorf("version = %q, want %q", got.version, tc.wantVersion)
			}
		})
	}
}

// detectOutboundIP must never hand buildRegisterRequest something the panel's
// `ip` rule would reject, whatever the host's networking looks like.
func TestDetectOutboundIPIsAlwaysAValidIP(t *testing.T) {
	t.Setenv("AGENT_IP", "")
	if ip := detectOutboundIP(); net.ParseIP(ip) == nil {
		t.Errorf("detectOutboundIP() = %q, which is not a valid IP address", ip)
	}
}

func TestDetectOutboundIPHonoursAndValidatesTheOverride(t *testing.T) {
	t.Setenv("AGENT_IP", "198.51.100.7")
	if got := detectOutboundIP(); got != "198.51.100.7" {
		t.Errorf("a valid AGENT_IP should be used verbatim, got %q", got)
	}

	// An invalid override must be ignored rather than forwarded into a 422.
	t.Setenv("AGENT_IP", "my-server.example.com")
	got := detectOutboundIP()
	if got == "my-server.example.com" {
		t.Error("an invalid AGENT_IP must not be sent to the panel")
	}
	if net.ParseIP(got) == nil {
		t.Errorf("fallback after an invalid AGENT_IP is %q, not a valid IP", got)
	}
}

func TestRegisterExitCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"spent or expired token", &api.HTTPError{Status: 401, Body: `{"message":"token_expired"}`}, exitRegisterRejected},
		{"plan limit", &api.HTTPError{Status: 403}, exitRegisterRejected},
		{"unknown endpoint or token", &api.HTTPError{Status: 404}, exitRegisterRejected},
		{"validation", &api.HTTPError{Status: 422}, exitRegisterRejected},
		{"rate limited", &api.HTTPError{Status: 429, RetryAfter: time.Hour}, exitRegisterTransient},
		{"server error", &api.HTTPError{Status: 500}, exitRegisterTransient},
		{"bad gateway", &api.HTTPError{Status: 502}, exitRegisterTransient},
		{"wrapped rejection", fmt.Errorf("register: %w", &api.HTTPError{Status: 401}), exitRegisterRejected},
		{"transport", &net.OpError{Op: "dial", Err: errors.New("connection refused")}, exitRegisterTransient},
		{"plain error", errors.New("boom"), exitRegisterTransient},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := registerExitCode(tt.err); got != tt.want {
				t.Fatalf("registerExitCode(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}

	if exitRegisterRejected != 78 {
		t.Fatalf("exitRegisterRejected = %d; docker-entrypoint.sh depends on 78", exitRegisterRejected)
	}
}
