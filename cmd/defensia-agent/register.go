package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/defensia/agent/internal/api"
	"github.com/defensia/agent/internal/config"
)

// The panel validates all seven registration fields as required, and allows
// five registration attempts per hour per source IP. Both facts drive the
// constants below: an empty field costs an attempt and returns a 422 the
// operator cannot act on, so the agent must never send one, and a single
// install run must never spend the whole hourly budget.
const (
	// installTokenLength is the panel's `size:64` rule on install_token.
	installTokenLength = 64

	// registerMaxAttempts caps one install run at three of the five attempts
	// the panel allows per hour, so a failed run always leaves the operator a
	// real retry instead of an hour of 429s.
	registerMaxAttempts = 3

	// registerRetryAfterCap is the longest Retry-After we are willing to wait
	// inside an installer. The panel's limiter returns up to an hour; blocking
	// on that looks like a hang, so past this we stop and say how long to wait.
	registerRetryAfterCap = 60 * time.Second

	// registerRetryWait is the delay used when a retryable response carries no
	// usable Retry-After.
	registerRetryWait = 5 * time.Second
)

// registrar is the slice of the API client registration needs, so the retry
// policy can be tested without an HTTP server.
type registrar interface {
	Register(req api.RegisterRequest) (*api.RegisterResponse, error)
}

// validateInstallToken normalises the token and rejects it locally when it
// cannot possibly satisfy the panel's `size:64` rule.
//
// This is the one required field with no honest fallback — it is a secret, and
// inventing a value would turn a clear "your token is truncated" into a vague
// "invalid token". Checking it here converts the most common registration
// failure into an immediate, actionable message that costs no rate budget.
// Shell pipelines mangle pasted tokens routinely: a trailing newline from a
// copy, a truncated paste, or quoting that drops a character.
func validateInstallToken(raw string) (string, error) {
	token := strings.TrimSpace(raw)

	if token == "" {
		return "", errors.New("install token is empty — pass it as the third argument to `register`, or via --token to the installer")
	}
	if len(token) != installTokenLength {
		return "", fmt.Errorf(
			"install token must be exactly %d characters but is %d — it looks truncated or mis-pasted; copy it again from https://defensia.cloud/account/agents",
			installTokenLength, len(token),
		)
	}

	return token, nil
}

// buildRegisterRequest assembles the registration payload, giving every
// required field a non-empty value. Detection can legitimately come up empty —
// a distro with no VERSION_ID, a host whose name is unset, an IP that no probe
// could determine — and the panel answers an empty field with a 422 that reads
// like a token problem. A defensible placeholder registers the server and
// leaves the field correctable later; an empty one blocks the install.
func buildRegisterRequest(name, hostname, token string, osi osInfo, ip, agentVersion string) api.RegisterRequest {
	name = strings.TrimSpace(name)
	hostname = strings.TrimSpace(hostname)

	// hostname: os.Hostname() returns "" on error, and containers are often
	// started with none. The operator-chosen agent name is the better of the
	// two identifiers, so prefer it over any placeholder.
	if hostname == "" {
		hostname = name
	}
	if hostname == "" {
		hostname = "unknown-host"
	}

	// name: supplied by the installer, which already refuses an empty one, but
	// `defensia-agent register` can be run by hand. Mirror the hostname rather
	// than invent a label the operator would not recognise in the panel.
	if name == "" {
		name = hostname
	}

	osName := strings.TrimSpace(osi.name)
	if osName == "" {
		osName = "linux"
	}

	// os_version: the field that locked this out. A distro whose /etc/os-release
	// carries ID but no VERSION_ID — Arch, Gentoo, rolling and minimal images —
	// leaves this empty. "unknown" is what the no-os-release path already sends,
	// so this is existing behaviour applied consistently, not new policy.
	osVersion := strings.TrimSpace(osi.version)
	if osVersion == "" {
		osVersion = "unknown"
	}

	// version: compiled in via -X main.version, so only empty if someone builds
	// without ldflags. Guard anyway — a build slip should not block an install.
	agentVersion = strings.TrimSpace(agentVersion)
	if agentVersion == "" {
		agentVersion = "unknown"
	}

	return api.RegisterRequest{
		InstallToken: token,
		Name:         name,
		Hostname:     hostname,
		IPAddress:    normalizeIP(ip),
		OS:           osName,
		OSVersion:    osVersion,
		Version:      agentVersion,
	}
}

// normalizeIP guarantees the payload carries something the panel's `ip` rule
// accepts.
//
// 0.0.0.0 is a placeholder, not the host's address, and it does land in the
// agent record — so this is the one fallback that stores a value which is not
// true. It is kept deliberately: the panel also records the request's source IP
// (`installer_ip`) independently, so the real address is not lost, and the
// alternative is a 422 that stops the install outright. detectOutboundIP tries
// hard enough that reaching this is rare, and the operator can correct the
// address in the panel. Blocking a working install over a cosmetic field would
// be the worse trade.
func normalizeIP(ip string) string {
	if parsed := net.ParseIP(strings.TrimSpace(ip)); parsed != nil {
		return parsed.String()
	}
	return "0.0.0.0"
}

// registerWithRetry applies the retry policy for registration.
//
// The rules that matter, in order:
//   - A 4xx other than 429 is permanent. The same payload will be rejected
//     forever, so retrying only spends the hourly budget and replaces the real
//     error with a 429 the operator cannot diagnose.
//   - A 429 is retried only when Retry-After says the wait is short. The panel
//     can ask for an hour; waiting that long inside an installer is
//     indistinguishable from a hang.
//   - Transport errors and 5xx are retried with backoff, but the total is
//     capped so one run cannot exhaust the budget.
func registerWithRetry(client registrar, req api.RegisterRequest, sleep func(time.Duration)) (*api.RegisterResponse, error) {
	var lastErr error

	for attempt := 1; attempt <= registerMaxAttempts; attempt++ {
		resp, err := client.Register(req)
		if err == nil {
			return resp, nil
		}
		lastErr = err

		wait, retryable := registerRetryDelay(err, attempt)
		if !retryable {
			return nil, err
		}

		sleep(wait)
	}

	return nil, lastErr
}

// registerRetryDelay decides whether err is worth another attempt and how long
// to wait first. attempt is the 1-based number of the attempt that just failed.
func registerRetryDelay(err error, attempt int) (time.Duration, bool) {
	if attempt >= registerMaxAttempts {
		return 0, false
	}

	var httpErr *api.HTTPError
	if !errors.As(err, &httpErr) {
		// No response at all: DNS failure, refused connection, timeout. Worth
		// another try — though a timeout may still have been counted by the
		// limiter, which is why the attempt cap exists.
		return backoffFor(attempt), true
	}

	if httpErr.Permanent() {
		return 0, false
	}

	if httpErr.Status == 429 {
		wait := httpErr.RetryAfter
		if wait <= 0 {
			wait = registerRetryWait
		}
		if wait > registerRetryAfterCap {
			return 0, false
		}
		return wait, true
	}

	// 5xx and anything else unexpected.
	return backoffFor(attempt), true
}

// backoffFor returns the delay after a given attempt: 2s, then 4s.
func backoffFor(attempt int) time.Duration {
	return time.Duration(1<<uint(attempt)) * time.Second
}

// reportRegistrationFailure prints what the server rejected and what to do
// about it.
//
// This replaces log.Fatalf("Registration failed: %v", err), which did carry the
// response body but flattened it into one line ending in raw JSON — so the
// operator saw a wall of escaped quotes rather than "os_version is required",
// and in this incident concluded the install token was at fault.
func reportRegistrationFailure(w io.Writer, err error) {
	var httpErr *api.HTTPError
	if !errors.As(err, &httpErr) {
		fmt.Fprintf(w, "Registration failed: could not reach the Defensia API.\n")
		fmt.Fprintf(w, "  Error: %v\n", err)
		fmt.Fprintf(w, "  Check the server URL and that outbound HTTPS is allowed, then run register again.\n")
		return
	}

	fmt.Fprintf(w, "Registration failed: the Defensia API returned HTTP %d.\n", httpErr.Status)

	if msg := httpErr.Message(); msg != "" {
		fmt.Fprintf(w, "  Server said: %s\n", msg)
	}

	for _, line := range httpErr.FieldErrors() {
		fmt.Fprintf(w, "  Rejected field — %s\n", line)
	}

	if hint := registrationHint(httpErr); hint != "" {
		fmt.Fprintf(w, "  %s\n", hint)
	}
}

// registrationHint maps a status onto the action that resolves it.
func registrationHint(httpErr *api.HTTPError) string {
	switch httpErr.Status {
	case 401:
		return "Generate a fresh install token at https://defensia.cloud/account/agents and run the installer again."
	case 403:
		return "Your plan's server limit is reached. Add servers from the Billing page, then register again."
	case 422:
		return "The agent sent a value the panel rejected — see the field above. This is a bug in the agent unless the install token is wrong; please report it at https://defensia.cloud/tickets/create with these lines."
	case 429:
		retry := httpErr.RetryAfter
		if retry <= 0 {
			return "Too many registration attempts from this IP. Wait an hour and run the installer again — and note that the attempts before this one failed for a different reason."
		}
		return fmt.Sprintf(
			"Too many registration attempts from this IP. Wait %s and run the installer again — the attempts before this one failed for a different reason, which is the one to fix.",
			retry.Round(time.Second),
		)
	default:
		if httpErr.Status >= 500 {
			return "The Defensia API is having trouble. Wait a few minutes and run the installer again."
		}
		return ""
	}
}

// runRegister performs first-boot registration and saves the config.
func runRegister(serverURL, name, installToken string) {
	token, err := validateInstallToken(installToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Registration failed: %v\n", err)
		os.Exit(1)
	}

	hostname, hostErr := os.Hostname()
	if hostErr != nil {
		// Not fatal: buildRegisterRequest falls back to the agent name. Say so,
		// because an unset hostname is worth knowing about.
		fmt.Fprintf(os.Stderr, "Warning: could not read the system hostname (%v) — using the agent name instead.\n", hostErr)
	}

	req := buildRegisterRequest(name, hostname, token, detectOS(), detectOutboundIP(), version)

	if req.IPAddress == "0.0.0.0" {
		fmt.Fprintf(os.Stderr, "Warning: could not determine this host's outbound IP — registering with a placeholder. Set AGENT_IP to the correct address and re-register, or correct it in the panel.\n")
	}

	client := api.New(serverURL, "")

	fmt.Printf("Registering agent '%s' at %s...\n", req.Name, serverURL)

	resp, err := registerWithRetry(client, req, time.Sleep)
	if err != nil {
		reportRegistrationFailure(os.Stderr, err)
		os.Exit(1)
	}

	cfg := &config.Config{
		ServerURL:    serverURL,
		AgentToken:   resp.Token,
		AgentID:      resp.Agent.ID,
		ReverbURL:    resp.Reverb.URL,
		ReverbAppKey: resp.Reverb.AppKey,
		AuthEndpoint: resp.Reverb.AuthEndpoint,
	}

	if err := config.Save(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Registration succeeded but the config could not be saved: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Agent registered successfully (id=%d)\n", resp.Agent.ID)
	fmt.Printf("Config saved to %s\n", os.Getenv("DEFENSIA_CONFIG"))
	fmt.Println("Run 'defensia-agent start' to begin monitoring.")
}
