package api

import (
	"encoding/json"
	"errors"
)

// CSFHeartbeatFields is embedded as an anonymous pointer in HeartbeatRequest:
// nil means "nothing to report" and encoding/json drops every field below
// entirely (no key starting with csf_ appears at all — COL-06). A non-nil
// pointer always reports CSFInstalled, and every other field is a pointer or
// a slice with NO omitempty: false/0/empty-slice are real, meaningful values
// (e.g. "CSF has zero denied IPs right now") and must round-trip, while a nil
// pointer round-trips as explicit JSON null ("we never collected this fact").
// Collapsing either case into omission (the classic `omitempty` trap on a
// bool/int field) is exactly how "no CSF" silently becomes "CSF fine" on the
// dashboard — see 15-RESEARCH.md's "What goes wrong" note.
type CSFHeartbeatFields struct {
	CSFInstalled       bool     `json:"csf_installed"`
	CSFVersion         *string  `json:"csf_version"`
	CSFPortsIn         *string  `json:"csf_ports_in"`
	CSFPortsOut        *string  `json:"csf_ports_out"`
	CSFDenyCount       *int     `json:"csf_deny_count"`
	CSFAllowCount      *int     `json:"csf_allow_count"`
	CSFFork            *string  `json:"csf_fork"`
	CSFForkEvidence    []string `json:"csf_fork_evidence"`
	CSFTesting         *bool    `json:"csf_testing"`
	CSFAutoUpdates     *bool    `json:"csf_auto_updates"`
	CSFAutoUpdatesCron *bool    `json:"csf_auto_updates_cron"`
	CSFLFDaemon        *bool    `json:"csf_lf_daemon"`
	CSFLFDRunning      *bool    `json:"csf_lfd_running"`
	CSFIPv6            *bool    `json:"csf_ipv6"`
	CSFDownloadServers []string `json:"csf_download_servers"`
	CSFDenyIPLimit     *int     `json:"csf_deny_ip_limit"`
	CSFDenyTempIPLimit *int     `json:"csf_deny_temp_ip_limit"`
	CSFListsHash       *string  `json:"csf_lists_hash"`
	CSFListsTruncated  *bool    `json:"csf_lists_truncated"`
}

// CSFListsRequest is the body of POST /api/v1/agent/csf/lists (plan 15-10).
// Sent only when Hash changes from the last successful upload (hash-gated on
// the panel side too, so a repeat upload short-circuits to a no-op).
type CSFListsRequest struct {
	Hash        string         `json:"hash"`
	CollectedAt string         `json:"collected_at"`
	Deny        CSFListPayload `json:"deny"`
	Allow       CSFListPayload `json:"allow"`
}

// CSFListPayload mirrors internal/firewall.CSFList's shape across the wire.
type CSFListPayload struct {
	Total     int                   `json:"total"`
	Truncated bool                  `json:"truncated"`
	Entries   []CSFListEntryPayload `json:"entries"`
}

// CSFListEntryPayload mirrors internal/firewall.CSFListEntry across the wire.
type CSFListEntryPayload struct {
	Value   string `json:"value"`
	Kind    string `json:"kind"`
	Comment string `json:"comment,omitempty"`
}

// Caps mirror the panel's POST /api/v1/agent/csf/lists limits exactly (plan
// 15-10, verified merge-ready): 1000 entries per list, 1 MiB request body.
// Checking here means an oversized or malformed snapshot is rejected locally
// with a plain Go error instead of burning the endpoint's 4/min throttle
// budget on a request the panel would 422/413 anyway.
const (
	csfListsMaxEntries   = 1000
	csfListsMaxBodyBytes = 1 << 20 // 1 MiB
)

// ErrCSFListsTooLarge is returned by UploadCSFLists when req exceeds the
// panel's caps (entries per list, or total marshalled body size) without
// making any HTTP request.
var ErrCSFListsTooLarge = errors.New("csf lists payload exceeds panel caps (1000 entries/list, 1 MiB body)")

// UploadCSFLists POSTs the agent's classified deny/allow CSF lists to the
// panel. Returns ErrCSFListsTooLarge (no request sent) if req exceeds the
// panel's own caps, or the *HTTPError the panel/old-panel returned otherwise
// — notably Status 404 (or 405) for a panel that predates this route, and
// Status 429 for throttle exhaustion. Classifying those is the runtime's job:
// see csfListsBackoffFor in cmd/defensia-agent/csf_runtime.go.
func (c *Client) UploadCSFLists(req CSFListsRequest) error {
	if len(req.Deny.Entries) > csfListsMaxEntries || len(req.Allow.Entries) > csfListsMaxEntries {
		return ErrCSFListsTooLarge
	}

	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if len(data) > csfListsMaxBodyBytes {
		return ErrCSFListsTooLarge
	}

	return c.post("/api/v1/agent/csf/lists", c.token, req, nil)
}
