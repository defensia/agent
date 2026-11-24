// Package csfsotwire defines the JSON wire types shared between the
// agent's internal/firewall package (which observes and diffs the
// managed CSF scope) and internal/api (which marshals heartbeat/sync
// payloads). It is a leaf package (stdlib only) so neither of those two
// packages needs to import the other.
package csfsotwire

import (
	"encoding/json"
	"time"
)

// Entry is one tagged csf.allow/csf.deny line in the managed scope:
// Value is the IP or CIDR, Comment is the ownership reason (with any
// CSF-appended date suffix already stripped).
type Entry struct {
	Value   string `json:"value"`
	Comment string `json:"comment,omitempty"`
}

// Problem is a read-only precheck finding (duplicate key, unparseable
// value, csf.disable present) that keeps a key or the whole feature out
// of scope without ever writing anything.
type Problem struct {
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

// Managed is the managed CSF scope: the in-scope port list keys (raw
// values) and the tagged allow/deny entries. Ports/Allow/Deny always
// marshal to {}/[]/[] rather than null, even when empty, so the panel
// never has to special-case a missing container.
type Managed struct {
	Ports map[string]string `json:"ports"`
	Allow []Entry           `json:"allow"`
	Deny  []Entry           `json:"deny"`
}

// MarshalJSON normalises nil Ports/Allow/Deny to empty (non-null)
// containers before delegating to the default struct marshaling.
func (m Managed) MarshalJSON() ([]byte, error) {
	type alias Managed

	out := alias(m)
	if out.Ports == nil {
		out.Ports = map[string]string{}
	}
	if out.Allow == nil {
		out.Allow = []Entry{}
	}
	if out.Deny == nil {
		out.Deny = []Entry{}
	}

	return json.Marshal(out)
}

// DriftItem is one difference between desired and observed state: a port
// key's added/removed tokens, or a list entry that appeared/disappeared.
type DriftItem struct {
	Kind      string    `json:"kind"`
	Key       string    `json:"key,omitempty"`
	Value     string    `json:"value,omitempty"`
	Change    string    `json:"change,omitempty"`
	Added     []string  `json:"added,omitempty"`
	Removed   []string  `json:"removed,omitempty"`
	FirstSeen time.Time `json:"first_seen,omitempty"`
	Hint      string    `json:"hint,omitempty"`
}

// Refusal is a logged, audited guard refusal: why a desired change (or a
// revert) was not applied.
type Refusal struct {
	Reason     string    `json:"reason"`
	Detail     string    `json:"detail,omitempty"`
	At         time.Time `json:"at,omitempty"`
	Generation uint64    `json:"generation,omitempty"`
}

// Config is the config.csf_sot block of every sync (CONTRACT §1): what
// the panel wants the agent to do right now. Mode "csf" (or the type's
// zero value / a nil *Config at the call site) means "do nothing, this
// server is not source-of-truth managed".
type Config struct {
	Mode              string   `json:"mode"`
	Correction        string   `json:"correction,omitempty"`
	Generation        uint64   `json:"generation,omitempty"`
	SnapshotRequested bool     `json:"snapshot_requested,omitempty"`
	Desired           *Managed `json:"desired,omitempty"`
	RevertToken       *string  `json:"revert_token,omitempty"`
	ResumeToken       *string  `json:"resume_token,omitempty"`
	RetryToken        *string  `json:"retry_token,omitempty"`
}

// TokensAcked echoes back, in the heartbeat, exactly which pending
// token(s) the agent has now acted on (CONTRACT §2).
type TokensAcked struct {
	Revert *string `json:"revert,omitempty"`
	Resume *string `json:"resume,omitempty"`
	Retry  *string `json:"retry,omitempty"`
}

// RetryInfo tracks intentional-change retry state (CONTRACT §2/§7).
type RetryInfo struct {
	Count  int        `json:"count"`
	NextAt *time.Time `json:"next_at,omitempty"`
}

// AutoInfo tracks the automatic-correction rate-limit window (CONTRACT
// §2/§7); filled in by 16.1-11.
type AutoInfo struct {
	FixesInWindow int        `json:"fixes_in_window"`
	NextAt        *time.Time `json:"next_at,omitempty"`
	HoldReason    *string    `json:"hold_reason,omitempty"`
}

// Report is the heartbeat's csf_sot block (CONTRACT §2): everything the
// panel needs to know about the agent's current reconcile state.
type Report struct {
	Active             bool        `json:"active"`
	Problems           []Problem   `json:"problems,omitempty"`
	GenerationSeen     uint64      `json:"generation_seen"`
	GenerationAcked    uint64      `json:"generation_acked"`
	Status             string      `json:"status,omitempty"`
	ObservedHash       string      `json:"observed_hash,omitempty"`
	DesiredHash        string      `json:"desired_hash,omitempty"`
	TokensAcked        TokensAcked `json:"tokens_acked"`
	Drift              []DriftItem `json:"drift"`
	Observed           *Managed    `json:"observed,omitempty"`
	CSFConfMtime       *time.Time  `json:"csf_conf_mtime,omitempty"`
	IPv6               bool        `json:"ipv6,omitempty"`
	ManagedKeys        []string    `json:"managed_keys,omitempty"`
	TaggedEntriesCount int         `json:"tagged_entries_count,omitempty"`
	Retry              *RetryInfo  `json:"retry,omitempty"`
	Auto               *AutoInfo   `json:"auto,omitempty"`
	Refused            []Refusal   `json:"refused,omitempty"`
	Error              *Refusal    `json:"error,omitempty"`
	SSHPorts           []int       `json:"ssh_ports,omitempty"`
	TestingMode        bool        `json:"testing_mode,omitempty"`
}

// MarshalJSON normalises a nil Drift to an empty (non-null) array
// before delegating to the default struct marshaling.
func (r Report) MarshalJSON() ([]byte, error) {
	type alias Report

	out := alias(r)
	if out.Drift == nil {
		out.Drift = []DriftItem{}
	}

	return json.Marshal(out)
}

// SnapshotRequest is the body of POST /api/v1/agent/csf/sot/snapshot
// (CONTRACT §4): a read-only Observe result.
type SnapshotRequest struct {
	Observed     Managed   `json:"observed"`
	ObservedHash string    `json:"observed_hash"`
	IPv6         bool      `json:"ipv6"`
	ManagedKeys  []string  `json:"managed_keys"`
	SSHPorts     []int     `json:"ssh_ports"`
	Fork         string    `json:"fork,omitempty"`
	Version      string    `json:"version,omitempty"`
	Problems     []Problem `json:"problems"`
}

// MarshalJSON normalises nil ManagedKeys/SSHPorts/Problems to empty
// (non-null) arrays before delegating to the default struct marshaling
// -- the same fix Managed.MarshalJSON already applies above, for the
// same reason: the panel's validation rules for these three fields
// (`sometimes`, `array`, no `nullable`) reject an explicit JSON `null`
// outright with a 422, even though "nothing to report" is the normal,
// healthy case for every one of them (no precheck problems, IPv6 off
// with no v6 keys, ssh detection returning nothing). Confirmed live
// (phase 16.1, 2026-11-19): every real activation snapshot sent `null`
// for the typically-empty `problems` field and was rejected outright,
// so SOT-02 activation never completed on any real VM.
func (r SnapshotRequest) MarshalJSON() ([]byte, error) {
	type alias SnapshotRequest

	out := alias(r)
	if out.ManagedKeys == nil {
		out.ManagedKeys = []string{}
	}
	if out.SSHPorts == nil {
		out.SSHPorts = []int{}
	}
	if out.Problems == nil {
		out.Problems = []Problem{}
	}

	return json.Marshal(out)
}

// SnapshotResponse is the panel's reply to a snapshot POST.
type SnapshotResponse struct {
	Accepted   bool   `json:"accepted"`
	Generation uint64 `json:"generation,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// Hint is the heartbeat response's csf_sot trigger hint (CONTRACT §3):
// just the scalars the agent compares against its last-seen Config to
// decide whether to run a full sync right now.
type Hint struct {
	Mode              string  `json:"mode"`
	Correction        string  `json:"correction,omitempty"`
	Generation        uint64  `json:"generation,omitempty"`
	SnapshotRequested bool    `json:"snapshot_requested,omitempty"`
	RevertToken       *string `json:"revert_token,omitempty"`
	ResumeToken       *string `json:"resume_token,omitempty"`
	RetryToken        *string `json:"retry_token,omitempty"`
}

// Equal reports whether the hint matches what the agent already knows
// from c (its last-seen Config) -- false means "something changed, run a
// full sync now". A nil c (no config ever seen) is never equal.
func (h Hint) Equal(c *Config) bool {
	if c == nil {
		return false
	}

	return h.Mode == c.Mode &&
		h.Correction == c.Correction &&
		h.Generation == c.Generation &&
		h.SnapshotRequested == c.SnapshotRequested &&
		strPtrEqual(h.RevertToken, c.RevertToken) &&
		strPtrEqual(h.ResumeToken, c.ResumeToken) &&
		strPtrEqual(h.RetryToken, c.RetryToken)
}

func strPtrEqual(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}

	return *a == *b
}
