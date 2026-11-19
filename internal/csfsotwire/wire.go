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
