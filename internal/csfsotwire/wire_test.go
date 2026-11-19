package csfsotwire

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestManagedEmptyMarshalsToEmptyContainers(t *testing.T) {
	m := Managed{Ports: map[string]string{}}

	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	got := string(b)
	if !strings.Contains(got, `"ports":{}`) {
		t.Errorf("marshal(empty Managed) = %s, want ports:{}", got)
	}
	if !strings.Contains(got, `"allow":[]`) || !strings.Contains(got, `"deny":[]`) {
		t.Errorf("marshal(empty Managed) = %s, want allow:[] and deny:[]", got)
	}
}

// TestSnapshotRequestEmptyMarshalsToEmptyContainers locks in a real bug
// found live (phase 16.1, 2026-11-19): a healthy activation (no precheck
// problems -- the normal case) leaves Problems nil, which without this
// fix marshaled to a literal JSON `null`. The panel's own validation
// rule for `problems` (`sometimes`, `array`, no `nullable`) treats a
// present-but-null field as a validation failure (422), not as
// "absent" -- so every real activation snapshot was rejected outright
// and SOT-02 never completed on any VM. ManagedKeys/SSHPorts share the
// exact same validation shape and are fixed the same way.
func TestSnapshotRequestEmptyMarshalsToEmptyContainers(t *testing.T) {
	req := SnapshotRequest{Observed: Managed{Ports: map[string]string{}}, ObservedHash: "deadbeef"}

	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	got := string(b)
	if !strings.Contains(got, `"problems":[]`) {
		t.Errorf("marshal(empty SnapshotRequest) = %s, want problems:[] (not null)", got)
	}
	if !strings.Contains(got, `"managed_keys":[]`) {
		t.Errorf("marshal(empty SnapshotRequest) = %s, want managed_keys:[] (not null)", got)
	}
	if !strings.Contains(got, `"ssh_ports":[]`) {
		t.Errorf("marshal(empty SnapshotRequest) = %s, want ssh_ports:[] (not null)", got)
	}
}

func TestDriftItemPortRoundTrip(t *testing.T) {
	d := DriftItem{
		Kind:    "port",
		Key:     "TCP_IN",
		Added:   []string{"8080"},
		Removed: []string{"21"},
	}

	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var back DriftItem
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Kind != d.Kind || back.Key != d.Key || len(back.Added) != 1 || back.Added[0] != "8080" {
		t.Errorf("round-trip mismatch: got %+v, want %+v", back, d)
	}
}

func TestWireConfigDecode(t *testing.T) {
	var csfMode Config
	if err := json.Unmarshal([]byte(`{"mode":"csf"}`), &csfMode); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if csfMode.Mode != "csf" || csfMode.Desired != nil {
		t.Errorf("csf mode = %+v, want Mode=csf Desired=nil", csfMode)
	}

	active := `{"mode":"defensia","correction":"warn","generation":7,"snapshot_requested":false,
		"desired":{"ports":{"TCP_IN":"22,80"},"allow":[],"deny":[]},
		"revert_token":"R1","resume_token":null,"retry_token":"T1","unknown_future_key":123}`
	var cfg Config
	if err := json.Unmarshal([]byte(active), &cfg); err != nil {
		t.Fatalf("unmarshal active: %v", err)
	}
	if cfg.Mode != "defensia" || cfg.Correction != "warn" || cfg.Generation != 7 {
		t.Errorf("active cfg = %+v", cfg)
	}
	if cfg.Desired == nil || cfg.Desired.Ports["TCP_IN"] != "22,80" {
		t.Errorf("active cfg.Desired = %+v", cfg.Desired)
	}
	if cfg.RevertToken == nil || *cfg.RevertToken != "R1" {
		t.Errorf("RevertToken = %v, want R1", cfg.RevertToken)
	}
	if cfg.ResumeToken != nil {
		t.Errorf("ResumeToken = %v, want nil", cfg.ResumeToken)
	}
}

func TestWireReportEncode(t *testing.T) {
	r := Report{
		Active:          true,
		GenerationSeen:  3,
		GenerationAcked: 3,
		Status:          "in_sync",
	}

	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)

	if !strings.Contains(s, `"drift":[]`) {
		t.Errorf("marshal(Report{}) = %s, want drift:[]", s)
	}
	if strings.Contains(s, `"observed"`) {
		t.Errorf("marshal(Report{}) = %s, want no observed key (omitempty, nil pointer)", s)
	}
	if !strings.Contains(s, `"tokens_acked":{}`) {
		t.Errorf("marshal(Report{}) = %s, want tokens_acked object present", s)
	}
	if !strings.Contains(s, `"status":"in_sync"`) {
		t.Errorf("marshal(Report{}) = %s, want status in_sync", s)
	}
}

func TestProblemAndRefusalShapes(t *testing.T) {
	p := Problem{Reason: "duplicate_key", Detail: "TCP_IN"}
	if p.Reason != "duplicate_key" {
		t.Fatalf("Problem.Reason = %q", p.Reason)
	}

	r := Refusal{Reason: "ssh_port_in_use", Detail: "22", At: time.Unix(0, 0).UTC(), Generation: 7}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal refusal: %v", err)
	}
	if !strings.Contains(string(b), `"generation":7`) {
		t.Errorf("marshal(refusal) = %s, want generation:7", string(b))
	}
}
