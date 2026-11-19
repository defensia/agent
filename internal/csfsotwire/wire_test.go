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
