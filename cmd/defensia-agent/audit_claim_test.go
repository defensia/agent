package main

import (
	"sync"
	"testing"
)

// An audit can now reach the agent two ways — the WebSocket broadcast and the
// heartbeat — so the same request must not run twice and submit two inventories
// for one audit id.
func TestClaimAuditRunsAnIdOnlyOnce(t *testing.T) {
	resetStartedAudits()

	if !claimAudit(9001) {
		t.Fatal("the first claim on an id must succeed")
	}
	if claimAudit(9001) {
		t.Error("the second claim on the same id must be refused")
	}
	if !claimAudit(9002) {
		t.Error("a different id must still be claimable")
	}
}

func TestClaimAuditIsSafeUnderConcurrency(t *testing.T) {
	resetStartedAudits()

	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if claimAudit(4242) {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if wins != 1 {
		t.Errorf("exactly one of 50 concurrent claims must win, got %d", wins)
	}
}

// The agent is long-lived, so the record of started audits must not grow without
// bound.
func TestClaimAuditBoundsItsMemory(t *testing.T) {
	resetStartedAudits()

	for i := int64(0); i < 300; i++ {
		claimAudit(i)
	}

	startedAudits.Lock()
	defer startedAudits.Unlock()

	if len(startedAudits.seen) > 64 {
		t.Errorf("startedAudits holds %d ids, cap is 64", len(startedAudits.seen))
	}
	if len(startedAudits.order) != len(startedAudits.seen) {
		t.Errorf("the index and the order list disagree: %d vs %d", len(startedAudits.seen), len(startedAudits.order))
	}
	// The newest must still be remembered, or a duplicate would slip through.
	if !startedAudits.seen[299] {
		t.Error("the most recent id was forgotten; a duplicate of it would run twice")
	}
}

func resetStartedAudits() {
	startedAudits.Lock()
	defer startedAudits.Unlock()
	startedAudits.seen = make(map[int64]bool)
	startedAudits.order = nil
}
