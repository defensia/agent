package loadgen

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func testProfile() Profile {
	return Profile{
		Source:                  "test fixture",
		RowsPerServerDay:        1000,
		BotWindowSeconds:        60,
		WebWindowSeconds:        30,
		TargetReductionPct:      30,
		TheoreticalReductionPct: 45,
		CriticalsPerServerDay:   100,
		Allowlist:               []string{"bot_crawl"},
		MaxKeys:                 10000,
		MaxCount:                1000,
		HourlyShare: []float64{
			0.055, 0.042, 0.040, 0.042, 0.040, 0.049, 0.048, 0.023, 0.029, 0.024, 0.022, 0.047,
			0.044, 0.042, 0.052, 0.056, 0.058, 0.083, 0.067, 0.024, 0.028, 0.023, 0.016, 0.046,
		},
		Types: []ProfileType{
			{Type: "bot_crawl", Severity: "info", PerServerDay: 600, RepeatsPerKey: 2.92},
			{Type: "path_traversal", Severity: "warning", PerServerDay: 150, RepeatsPerKey: 1.0},
			{Type: "env_probe", Severity: "critical", PerServerDay: 100, RepeatsPerKey: 1.0},
			{Type: "ban_created", Severity: "warning", PerServerDay: 50, RepeatsPerKey: 1.0},
			{Type: "malware_scan_progress", Severity: "info", PerServerDay: 100, RepeatsPerKey: 1.0},
		},
	}
}

func dayStart() time.Time { return time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC) }

func sha256OfJSON(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sum := sha256.Sum256(data)
	return string(sum[:])
}

func TestGenerateDeterministic(t *testing.T) {
	p := testProfile()
	a := Generate(p, 19, dayStart(), "run-a", false)
	b := Generate(p, 19, dayStart(), "run-a", false)

	if len(a) != len(b) {
		t.Fatalf("length differs: %d vs %d", len(a), len(b))
	}
	if sha256OfJSON(t, a) != sha256OfJSON(t, b) {
		t.Fatalf("same seed produced different output (sha256 mismatch)")
	}

	c := Generate(p, 20, dayStart(), "run-a", false)
	if sha256OfJSON(t, a) == sha256OfJSON(t, c) {
		t.Fatalf("different seed produced identical output")
	}
}

func TestGeneratePerTypeTotals(t *testing.T) {
	p := testProfile()
	events := Generate(p, 19, dayStart(), "run-totals", false)

	counts := map[string]int{}
	for _, e := range events {
		counts[e.Req.Type+"|"+e.Req.Severity]++
	}

	total := 0
	for _, pt := range p.Types {
		total += pt.PerServerDay
		got := counts[pt.Type+"|"+pt.Severity]
		diff := got - pt.PerServerDay
		if diff < -1 || diff > 1 {
			t.Errorf("%s/%s: want %d +-1, got %d", pt.Type, pt.Severity, pt.PerServerDay, got)
		}
	}

	totalGot := len(events)
	diff := totalGot - total
	if diff < -len(p.Types) || diff > len(p.Types) {
		t.Errorf("total events: want ~%d, got %d", total, totalGot)
	}
}

func TestGenerateHourlyShape(t *testing.T) {
	p := testProfile()
	// Larger volume for a stable chi-square-ish sanity check.
	p.Types[0].PerServerDay = 20000
	events := Generate(p, 19, dayStart(), "run-hourly", false)

	hourCounts := make([]int, 24)
	for _, e := range events {
		hourCounts[e.At.UTC().Hour()]++
	}

	total := len(events)
	for h, share := range p.HourlyShare {
		if share < 0.02 {
			continue // too small a bucket to assert tightly
		}
		expected := share * float64(total)
		got := float64(hourCounts[h])
		lower, upper := expected*0.8, expected*1.2
		if got < lower || got > upper {
			t.Errorf("hour %d: got %d, want within +-20%% of %.1f", h, hourCounts[h], expected)
		}
	}
}

func TestGenerateCriticalAndLockedAreIndividual(t *testing.T) {
	p := testProfile()
	events := Generate(p, 19, dayStart(), "run-crit", false)

	// Every env_probe/critical, ban_created and malware_scan_progress
	// event must have a unique source IP (no two occurrences share a key)
	// because the generator forces repeats=1 for critical/locked types.
	seen := map[string]bool{}
	for _, e := range events {
		switch {
		case e.Req.Severity == "critical", e.Req.Type == "ban_created", e.Req.Type == "malware_scan_progress":
			key := e.Req.Type + "|" + e.Req.SourceIP
			if seen[key] {
				t.Errorf("critical/locked type %s reused source_ip %s across occurrences", e.Req.Type, e.Req.SourceIP)
			}
			seen[key] = true
			if e.Req.Count != 0 {
				t.Errorf("critical/locked type %s carries non-zero Count %d", e.Req.Type, e.Req.Count)
			}
		}
	}
}

func TestGenerateDetailsCarryLoadRunAndSeq(t *testing.T) {
	p := testProfile()
	events := Generate(p, 19, dayStart(), "run-details-xyz", false)

	seqSeen := map[string]bool{}
	for _, e := range events {
		if e.Req.Details["load_run"] != "run-details-xyz" {
			t.Fatalf("event missing/incorrect details.load_run: %q", e.Req.Details["load_run"])
		}
		seq := e.Req.Details["load_seq"]
		if seq == "" {
			t.Fatalf("event missing details.load_seq")
		}
		if seqSeen[seq] {
			t.Fatalf("duplicate load_seq %q", seq)
		}
		seqSeen[seq] = true
	}
}

func TestGenerateIPsInRange(t *testing.T) {
	p := testProfile()
	events := Generate(p, 19, dayStart(), "run-ip", false)
	for _, e := range events {
		ip := e.Req.SourceIP
		if len(ip) == 0 {
			t.Fatalf("event with empty source_ip")
		}
		if ip[:7] != "198.18." && ip[:7] != "198.19." {
			t.Fatalf("source_ip %s not in 198.18.0.0/15", ip)
		}
	}
}

func TestGenerateNoRealHostnames(t *testing.T) {
	p := testProfile()
	events := Generate(p, 19, dayStart(), "run-host", false)
	for _, e := range events {
		domain := e.Req.Details["domain"]
		if domain == "" {
			continue
		}
		if len(domain) < len("site01.example.test") || domain[len(domain)-12:] != "example.test" {
			t.Fatalf("domain %q does not look like a synthetic siteNN.example.test host", domain)
		}
	}
}

func TestGenerateBurstUniqueIPs(t *testing.T) {
	p := testProfile()
	events := Generate(p, 19, dayStart(), "run-burst", true)

	if len(events) != burstN {
		t.Fatalf("burst: want %d events, got %d", burstN, len(events))
	}

	ips := map[string]bool{}
	for _, e := range events {
		if e.Req.Type != "bot_unknown" {
			t.Errorf("burst event has type %q, want bot_unknown", e.Req.Type)
		}
		if ips[e.Req.SourceIP] {
			t.Fatalf("burst mode reused source_ip %s (must be unique per event)", e.Req.SourceIP)
		}
		ips[e.Req.SourceIP] = true
	}
}

func TestLoadProfileRoundTrip(t *testing.T) {
	p := testProfile()
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	tmp := t.TempDir() + "/profile.json"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		t.Fatalf("write temp profile: %v", err)
	}
	loaded, err := LoadProfile(tmp)
	if err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}
	if loaded.RowsPerServerDay != p.RowsPerServerDay || len(loaded.Types) != len(p.Types) {
		t.Fatalf("round trip mismatch: %+v vs %+v", loaded, p)
	}
}
