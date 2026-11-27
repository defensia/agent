// Package loadgen generates a deterministic, profile-driven event stream
// for the AGG-05 lab load test (19-13-PLAN.md): a reproducible stand-in
// for a day of real traffic on a shared-hosting server, shaped by
// 19-BASELINE.md's measured per-type volume, hourly distribution and
// aggregation collapse ratio.
//
// loadgen knows nothing about the real Aggregator (internal/api) and does
// not decide whether any event it produces actually gets merged on the
// wire — that decision belongs entirely to the real api.Client/Aggregator
// the integration test drives. loadgen's only job is to produce the exact
// same INPUT stream, byte-for-byte, given the same seed, so a before/after
// (aggregation off vs on) comparison is a comparison of the pipeline, not
// of two different synthetic days.
package loadgen

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"sort"
	"time"

	"github.com/defensia/agent/internal/api"
)

// burstN is the fixed event count for Generate's Burst=true worst-case
// leg (19-13-PLAN.md task 1 behavior: "Burst mode (Generate with
// Burst=true, N=5000)"). Not profile-driven: the burst leg exists purely
// to prove that IP-rotating traffic which can never share an aggregation
// key still loses zero events, regardless of profile.json's shape.
const burstN = 5000

// ProfileType is one row of profile.json's "types" array: a single
// (type, severity) pair's measured daily volume and collapse ratio.
type ProfileType struct {
	Type          string  `json:"type"`
	Severity      string  `json:"severity"`
	PerServerDay  int     `json:"per_server_day"`
	RepeatsPerKey float64 `json:"repeats_per_key"`
}

// Profile is lab/load/profile.json: the measured AGG-01 baseline
// (19-BASELINE.md aggregation_decisions), converted to JSON so the Go
// generator and the lab shell scripts share one file instead of parsing
// YAML twice.
type Profile struct {
	Source                  string        `json:"source"`
	RowsPerServerDay        int           `json:"rows_per_server_day"`
	BotWindowSeconds        int           `json:"bot_window_seconds"`
	WebWindowSeconds        int           `json:"web_window_seconds"`
	TargetReductionPct      int           `json:"target_reduction_pct"`
	TheoreticalReductionPct int           `json:"theoretical_reduction_pct"`
	CriticalsPerServerDay   int           `json:"criticals_per_server_day"`
	Allowlist               []string      `json:"allowlist"`
	MaxKeys                 int           `json:"max_keys"`
	MaxCount                int           `json:"max_count"`
	HourlyShare             []float64     `json:"hourly_share"`
	Types                   []ProfileType `json:"types"`
}

// LoadProfile reads and decodes path (lab/load/profile.json) into a Profile.
func LoadProfile(path string) (Profile, error) {
	var p Profile
	data, err := os.ReadFile(path)
	if err != nil {
		return p, fmt.Errorf("loadgen: read profile %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return p, fmt.Errorf("loadgen: decode profile %s: %w", path, err)
	}
	return p, nil
}

// Event pairs the virtual-clock timestamp an event should be replayed at
// (At) with the wire payload itself (Req). Generate returns events sorted
// by At so a caller can drive a virtual clock forward monotonically while
// replaying them in order.
type Event struct {
	At  time.Time
	Req api.EventRequest
}

// botTypeFamily/webTypeFamily mirror internal/api/eventtypes.go's
// botTypes/webTypes classification. Duplicated here deliberately rather
// than imported: those maps are unexported (package-private, by design —
// see eventtypes.go's own comment on why the structural candidate set is
// not meant to be consumed outside internal/api), and loadgen is a test
// tool shaping SYNTHETIC input, not a second implementation of the real
// aggregation decision. Keep in sync by hand if eventtypes.go's sets ever
// change; TestProfileTypesClassifiable guards against drift by failing
// loudly if profile.json ever names a type this file does not classify.
var botTypeFamily = map[string]bool{
	"bot_crawl":    true,
	"bot_detected": true,
	"bot_unknown":  true,
	"bot_monitor":  true,
	"bot_spoofed":  true,
}

var webTypeFamily = map[string]bool{
	"scanner_detected":  true,
	"404_flood":         true,
	"env_probe":         true,
	"config_probe":      true,
	"sql_injection":     true,
	"xss_attempt":       true,
	"path_traversal":    true,
	"web_exploit":       true,
	"modsecurity_block": true,
}

// lockedNeverAggregate mirrors internal/api/eventtypes.go's own locked
// set, for the same reason as botTypeFamily/webTypeFamily above: loadgen
// forces exactly one occurrence per key for these types (never grouped),
// matching the real pipeline's hard safety gate regardless of what
// repeats_per_key says in profile.json.
var lockedNeverAggregate = map[string]bool{
	"malware_realtime":       true,
	"malware_blocked":        true,
	"malware_quarantined":    true,
	"malware_scan_started":   true,
	"malware_scan_progress":  true,
	"malware_scan_completed": true,
	"rce_attempt":            true,
	"web_shell":              true,
	"ban_created":            true,
	"sigma_detection":        true,
}

// probeURIs is the fixed pool of 30 synthetic probe paths used for web-type
// events (and, varied per occurrence, for bot-type events' details.uri).
// No real customer paths — generic hosting-admin/CMS probe shapes only.
var probeURIs = []string{
	"/wp-login.php", "/wp-admin/", "/.env", "/.git/config", "/admin/",
	"/phpmyadmin/", "/xmlrpc.php", "/config.php", "/wp-content/debug.log",
	"/.well-known/security.txt", "/vendor/", "/backup.sql", "/shell.php",
	"/cgi-bin/test.cgi", "/server-status", "/.htaccess", "/robots.txt",
	"/wp-json/wp/v2/users", "/administrator/", "/install.php",
	"/phpinfo.php", "/.aws/credentials", "/db_backup.zip", "/old/index.php",
	"/test.php", "/uploads/shell.php", "/.ssh/id_rsa", "/setup-config.php",
	"/wp-content/uploads/", "/api/v1/debug",
}

// botSlugs/botNames/userAgents are small synthetic pools so bot-type keys
// (domain+bot_slug+user_agent, per internal/api/aggregator.go's keyFor)
// repeat across occurrences within one key while varying across keys.
var botSlugs = []string{"lab_crawlerbot", "lab_scraperbot", "lab_fetchbot", "lab_indexbot", "lab_probebot"}
var botNames = []string{"LabCrawler", "LabScraper", "LabFetcher", "LabIndexer", "LabProbe"}
var userAgents = []string{
	"LabCrawlerBot/1.0 (+http://example.test/bot)",
	"LabScraperBot/2.1 (+http://example.test/bot)",
	"Mozilla/5.0 (compatible; LabFetchBot/1.0)",
	"LabIndexBot/3.0",
	"LabProbeBot/1.2",
}

// seq is a per-Generate monotonic counter backing details.load_seq, so
// every event — aggregatable or not — carries a unique sequence id within
// one run, independent of final time-sort order.
type seq struct{ n int }

func (s *seq) next() string {
	s.n++
	return fmt.Sprintf("%d", s.n)
}

// ipAllocator hands out unique, deterministic IPs from 198.18.0.0/15
// (TEST-NET-3 adjacent, RFC 2544 benchmarking range — never a real host).
// /15 = 2^17 addresses (198.18.0.0-198.19.255.255), far more than this
// generator's worst-case key count (burstN=5000, or the baseline's ~18k
// per_server_day events spread across far fewer keys since only
// bot_crawl has repeats_per_key > 1).
type ipAllocator struct{ next uint32 }

func (a *ipAllocator) alloc() string {
	off := a.next
	a.next++
	b2 := 18 + (off>>16)&1
	b3 := (off >> 8) & 0xFF
	b4 := off & 0xFF
	return fmt.Sprintf("198.%d.%d.%d", b2, b3, b4)
}

// poissonSample draws from a Poisson distribution with mean lambda using
// Knuth's algorithm — adequate for this generator's small lambdas
// (repeats_per_key rarely exceeds low single digits) and avoids a new
// dependency for one call site.
func poissonSample(rng *rand.Rand, lambda float64) int {
	if lambda <= 0 {
		return 0
	}
	l := math.Exp(-lambda)
	k := 0
	p := 1.0
	for {
		k++
		p *= rng.Float64()
		if p <= l {
			break
		}
	}
	return k - 1
}

// sampleHour draws an hour-of-day index (0-23) from share's CDF.
func sampleHour(rng *rand.Rand, share []float64) int {
	r := rng.Float64()
	cum := 0.0
	for h, s := range share {
		cum += s
		if r <= cum {
			return h
		}
	}
	return len(share) - 1
}

// domainFor returns a deterministic synthetic domain for index i.
func domainFor(i int) string {
	return fmt.Sprintf("site%02d.example.test", (i%30)+1)
}

// Generate produces a deterministic event stream for profile p, seeded by
// seed (same seed -> byte-identical output, checked via sha256 by
// TestGenerateDeterministic), anchored at dayStart, tagged with runID in
// every event's details.load_run.
//
// Non-burst mode: replays p.Types at p.RowsPerServerDay-shaped volume,
// p.HourlyShare-shaped timing, and p.Types[].RepeatsPerKey-shaped
// aggregation-key grouping (critical-severity and locked-never-aggregate
// types are always forced to exactly one occurrence per key, regardless
// of what RepeatsPerKey says, matching internal/api/eventtypes.go's
// ShouldAggregate's own fail-safe priority).
//
// Burst mode (burst=true): ignores p.Types/p.HourlyShare entirely and
// emits burstN bot_unknown events, each from its own unique IP (repeats
// per key always 1 — an IP-rotating attacker no amount of time-bucketing
// can collapse), spaced over a short 5-minute window starting at dayStart.
// This is the worst-case leg: it must still lose zero events, with
// (expected, honestly reported) near-zero row reduction.
func Generate(p Profile, seed int64, dayStart time.Time, runID string, burst bool) []Event {
	rng := rand.New(rand.NewPCG(uint64(seed), uint64(seed))) //nolint:gosec // deterministic replay, not security-sensitive
	s := &seq{}
	ips := &ipAllocator{}

	if burst {
		return generateBurst(rng, s, ips, dayStart, runID)
	}

	var events []Event
	keyIndex := 0
	for _, t := range p.Types {
		if t.PerServerDay <= 0 {
			continue
		}
		repeats := t.RepeatsPerKey
		if t.Severity == "critical" || lockedNeverAggregate[t.Type] {
			repeats = 1 // never-aggregate gate wins over any profile value
		}
		if repeats < 1 {
			repeats = 1
		}

		windowSeconds := p.WebWindowSeconds
		if botTypeFamily[t.Type] {
			windowSeconds = p.BotWindowSeconds
		}

		remaining := t.PerServerDay
		for remaining > 0 {
			n := 1 + poissonSample(rng, repeats-1)
			if n > remaining {
				n = remaining
			}
			events = append(events, generateKey(rng, s, ips, t, n, windowSeconds, p.HourlyShare, dayStart, runID, keyIndex)...)
			remaining -= n
			keyIndex++
		}
	}

	sort.Slice(events, func(i, j int) bool { return events[i].At.Before(events[j].At) })
	return events
}

// generateKey emits n occurrences of one aggregation key (shared ip and,
// for bot/web types, shared domain+target dimension) inside a single
// windowSeconds-wide interval anchored at an hour sampled from
// hourlyShare, per the plan's behavior: "uniform in [start, start+window)".
func generateKey(rng *rand.Rand, s *seq, ips *ipAllocator, t ProfileType, n int, windowSeconds int, hourlyShare []float64, dayStart time.Time, runID string, keyIndex int) []Event {
	hour := sampleHour(rng, hourlyShare)
	hourStart := dayStart.Add(time.Duration(hour) * time.Hour)
	maxOffset := time.Hour - time.Duration(windowSeconds)*time.Second
	if maxOffset < 0 {
		maxOffset = 0
	}
	windowStart := hourStart.Add(time.Duration(rng.Int64N(int64(maxOffset) + 1)))

	ip := ips.alloc()
	domain := domainFor(keyIndex)
	isBot := botTypeFamily[t.Type]
	isWeb := webTypeFamily[t.Type]

	var slug, name, ua, uri string
	if isBot {
		idx := keyIndex % len(botSlugs)
		slug, name, ua = botSlugs[idx], botNames[idx], userAgents[idx]
		uri = probeURIs[keyIndex%len(probeURIs)]
	} else if isWeb {
		uri = probeURIs[keyIndex%len(probeURIs)]
	}

	out := make([]Event, 0, n)
	for i := 0; i < n; i++ {
		var at time.Time
		if windowSeconds > 0 {
			at = windowStart.Add(time.Duration(rng.Int64N(int64(windowSeconds) * int64(time.Second))))
		} else {
			at = windowStart
		}

		details := map[string]string{
			"load_run": runID,
			"load_seq": s.next(),
			"domain":   domain,
		}

		switch {
		case isBot:
			details["uri"] = probeURIs[(keyIndex+i)%len(probeURIs)]
			details["user_agent"] = ua
			details["bot_slug"] = slug
			details["bot_name"] = name
		case isWeb:
			details["uri"] = uri
			details["user_agent"] = "Mozilla/5.0 (LabProbeAgent)"
			details["log_file"] = "/var/log/nginx/access.log"
		default:
			details["file"] = fmt.Sprintf("/var/www/%s/reason-%d.txt", domain, s.n)
			details["reason"] = "synthetic-load"
		}

		out = append(out, Event{
			At: at,
			Req: api.EventRequest{
				Type:       t.Type,
				Severity:   t.Severity,
				SourceIP:   ip,
				Details:    details,
				OccurredAt: at.UTC().Format(time.RFC3339),
			},
		})
	}
	return out
}

// generateBurst produces burstN bot_unknown events, each from a distinct
// IP (so no two ever share an aggregation key), spaced evenly over a
// 5-minute window starting at dayStart.
func generateBurst(rng *rand.Rand, s *seq, ips *ipAllocator, dayStart time.Time, runID string) []Event {
	const window = 5 * time.Minute
	out := make([]Event, 0, burstN)
	for i := 0; i < burstN; i++ {
		at := dayStart.Add(time.Duration(rng.Int64N(int64(window))))
		ip := ips.alloc()
		details := map[string]string{
			"load_run":   runID,
			"load_seq":   s.next(),
			"domain":     domainFor(i),
			"uri":        probeURIs[i%len(probeURIs)],
			"user_agent": fmt.Sprintf("LabBurstBot/1.0 (+ip-rotating; seq=%d)", i),
			"bot_slug":   "lab_burst",
			"bot_name":   "LabBurst",
		}
		out = append(out, Event{
			At: at,
			Req: api.EventRequest{
				Type:       "bot_unknown",
				Severity:   "info",
				SourceIP:   ip,
				Details:    details,
				OccurredAt: at.UTC().Format(time.RFC3339),
			},
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}
