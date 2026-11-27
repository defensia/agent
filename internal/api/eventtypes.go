package api

// Event type classification for phase 19 aggregation (AGG-02/AGG-03).
//
// Aggregation happens after scoring and bans have already been decided —
// merging rows never changes whether an IP gets banned or an alert fires,
// it only changes how many wire-identical rows are sent for the same
// decision. Three gates decide whether a given event is a candidate for
// merging at all; ShouldAggregate evaluates them in order and fails safe
// (never aggregate) on anything it does not recognize:
//
//  1. Severity "critical" always passes through 1:1. A critical row is
//     evidence; evidence must never be summarized away.
//  2. The locked never-aggregate set (below) always passes through 1:1
//     regardless of severity, by product decision — this is the AGG-03
//     hard safety gate and is not configurable at runtime.
//  3. Anything not in aggregatableTypes passes through 1:1. This includes
//     every type this file does not know about ("brand_new_type"), which
//     is the fail-safe default for a type literal the agent has never
//     seen classified — safer to send one row too many than to silently
//     merge something nobody has reviewed.
//
// Beyond those three structural gates, the server (panel) can further
// restrict — but never extend — what is actually enabled at runtime via
// AggregationConfig.PanelTypes. See aggregator.go.

// lockedNeverAggregate is the hard, non-configurable set of event types
// that must always be reported individually, decided by the product
// owner: these are the types whose job is to be critical evidence of an
// active compromise or an enforcement action already taken, where losing
// the exact occurrence count (and exact timestamp of each one) would hide
// the thing the type exists to show. ShouldAggregate checks this set
// before anything else that could be configured away.
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

// botTypes are event types produced by the bot classifier in
// internal/watcher/weblog.go. Aggregation key separation for this family
// uses (domain, bot_slug, user_agent) as the target component (see
// aggregator.go aggKey) — the bot classifier, not the request path, is
// what distinguishes one bot's traffic from another's.
var botTypes = map[string]bool{
	"bot_crawl":    true,
	"bot_detected": true,
	"bot_unknown":  true,
	"bot_monitor":  true,
	"bot_spoofed":  true,
}

// webTypes are request-path-driven event types produced by the web log
// watcher. Aggregation key separation for this family uses (domain, uri)
// as the target component — the same probe hitting two different paths on
// the same domain is two different findings, not one.
var webTypes = map[string]bool{
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

// aggregatableTypes is the full set of event types the agent is
// structurally willing to aggregate at all: every bot/web candidate type
// measured by the AGG-01 production baseline against a shared-hosting
// fleet (19-BASELINE.md Q4 — per-type row share and collapse ratio), minus
// the locked never-aggregate set (there is no overlap between the two by
// construction, see TestAllowlistShape).
//
// The baseline's measured DECISION is far more conservative than this
// structural set — today only one of these fourteen types (bot_crawl)
// clears the baseline's reduction and share bars on real data — and that
// narrower, currently-enabled subset is supplied at runtime via
// AggregationConfig.PanelTypes, not baked in here. PanelTypes can only
// restrict aggregatableTypes further, never add to it (see aggregator.go),
// so widening what is actually enabled in production as more types get
// measured and trusted is a config change, not a binary rebuild.
var aggregatableTypes = mergeTypeSets(botTypes, webTypes)

func mergeTypeSets(sets ...map[string]bool) map[string]bool {
	merged := make(map[string]bool)
	for _, set := range sets {
		for t := range set {
			merged[t] = true
		}
	}
	return merged
}

// ShouldAggregate reports whether e is a structural candidate for merging
// into a rollup, evaluated against the optional server-supplied
// restriction panelTypes (nil means "whatever the agent itself allows",
// i.e. aggregatableTypes unrestricted).
//
// Order matters and is deliberately fail-safe: a critical event, a locked
// type, or an unrecognized type is never aggregated no matter what
// panelTypes says, and panelTypes can only turn an otherwise-aggregatable
// type off, never on.
func ShouldAggregate(e EventRequest, panelTypes map[string]bool) bool {
	if e.Severity == "critical" {
		return false
	}
	if lockedNeverAggregate[e.Type] {
		return false
	}
	if !aggregatableTypes[e.Type] {
		return false
	}
	if panelTypes != nil && !panelTypes[e.Type] {
		return false
	}
	return true
}

// isBotType reports whether t is one of the bot-classifier event types.
func isBotType(t string) bool { return botTypes[t] }

// isWebType reports whether t is one of the request-path-driven event types.
func isWebType(t string) bool { return webTypes[t] }
