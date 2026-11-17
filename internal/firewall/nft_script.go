package firewall

import (
	"fmt"
	"math"
	"net"
	"regexp"
	"strings"
	"time"
)

// nftables table/chain layout constants. Phase 17 NFT-02/NFT-04: the agent
// owns exactly one table (inet defensia) and never touches any other table
// or chain — coexistence with other packet-filtering stacks (firewall
// daemons, CSF's own iptables-nft rules) depends on this. The agent never
// clears the entire kernel ruleset in one command.
const (
	nftFamily        = "inet"
	nftTable         = "defensia"
	nftInputPriority = -10 // before iptables-nft filter (0) and other firewall daemons' hooks; a drop anywhere is final, same constraint iptables already had
	nftBanSetSize    = 65536
	nftMinVersion    = "1.0.0" // below this, Probe() fails and detection falls through to iptables
	nftChunk         = 1000    // elements per `add element` statement, to keep any single line bounded
	nftRuleKeyPrefix = "defensia-rule:"
	nftGeoKeyPrefix  = "defensia-geo:"
)

// nftProbeScript is issued once by Probe() to prove nf_tables + CAP_NET_ADMIN
// actually work on this host (LookPath alone would call a broken nft "found").
// It touches a throwaway table, never `defensia`.
const nftProbeScript = "add table inet defensia_probe\ndelete table inet defensia_probe\n"

// nftEnsureScript returns the full idempotent setup transaction: table,
// chains, sets, and the input/protected chain contents (flushed and rebuilt
// every call so a tampered chain self-repairs with no window). The
// `portrules` and `geo` chains and all set elements are NEVER flushed here —
// only Ensure recreates structure; ApplyRule/GeoReplace/etc. own their own
// contents.
//
// The chain is named "portrules", not "rules": nft's own command-line
// grammar reserves "rules"/"rule" as keywords for its `list`/`delete` verbs
// (confirmed on nftables v1.1.5 — `nft list chain inet defensia rules`
// fails with "syntax error, unexpected rules, expecting string or last",
// even though `add chain ... rules` succeeds). Every chain name that will
// ever be passed as a bare CLI argument (not just inside an `-f -` script)
// must avoid nft's reserved vocabulary.
func nftEnsureScript() string {
	lines := []string{
		fmt.Sprintf("add table %s %s", nftFamily, nftTable),
		fmt.Sprintf("add chain %s %s input { type filter hook input priority %d; policy accept; }", nftFamily, nftTable, nftInputPriority),
		fmt.Sprintf("add chain %s %s protected", nftFamily, nftTable),
		fmt.Sprintf("add chain %s %s portrules", nftFamily, nftTable),
		fmt.Sprintf("add chain %s %s geo", nftFamily, nftTable),
		fmt.Sprintf("add set %s %s bans4 { type ipv4_addr; flags timeout; size %d; }", nftFamily, nftTable, nftBanSetSize),
		fmt.Sprintf("add set %s %s bans6 { type ipv6_addr; flags timeout; size %d; }", nftFamily, nftTable, nftBanSetSize),
		fmt.Sprintf("add set %s %s protected4 { type ipv4_addr; }", nftFamily, nftTable),
		fmt.Sprintf("add set %s %s protected6 { type ipv6_addr; }", nftFamily, nftTable),
		fmt.Sprintf("flush chain %s %s input", nftFamily, nftTable),
		fmt.Sprintf(`add rule %s %s input jump protected comment "defensia:protected"`, nftFamily, nftTable),
		fmt.Sprintf(`add rule %s %s input jump portrules comment "defensia:rules"`, nftFamily, nftTable),
		fmt.Sprintf(`add rule %s %s input ip saddr @bans4 drop comment "defensia:bans4"`, nftFamily, nftTable),
		fmt.Sprintf(`add rule %s %s input ip6 saddr @bans6 drop comment "defensia:bans6"`, nftFamily, nftTable),
		fmt.Sprintf(`add rule %s %s input jump geo comment "defensia:geo"`, nftFamily, nftTable),
		fmt.Sprintf("flush chain %s %s protected", nftFamily, nftTable),
		fmt.Sprintf(`add rule %s %s protected ip saddr @protected4 accept comment "defensia:protected4"`, nftFamily, nftTable),
		fmt.Sprintf(`add rule %s %s protected ip6 saddr @protected6 accept comment "defensia:protected6"`, nftFamily, nftTable),
	}
	return strings.Join(lines, "\n") + "\n"
}

// nftTimeoutSuffix renders the optional " timeout Ns" clause for a ban
// element. ttl <= 0 means no kernel timeout (panel-driven expiry) -> "".
// Sub-second ttls round up (ceil) to a minimum of 1s — nft has no sub-second
// timeout granularity worth using here.
func nftTimeoutSuffix(ttl time.Duration) string {
	if ttl <= 0 {
		return ""
	}
	secs := int64(math.Ceil(ttl.Seconds()))
	if secs < 1 {
		secs = 1
	}
	return fmt.Sprintf(" timeout %ds", secs)
}

// nftBanScript builds one or more `add element` statements for set (bans4 or
// bans6), chunked to nftChunk entries per statement. Empty entries -> "".
func nftBanScript(set string, entries []BanEntry) string {
	if len(entries) == 0 {
		return ""
	}
	var b strings.Builder
	for i := 0; i < len(entries); i += nftChunk {
		end := i + nftChunk
		if end > len(entries) {
			end = len(entries)
		}
		parts := make([]string, 0, end-i)
		for _, e := range entries[i:end] {
			parts = append(parts, e.IP+nftTimeoutSuffix(e.TTL))
		}
		fmt.Fprintf(&b, "add element %s %s %s { %s }\n", nftFamily, nftTable, set, strings.Join(parts, ", "))
	}
	return b.String()
}

// nftUnbanScript deletes a single element. Deleting an absent element is the
// backend's problem to tolerate (isNftNotFound), not this builder's.
func nftUnbanScript(set, ip string) string {
	return fmt.Sprintf("delete element %s %s %s { %s }\n", nftFamily, nftTable, set, ip)
}

// nftRuleExpr builds the match+verdict expression and the stable comment key
// for a port/CIDR rule, mirroring iptables.go's buildRuleArgs semantics:
// an empty/"all" protocol only becomes "tcp" when a port is given. Unlike
// the iptables backend (which keeps origin/main's permissive behaviour), nft
// refuses a spec that would match everything (no source, no port/protocol
// restriction) — deliberately stricter, see 17-04-SUMMARY.md.
func nftRuleExpr(spec RuleSpec) (expr, key string, err error) {
	source := "-"
	var srcExpr string
	family := "" // "4" or "6" once a source is resolved

	switch {
	case spec.IPAddress != nil && *spec.IPAddress != "":
		ip := net.ParseIP(*spec.IPAddress)
		if ip == nil {
			return "", "", fmt.Errorf("invalid IP address: %s", *spec.IPAddress)
		}
		source = ip.String()
		if ip.To4() != nil {
			family = "4"
			srcExpr = "ip saddr " + source
		} else {
			family = "6"
			srcExpr = "ip6 saddr " + source
		}
	case spec.IPRange != nil && *spec.IPRange != "":
		_, network, perr := net.ParseCIDR(*spec.IPRange)
		if perr != nil {
			return "", "", fmt.Errorf("invalid CIDR: %s", *spec.IPRange)
		}
		source = network.String()
		if network.IP.To4() != nil {
			family = "4"
			srcExpr = "ip saddr " + source
		} else {
			family = "6"
			srcExpr = "ip6 saddr " + source
		}
	}

	proto := strings.ToLower(spec.Protocol)
	var port int
	if spec.Port != nil {
		port = *spec.Port
	}
	origPort := port

	if proto == "" || proto == "all" {
		if port != 0 {
			proto = "tcp"
		} else {
			proto = "all"
		}
	}

	if proto == "icmp" && origPort != 0 && srcExpr == "" {
		return "", "", fmt.Errorf("icmp rule with a port but no source has nothing meaningful left to match (port is ignored for icmp)")
	}

	var protoExpr string
	switch proto {
	case "all":
		protoExpr = ""
		port = 0
	case "icmp":
		port = 0
		if family == "6" {
			protoExpr = "meta l4proto ipv6-icmp"
		} else {
			protoExpr = "meta l4proto icmp"
		}
	default: // tcp, udp, and any other named protocol
		if port != 0 {
			protoExpr = fmt.Sprintf("%s dport %d", proto, port)
		} else {
			protoExpr = "meta l4proto " + proto
		}
	}

	if srcExpr == "" && protoExpr == "" {
		return "", "", fmt.Errorf("rule must match a source or a protocol/port (a match-everything rule is refused)")
	}

	verdict := "drop"
	if spec.Type == "allow" {
		verdict = "accept"
	}

	var parts []string
	if srcExpr != "" {
		parts = append(parts, srcExpr)
	}
	if protoExpr != "" {
		parts = append(parts, protoExpr)
	}
	parts = append(parts, verdict)

	expr = strings.Join(parts, " ")
	key = fmt.Sprintf("%s%s:%s:%s:%d", nftRuleKeyPrefix, spec.Type, proto, source, port)
	return expr, key, nil
}

// decodeRuleKey reverses nftRuleExpr's key into a ParsedRule. source may
// itself contain colons (IPv6), so port is split from the right and
// type/proto from the left, not a single SplitN(... ,4).
func decodeRuleKey(key string) (ParsedRule, bool) {
	if !strings.HasPrefix(key, nftRuleKeyPrefix) {
		return ParsedRule{}, false
	}
	rest := strings.TrimPrefix(key, nftRuleKeyPrefix)
	head := strings.SplitN(rest, ":", 3)
	if len(head) != 3 {
		return ParsedRule{}, false
	}
	typ, proto, sourceAndPort := head[0], head[1], head[2]
	i := strings.LastIndex(sourceAndPort, ":")
	if i < 0 {
		return ParsedRule{}, false
	}
	source := sourceAndPort[:i]
	portStr := sourceAndPort[i+1:]
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		return ParsedRule{}, false
	}
	if source == "-" {
		source = ""
	}
	return ParsedRule{RawRule: key, Type: typ, Protocol: proto, Source: source, Port: port}, true
}

// nftAddRuleScript / nftDeleteRuleScript add or remove one rule in the
// `portrules` chain by expression/comment or by handle.
func nftAddRuleScript(expr, key string) string {
	return fmt.Sprintf(`add rule %s %s portrules %s comment "%s"`+"\n", nftFamily, nftTable, expr, key)
}

func nftDeleteRuleScript(chain string, handle int) string {
	return fmt.Sprintf("delete rule %s %s %s handle %d\n", nftFamily, nftTable, chain, handle)
}

// geoCCPattern matches exactly a 2-letter country code (case-insensitive).
var geoCCPattern = regexp.MustCompile(`^[A-Za-z]{2}$`)

// nftGeoSetName validates cc and returns its set name ("geo_" + lowercase).
func nftGeoSetName(cc string) (string, error) {
	if !geoCCPattern.MatchString(cc) {
		return "", fmt.Errorf("invalid country code: %q", cc)
	}
	return "geo_" + strings.ToLower(cc), nil
}

// filterGeoCIDRs keeps only valid, non-default-route IPv4 CIDRs (bare IPv4
// becomes /32), drops IPv6 and duplicates, and preserves first-occurrence
// order (map set lookups do not have a stable iteration order).
func filterGeoCIDRs(cidrs []string) []string {
	seen := make(map[string]bool, len(cidrs))
	out := make([]string, 0, len(cidrs))
	for _, raw := range cidrs {
		c := strings.TrimSpace(raw)
		if c == "" {
			continue
		}
		var network *net.IPNet
		if strings.Contains(c, "/") {
			_, n, err := net.ParseCIDR(c)
			if err != nil {
				continue
			}
			network = n
		} else {
			ip := net.ParseIP(c)
			if ip == nil {
				continue
			}
			v4 := ip.To4()
			if v4 == nil {
				continue
			}
			network = &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
		}
		if network.IP.To4() == nil {
			continue // IPv6 CIDR, dropped — geo sets here are IPv4-only
		}
		norm := network.String()
		if norm == "0.0.0.0/0" {
			continue
		}
		if seen[norm] {
			continue
		}
		seen[norm] = true
		out = append(out, norm)
	}
	return out
}

// nftGeoSetupScript builds only the create+flush lines for a country set —
// the first half of the two-step fallback backend_nft.go uses when the
// atomic script in nftGeoReplaceScript fails with an "interval"/"conflicting"
// kernel error (the set has incompatible interval state mid-transaction).
func nftGeoSetupScript(cc string) (string, error) {
	setName, err := nftGeoSetName(cc)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "add set %s %s %s { type ipv4_addr; flags interval; auto-merge; }\n", nftFamily, nftTable, setName)
	fmt.Fprintf(&b, "flush set %s %s %s\n", nftFamily, nftTable, setName)
	return b.String(), nil
}

// nftGeoElementsScript builds only the element (and optional rule) lines for
// a country set — the second half of the two-step fallback.
func nftGeoElementsScript(cc string, cidrs []string, addRule bool) (string, error) {
	setName, err := nftGeoSetName(cc)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for i := 0; i < len(cidrs); i += nftChunk {
		end := i + nftChunk
		if end > len(cidrs) {
			end = len(cidrs)
		}
		fmt.Fprintf(&b, "add element %s %s %s { %s }\n", nftFamily, nftTable, setName, strings.Join(cidrs[i:end], ", "))
	}
	if addRule {
		fmt.Fprintf(&b, `add rule %s %s geo ip saddr @%s drop comment "%s%s"`+"\n", nftFamily, nftTable, setName, nftGeoKeyPrefix, strings.ToLower(cc))
	}
	return b.String(), nil
}

// nftGeoReplaceScript builds the atomic country-set replace transaction:
// create (idempotent) + flush + repopulate, optionally followed by the one
// DROP rule that references the set. addRule=false is used when the rule
// already exists (idempotent ApplyRule-style check done by the caller).
// It is exactly nftGeoSetupScript + nftGeoElementsScript concatenated — kept
// as one atomic `nft -f -` transaction in the common case; backend_nft.go
// falls back to issuing the two halves separately only on error.
func nftGeoReplaceScript(cc string, cidrs []string, addRule bool) (string, error) {
	setup, err := nftGeoSetupScript(cc)
	if err != nil {
		return "", err
	}
	elems, err := nftGeoElementsScript(cc, cidrs, addRule)
	if err != nil {
		return "", err
	}
	return setup + elems, nil
}

// nftGeoRemoveScript deletes the country's DROP rule (if handle != 0) and its
// set. handle 0 means no rule was ever added (e.g. GeoSupported but never
// enforced) — only the set delete is issued.
func nftGeoRemoveScript(cc string, handle int) (string, error) {
	setName, err := nftGeoSetName(cc)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if handle != 0 {
		fmt.Fprintf(&b, "delete rule %s %s geo handle %d\n", nftFamily, nftTable, handle)
	}
	fmt.Fprintf(&b, "delete set %s %s %s\n", nftFamily, nftTable, setName)
	return b.String(), nil
}

// nftProtectedScript rebuilds the protected4/protected6 sets from scratch:
// flush, then repopulate only if non-empty (an empty protected list means no
// add element line, not an add of nothing).
func nftProtectedScript(v4, v6 []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "flush set %s %s protected4\n", nftFamily, nftTable)
	if len(v4) > 0 {
		fmt.Fprintf(&b, "add element %s %s protected4 { %s }\n", nftFamily, nftTable, strings.Join(v4, ", "))
	}
	fmt.Fprintf(&b, "flush set %s %s protected6\n", nftFamily, nftTable)
	if len(v6) > 0 {
		fmt.Fprintf(&b, "add element %s %s protected6 { %s }\n", nftFamily, nftTable, strings.Join(v6, ", "))
	}
	return b.String()
}
