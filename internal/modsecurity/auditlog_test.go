package modsecurity

import "testing"

func rule(id string, tags ...string) RuleMatch {
	return RuleMatch{ID: id, Tags: tags}
}

// TestClassifyProductionCombos uses the rule-ID combinations actually observed
// in production, where protocol-enforcement noise on "/" was being reported as
// web_exploit and inflating the exploitation metrics ~1.9x.
func TestClassifyProductionCombos(t *testing.T) {
	tests := []struct {
		name        string
		rules       []RuleMatch
		wantType    string
		wantEnforce bool
	}{
		// ── The noise that caused the bug ──
		{
			name:        "missing Host header on / (top offender, 25866 hits)",
			rules:       []RuleMatch{rule("920280", "attack-protocol"), rule("980170")},
			wantType:    "modsecurity_block",
			wantEnforce: true,
		},
		{
			name:        "conflicting Connection header (22105 hits)",
			rules:       []RuleMatch{rule("920210", "attack-protocol")},
			wantType:    "modsecurity_block",
			wantEnforce: true,
		},
		{
			name:        "numeric Host header with anomaly meta rules",
			rules:       []RuleMatch{rule("920350", "attack-protocol"), rule("949110"), rule("980130")},
			wantType:    "modsecurity_block",
			wantEnforce: true,
		},
		{
			name:        "method not allowed by policy is not an exploit",
			rules:       []RuleMatch{rule("911100", "attack-generic"), rule("920350", "attack-protocol")},
			wantType:    "modsecurity_block",
			wantEnforce: true,
		},

		// ── Real attacks that were being masked by a leading 920 rule ──
		{
			name:        "LFI behind protocol noise (1016 masked in prod)",
			rules:       []RuleMatch{rule("920280", "attack-protocol"), rule("930110", "attack-lfi")},
			wantType:    "path_traversal",
			wantEnforce: false,
		},
		{
			name:        "SQLi must win over protocol enforcement",
			rules:       []RuleMatch{rule("920210", "attack-protocol"), rule("942100", "attack-sqli"), rule("949110")},
			wantType:    "sql_injection",
			wantEnforce: false,
		},
		{
			name:        "XSS must win over protocol enforcement",
			rules:       []RuleMatch{rule("920350", "attack-protocol"), rule("941100", "attack-xss")},
			wantType:    "xss_attempt",
			wantEnforce: false,
		},
		{
			name:        "PHP injection outranks method enforcement",
			rules:       []RuleMatch{rule("911100", "attack-generic"), rule("933100", "attack-injection-php")},
			wantType:    "rce_attempt",
			wantEnforce: false,
		},

		// ── 920 vs 921: same tag, opposite meaning ──
		{
			name:        "request smuggling is a real attack despite attack-protocol tag",
			rules:       []RuleMatch{rule("921110", "attack-protocol")},
			wantType:    "header_injection",
			wantEnforce: false,
		},

		// ── 934 generic really is exploitation ──
		{
			name:        "generic application attack stays web_exploit",
			rules:       []RuleMatch{rule("934100", "attack-generic")},
			wantType:    "web_exploit",
			wantEnforce: false,
		},

		// ── Defensia's own inline rules (no tags at all) ──
		{
			name:        "Defensia SQLi rule no longer falls through to modsecurity_block",
			rules:       []RuleMatch{rule("9910001")},
			wantType:    "sql_injection",
			wantEnforce: false,
		},
		{
			name:        "Defensia Spring4Shell rule",
			rules:       []RuleMatch{rule("9910013")},
			wantType:    "web_exploit",
			wantEnforce: false,
		},
		{
			name:        "Defensia rule outranks co-firing protocol noise",
			rules:       []RuleMatch{rule("920280", "attack-protocol"), rule("9910004")},
			wantType:    "path_traversal",
			wantEnforce: false,
		},

		// ── Meta rules must never classify on their own ──
		{
			name:        "only meta rules falls back to the tag mapping",
			rules:       []RuleMatch{rule("949110"), rule("980130")},
			wantType:    "modsecurity_block",
			wantEnforce: false,
		},
		{
			name:        "no rules at all",
			rules:       nil,
			wantType:    "modsecurity_block",
			wantEnforce: false,
		},
		{
			name:        "unrecognised rule ID falls back to its tag",
			rules:       []RuleMatch{rule("123456", "attack-sqli")},
			wantType:    "sql_injection",
			wantEnforce: false,
		},

		// ── Comodo cWAF (cPanel/DirectAdmin default rule set) ──
		{
			name:        "Comodo /.env probe, highest-volume rule (3066 hits in prod)",
			rules:       []RuleMatch{rule("210492")},
			wantType:    "env_probe",
			wantEnforce: false,
		},
		{
			name:        "Comodo file-extension policy is enforcement, not an attack (666 hits)",
			rules:       []RuleMatch{rule("210730")},
			wantType:    "modsecurity_block",
			wantEnforce: true,
		},
		{
			name:        "Comodo WordPress CVE-2017-5487 disclosure (1971 hits)",
			rules:       []RuleMatch{rule("225170")},
			wantType:    "config_probe",
			wantEnforce: false,
		},
		{
			name:        "Comodo XML-RPC attack CVE-2013-0235 (1176 hits)",
			rules:       []RuleMatch{rule("240335")},
			wantType:    "xmlrpc_abuse",
			wantEnforce: false,
		},
		{
			name:        "Comodo unidentified WP rule stays in the generic bucket",
			rules:       []RuleMatch{rule("222212")},
			wantType:    "modsecurity_block",
			wantEnforce: false,
		},
		{
			name:        "Comodo meta rule alone never classifies",
			rules:       []RuleMatch{rule("200004")},
			wantType:    "modsecurity_block",
			wantEnforce: false,
		},
		{
			name:        "unmapped Comodo ID degrades to the generic bucket, not unknown",
			rules:       []RuleMatch{rule("299999")},
			wantType:    "modsecurity_block",
			wantEnforce: false,
		},
		{
			name:        "Comodo Struts RCE outranks its own enforcement rule",
			rules:       []RuleMatch{rule("210730"), rule("243930")},
			wantType:    "rce_attempt",
			wantEnforce: false,
		},

		// ── Mixed vendors: attack class decides, never the vendor ──
		{
			name:        "the only mixed combo seen in prod resolves to enforcement",
			rules:       []RuleMatch{rule("920100", "attack-protocol"), rule("920350", "attack-protocol"), rule("200004"), rule("980170")},
			wantType:    "modsecurity_block",
			wantEnforce: true,
		},
		{
			name:        "Comodo SQLi beats CRS protocol enforcement",
			rules:       []RuleMatch{rule("920280", "attack-protocol"), rule("220150")},
			wantType:    "sql_injection",
			wantEnforce: false,
		},
		{
			name:        "CRS SQLi beats Comodo enforcement — symmetric, no vendor bias",
			rules:       []RuleMatch{rule("210730"), rule("942100", "attack-sqli")},
			wantType:    "sql_injection",
			wantEnforce: false,
		},
		{
			name:        "CRS SQLi beats a Defensia scanner rule: class over vendor",
			rules:       []RuleMatch{rule("9910014"), rule("942100", "attack-sqli")},
			wantType:    "sql_injection",
			wantEnforce: false,
		},
		{
			name:        "at equal class the exact-ID rule wins the tie-break",
			rules:       []RuleMatch{rule("942100", "attack-sqli"), rule("9910001")},
			wantType:    "sql_injection",
			wantEnforce: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := &AuditEntry{Rules: tc.rules}
			gotType, gotEnforce := e.Classify()
			if gotType != tc.wantType {
				t.Errorf("Classify() type = %q, want %q", gotType, tc.wantType)
			}
			if gotEnforce != tc.wantEnforce {
				t.Errorf("Classify() isEnforcement = %v, want %v", gotEnforce, tc.wantEnforce)
			}
		})
	}
}

// TestNoEnforcementNoiseReachesExploitationBuckets guards the regression
// directly: none of the enforcement/reputation families may ever produce an
// event type that the panel counts as exploitation.
func TestNoEnforcementNoiseReachesExploitationBuckets(t *testing.T) {
	exploitationTypes := map[string]bool{
		"env_probe": true, "config_probe": true, "rce_attempt": true,
		"path_traversal": true, "header_injection": true, "shellshock": true,
		"ssrf_attempt": true, "web_exploit": true,
	}

	for fam := range enforcementFamilies {
		eventType := crsFamilyEventType[fam]
		if exploitationTypes[eventType] {
			t.Errorf("enforcement family %s maps to exploitation type %q", fam, eventType)
		}
	}
	for id := range comodoEnforcementRules {
		eventType := comodoRuleEventType[id]
		if exploitationTypes[eventType] {
			t.Errorf("Comodo enforcement rule %s maps to exploitation type %q", id, eventType)
		}
	}
}

// TestRankingIsByClassNotVendor is the structural guarantee behind the design:
// an event type's rank must not depend on which vendor's table produced it, so
// the same class from two vendors always scores the same.
func TestRankingIsByClassNotVendor(t *testing.T) {
	// Every table feeds the single class-keyed rank map, so a type appearing in
	// more than one vendor table cannot be ranked differently per vendor.
	for _, table := range []map[string]string{crsFamilyEventType, defensiaRuleEventType, comodoRuleEventType} {
		for key, eventType := range table {
			if eventType == "" {
				continue // meta rule
			}
			if _, ranked := eventClassRank[eventType]; !ranked {
				t.Errorf("%s maps to %q which has no entry in eventClassRank", key, eventType)
			}
		}
	}

	// A grave class must outrank the generic bucket regardless of origin.
	if eventClassRank["sql_injection"] <= eventClassRank["modsecurity_block"] {
		t.Error("sql_injection must outrank modsecurity_block")
	}
	if eventClassRank["rce_attempt"] <= eventClassRank["scanner_detected"] {
		t.Error("rce_attempt must outrank scanner_detected")
	}
}

// TestClassifyTypesArePanelAccepted keeps the mappings inside the panel's
// accepted event-type allowlist. An unknown type is rejected with a 422 and the
// event is lost, so a typo here would silently drop detections.
func TestClassifyTypesArePanelAccepted(t *testing.T) {
	// Mirrors the "events.*.type" in: rule in the panel's EventController.
	accepted := map[string]bool{}
	for _, t := range []string{
		"brute_force", "port_scan", "flood", "integrity_change", "zombie_processes",
		"web_exploit", "wp_bruteforce", "xmlrpc_abuse", "sql_injection", "path_traversal",
		"scanner_detected", "404_flood", "geoblock", "env_probe", "config_probe",
		"rce_attempt", "shellshock", "xss_attempt", "ssrf_attempt", "web_shell",
		"header_injection", "honeypot_triggered", "modsecurity_block", "modsecurity_enabled",
		"cms_bruteforce", "sigma_detection", "system_audit",
	} {
		accepted[t] = true
	}

	for fam, eventType := range crsFamilyEventType {
		if eventType == "" {
			continue // meta rule, never emitted
		}
		if !accepted[eventType] {
			t.Errorf("CRS family %s maps to %q which the panel does not accept", fam, eventType)
		}
	}
	for id, eventType := range defensiaRuleEventType {
		if !accepted[eventType] {
			t.Errorf("Defensia rule %s maps to %q which the panel does not accept", id, eventType)
		}
	}
	for id, eventType := range comodoRuleEventType {
		if eventType == "" {
			continue // meta rule, never emitted
		}
		if !accepted[eventType] {
			t.Errorf("Comodo rule %s maps to %q which the panel does not accept", id, eventType)
		}
	}
	for eventType := range eventClassRank {
		if !accepted[eventType] {
			t.Errorf("eventClassRank ranks %q which the panel does not accept", eventType)
		}
	}
}

// TestResolveSeverity covers severity by outcome: a probe the server refused is
// frustrated reconnaissance, one that returned 2xx is a disclosure.
func TestResolveSeverity(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  string
		ruleSev     string
		eventType   string
		enforcement bool
		want        string
	}{
		{"enforcement is pinned to info regardless of vendor severity", "403", "CRITICAL", "modsecurity_block", true, "info"},

		// Probe classes: the outcome decides, not Comodo's blanket CRITICAL.
		{"blocked /.env probe is frustrated recon", "403", "CRITICAL", "env_probe", false, "warning"},
		{"missing /.env probe is frustrated recon", "404", "CRITICAL", "env_probe", false, "warning"},
		{"served /.env probe is a real disclosure", "200", "CRITICAL", "env_probe", false, "critical"},
		{"served config probe is a real disclosure", "200", "WARNING", "config_probe", false, "critical"},
		{"206 partial content still counts as served", "206", "NOTICE", "config_probe", false, "critical"},
		{"redirected probe got nothing", "302", "CRITICAL", "config_probe", false, "warning"},
		{"server error probe got nothing", "500", "CRITICAL", "env_probe", false, "warning"},

		// Without a usable status code we must not invent an outcome.
		{"absent status code falls back to the rule severity", "", "CRITICAL", "env_probe", false, "critical"},
		{"unparseable status code falls back to the rule severity", "abc", "WARNING", "env_probe", false, "warning"},

		// LFI is rated the same way: the WAF stopping it is what decides.
		{"blocked LFI is frustrated recon", "403", "CRITICAL", "path_traversal", false, "warning"},
		{"missing LFI target is frustrated recon", "404", "CRITICAL", "path_traversal", false, "warning"},
		{"served /etc/passwd is the same leak as a served /.env", "200", "CRITICAL", "path_traversal", false, "critical"},

		// Non-probe classes are untouched by the outcome rule.
		{"SQLi keeps its rule severity even when blocked", "403", "CRITICAL", "sql_injection", false, "critical"},
		{"RCE keeps its rule severity when served", "200", "ERROR", "rce_attempt", false, "high"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := &AuditEntry{
				StatusCode: tc.statusCode,
				Rules:      []RuleMatch{{ID: "999999", Severity: tc.ruleSev}},
			}
			if got := e.ResolveSeverity(tc.eventType, tc.enforcement); got != tc.want {
				t.Errorf("ResolveSeverity(%q, %v) with status %q = %q, want %q",
					tc.eventType, tc.enforcement, tc.statusCode, got, tc.want)
			}
		})
	}
}

// TestProbeClassesAreRanked guards against a probe class being added here
// without a place in the rank table.
func TestProbeClassesAreRanked(t *testing.T) {
	for class := range probeClasses {
		if _, ok := eventClassRank[class]; !ok {
			t.Errorf("probe class %q has no entry in eventClassRank", class)
		}
	}
}

func TestCrsRuleFamily(t *testing.T) {
	cases := map[string]string{
		"920280":  "920",
		"942100":  "942",
		"9910001": "", // Defensia's own 7-digit IDs are not CRS families
		"":        "",
		"92028":   "",
	}
	for in, want := range cases {
		if got := crsRuleFamily(in); got != want {
			t.Errorf("crsRuleFamily(%q) = %q, want %q", in, got, want)
		}
	}
}
