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
}

// TestEveryMappedFamilyHasARank ensures a new family cannot be added to the
// type map without a rank, which would silently give it rank 0 and let any
// other finding outrank it.
func TestEveryMappedFamilyHasARank(t *testing.T) {
	for fam, eventType := range crsFamilyEventType {
		if eventType == "" {
			continue // meta rules are intentionally rankless
		}
		if _, ok := crsFamilyRank[fam]; !ok {
			t.Errorf("CRS family %s has an event type but no rank", fam)
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
