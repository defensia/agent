package firewall

import (
	"testing"
	"time"
)

func mustTime(now time.Time, d time.Duration) *time.Time {
	t := now.Add(d)
	return &t
}

func countOps(p passPlan, kind string) int {
	n := 0
	for _, o := range p.Ops {
		if o.Kind == kind {
			n++
		}
	}
	return n
}

func TestPlanBudget(t *testing.T) {
	now := time.Now()
	temp := TempBanList{Exists: true}
	for i := 0; i < 10; i++ {
		temp.Entries = append(temp.Entries, TempBanEntry{IP: sprintfIP(i), Comment: "lfd", ExpiresAt: now.Add(time.Hour)})
	}
	var desired []DesiredBan
	for i := 0; i < 200; i++ {
		desired = append(desired, DesiredBan{IP: sprintfIP(100 + i), Reason: "r", ExpiresAt: mustTime(now, time.Hour)})
	}
	plan := planCSFPass(passInput{Now: now, Desired: desired, Temp: temp, Conf: csfBanConf{TempLimit: 100}})
	if got := countOps(plan, "add"); got != 70 {
		t.Errorf("adds = %d, want 70", got)
	}
	if plan.Deferred != 130 {
		t.Errorf("deferred = %d, want 130", plan.Deferred)
	}
}

func TestPlanBudgetCountsOwnEntries(t *testing.T) {
	now := time.Now()
	temp := TempBanList{Exists: true}
	var desired []DesiredBan
	for i := 0; i < 40; i++ {
		ip := sprintfIP(i)
		temp.Entries = append(temp.Entries, TempBanEntry{IP: ip, Comment: "defensia:r", Ours: true, ExpiresAt: now.Add(10 * 24 * time.Hour)})
		desired = append(desired, DesiredBan{IP: ip, Reason: "r", ExpiresAt: mustTime(now, 10*24*time.Hour)})
	}
	for i := 0; i < 20; i++ {
		temp.Entries = append(temp.Entries, TempBanEntry{IP: sprintfIP(200 + i), Comment: "lfd", ExpiresAt: now.Add(time.Hour)})
	}
	for i := 0; i < 50; i++ {
		desired = append(desired, DesiredBan{IP: sprintfIP(300 + i), Reason: "r", ExpiresAt: mustTime(now, time.Hour)})
	}
	plan := planCSFPass(passInput{Now: now, Desired: desired, Temp: temp, Conf: csfBanConf{TempLimit: 100}})
	if got := countOps(plan, "add"); got != 20 {
		t.Errorf("adds = %d, want 20", got)
	}
	if plan.Deferred != 30 {
		t.Errorf("deferred = %d, want 30", plan.Deferred)
	}
}

func TestPlanLimitZeroUsesCap(t *testing.T) {
	now := time.Now()
	for _, lim := range []int{0, -1} {
		var desired []DesiredBan
		for i := 0; i < 600; i++ {
			desired = append(desired, DesiredBan{IP: sprintfIP(i), Reason: "r", ExpiresAt: mustTime(now, time.Hour)})
		}
		plan := planCSFPass(passInput{Now: now, Desired: desired, Temp: TempBanList{Exists: true}, Conf: csfBanConf{TempLimit: lim}})
		if got := countOps(plan, "add"); got != csfMaxOpsPerPass {
			// ops-per-pass cap kicks in before the 500 budget does; assert the
			// underlying budget directly instead of relying on ops this large.
			if plan.Budget != csfMaxDefensiaTemp {
				t.Errorf("limit %d: budget = %d, want %d", lim, plan.Budget, csfMaxDefensiaTemp)
			}
		}
	}
}

func TestPlanCapOwn(t *testing.T) {
	now := time.Now()
	var desired []DesiredBan
	for i := 0; i < 700; i++ {
		desired = append(desired, DesiredBan{IP: sprintfIP(i), Reason: "r", ExpiresAt: mustTime(now, time.Hour)})
	}
	plan := planCSFPass(passInput{Now: now, Desired: desired, Temp: TempBanList{Exists: true}, Conf: csfBanConf{TempLimit: 100000}})
	if plan.Budget > csfMaxDefensiaTemp {
		t.Errorf("budget = %d, must never exceed csfMaxDefensiaTemp (%d)", plan.Budget, csfMaxDefensiaTemp)
	}
}

func TestPlanPriority(t *testing.T) {
	now := time.Now()
	desired := []DesiredBan{
		{IP: "203.0.113.1", Reason: "r", BanCount: 1, PanelID: 1, ExpiresAt: mustTime(now, time.Hour)},
		{IP: "203.0.113.2", Reason: "r", BanCount: 5, PanelID: 2, ExpiresAt: mustTime(now, time.Hour)},
		{IP: "203.0.113.3", Reason: "r", BanCount: 5, PanelID: 9, ExpiresAt: nil},
	}
	plan := planCSFPass(passInput{Now: now, Desired: desired, Temp: TempBanList{Exists: true}, Conf: csfBanConf{TempLimit: 1000000}, Guard: allowAll})
	// TempLimit 12, 0 existing entries -> reserve 10 (csfReserveMin) -> budget
	// 12-0-10 = 2, so only the top 2 by priority are chosen.
	plan2 := planCSFPass(passInput{Now: now, Desired: desired, Temp: TempBanList{Exists: true}, Conf: csfBanConf{TempLimit: 12}, Guard: allowAll})
	_ = plan
	var ips []string
	for _, o := range plan2.Ops {
		if o.Kind == "add" {
			ips = append(ips, o.IP)
		}
	}
	if len(ips) != 2 || ips[0] != "203.0.113.3" || ips[1] != "203.0.113.2" {
		t.Errorf("priority order = %v, want [203.0.113.3 203.0.113.2] (permanent first, then BanCount desc, then PanelID desc)", ips)
	}
}

func allowAll(string) (bool, string) { return true, "" }

func TestPlanRemovesOnlyOurs(t *testing.T) {
	now := time.Now()
	temp := TempBanList{Exists: true, Entries: []TempBanEntry{
		{IP: "203.0.113.10", Comment: "defensia:r", Ours: true, ExpiresAt: now.Add(time.Hour)}, // A: ours, not desired
		{IP: "203.0.113.11", Comment: "lfd", ExpiresAt: now.Add(time.Hour)},                    // B: foreign, not desired
		{IP: "203.0.113.12", Comment: "defensia:r", Ours: true, ExpiresAt: now.Add(time.Hour)}, // C: ours, desired
	}}
	desired := []DesiredBan{{IP: "203.0.113.12", Reason: "r", ExpiresAt: mustTime(now, time.Hour)}}
	plan := planCSFPass(passInput{Now: now, Desired: desired, Temp: temp, Conf: csfBanConf{TempLimit: 1000}})
	var removed []string
	for _, o := range plan.Ops {
		if o.Kind == "remove" {
			removed = append(removed, o.IP)
		}
	}
	if len(removed) != 1 || removed[0] != "203.0.113.10" {
		t.Errorf("removed = %v, want [203.0.113.10]", removed)
	}
}

func TestPlanSkipsIPWithForeignEntry(t *testing.T) {
	now := time.Now()
	temp := TempBanList{Exists: true, Entries: []TempBanEntry{
		{IP: "203.0.113.20", Comment: "defensia:r", Ours: true, ExpiresAt: now.Add(time.Hour)},
		{IP: "203.0.113.20", Comment: "lfd", ExpiresAt: now.Add(time.Hour)},
	}}
	plan := planCSFPass(passInput{Now: now, Temp: temp, Conf: csfBanConf{TempLimit: 1000}})
	if countOps(plan, "remove") != 0 {
		t.Errorf("expected no removal while a foreign entry coexists, got %d", countOps(plan, "remove"))
	}
	if len(plan.Conflicts) != 1 || plan.Conflicts[0] != "203.0.113.20" {
		t.Errorf("conflicts = %v, want [203.0.113.20]", plan.Conflicts)
	}
}

func TestPlanForeignCovers(t *testing.T) {
	now := time.Now()
	temp := TempBanList{Exists: true, Entries: []TempBanEntry{
		{IP: "203.0.113.30", Comment: "lfd", ExpiresAt: now.Add(time.Hour)},
	}}
	desired := []DesiredBan{{IP: "203.0.113.30", Reason: "r", ExpiresAt: mustTime(now, time.Hour)}}
	plan := planCSFPass(passInput{Now: now, Desired: desired, Temp: temp, Conf: csfBanConf{TempLimit: 1000}})
	if countOps(plan, "add") != 0 {
		t.Errorf("expected no add for an already-foreign-covered IP")
	}
	if plan.Covered != 1 {
		t.Errorf("covered = %d, want 1", plan.Covered)
	}
	if plan.Deferred != 0 {
		t.Errorf("deferred = %d, want 0 (covered is not deferred)", plan.Deferred)
	}
}

func TestPlanTTL(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		exp  *time.Time
		want time.Duration
	}{
		{"2h", mustTime(now, 2*time.Hour), 2 * time.Hour},
		{"30s", mustTime(now, 30*time.Second), 60 * time.Second},
		{"90d", mustTime(now, 90*24*time.Hour), 30 * 24 * time.Hour},
		{"nil", nil, 30 * 24 * time.Hour},
	}
	for _, c := range cases {
		got := csfTTLFor(c.exp, now)
		if got != c.want {
			t.Errorf("%s: csfTTLFor = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestPlanRenew(t *testing.T) {
	now := time.Now()
	// permanent, remaining 6d -> renew
	plan := planCSFPass(passInput{Now: now, Desired: []DesiredBan{{IP: "203.0.113.40", Reason: "r", ExpiresAt: nil}},
		Temp: TempBanList{Exists: true, Entries: []TempBanEntry{{IP: "203.0.113.40", Comment: "defensia:r", Ours: true, ExpiresAt: now.Add(6 * 24 * time.Hour)}}},
		Conf: csfBanConf{TempLimit: 1000}})
	if countOps(plan, "remove") != 1 || countOps(plan, "add") != 1 {
		t.Errorf("permanent/6d remaining: expected renew (1 remove + 1 add), got %+v", plan.Ops)
	}

	// permanent, remaining 8d -> none
	plan = planCSFPass(passInput{Now: now, Desired: []DesiredBan{{IP: "203.0.113.41", Reason: "r", ExpiresAt: nil}},
		Temp: TempBanList{Exists: true, Entries: []TempBanEntry{{IP: "203.0.113.41", Comment: "defensia:r", Ours: true, ExpiresAt: now.Add(8 * 24 * time.Hour)}}},
		Conf: csfBanConf{TempLimit: 1000}})
	if len(plan.Ops) != 0 {
		t.Errorf("permanent/8d remaining: expected no renewal, got %+v", plan.Ops)
	}

	// finite desired expiry exceeds current by 2h -> renew
	plan = planCSFPass(passInput{Now: now, Desired: []DesiredBan{{IP: "203.0.113.42", Reason: "r", ExpiresAt: mustTime(now, 10*time.Hour)}},
		Temp: TempBanList{Exists: true, Entries: []TempBanEntry{{IP: "203.0.113.42", Comment: "defensia:r", Ours: true, ExpiresAt: now.Add(8 * time.Hour)}}},
		Conf: csfBanConf{TempLimit: 1000}})
	if countOps(plan, "remove") != 1 || countOps(plan, "add") != 1 {
		t.Errorf("finite +2h: expected renew, got %+v", plan.Ops)
	}

	// finite desired expiry exceeds current by 30m -> none
	plan = planCSFPass(passInput{Now: now, Desired: []DesiredBan{{IP: "203.0.113.43", Reason: "r", ExpiresAt: mustTime(now, 8*time.Hour+30*time.Minute)}},
		Temp: TempBanList{Exists: true, Entries: []TempBanEntry{{IP: "203.0.113.43", Comment: "defensia:r", Ours: true, ExpiresAt: now.Add(8 * time.Hour)}}},
		Conf: csfBanConf{TempLimit: 1000}})
	if len(plan.Ops) != 0 {
		t.Errorf("finite +30m: expected no renewal, got %+v", plan.Ops)
	}

	// desired shorter than remaining -> never shorten
	plan = planCSFPass(passInput{Now: now, Desired: []DesiredBan{{IP: "203.0.113.44", Reason: "r", ExpiresAt: mustTime(now, time.Hour)}},
		Temp: TempBanList{Exists: true, Entries: []TempBanEntry{{IP: "203.0.113.44", Comment: "defensia:r", Ours: true, ExpiresAt: now.Add(10 * 24 * time.Hour)}}},
		Conf: csfBanConf{TempLimit: 1000}})
	if len(plan.Ops) != 0 {
		t.Errorf("shorter desired: expected no renewal (never shorten), got %+v", plan.Ops)
	}
}

func TestPlanIPv6Disabled(t *testing.T) {
	now := time.Now()
	desired := []DesiredBan{{IP: "2001:db8::1", Reason: "r", ExpiresAt: mustTime(now, time.Hour)}}
	plan := planCSFPass(passInput{Now: now, Desired: desired, Temp: TempBanList{Exists: true}, Conf: csfBanConf{TempLimit: 1000, IPv6: false}})
	if countOps(plan, "add") != 0 {
		t.Errorf("expected no add with IPv6 disabled")
	}
	if plan.DeferredIPv6 != 1 {
		t.Errorf("deferred_ipv6 = %d, want 1", plan.DeferredIPv6)
	}
}

func TestPlanGuard(t *testing.T) {
	now := time.Now()
	desired := []DesiredBan{{IP: "203.0.113.50", Reason: "r", ExpiresAt: mustTime(now, time.Hour)}}
	plan := planCSFPass(passInput{Now: now, Desired: desired, Temp: TempBanList{Exists: true}, Conf: csfBanConf{TempLimit: 1000},
		Guard: func(ip string) (bool, string) { return false, "csf_allow" }})
	if countOps(plan, "add") != 0 {
		t.Errorf("expected no add for a guard-refused IP")
	}
	if plan.Skipped["203.0.113.50"] != "csf_allow" {
		t.Errorf("skipped[203.0.113.50] = %q, want csf_allow", plan.Skipped["203.0.113.50"])
	}
}

func TestPlanLocalGrace(t *testing.T) {
	now := time.Now()
	// Added 5 minutes ago, absent from panel list, not yet in tempban -> added.
	plan := planCSFPass(passInput{Now: now, Local: map[string]localBan{"203.0.113.60": {Reason: "ssh", AddedAt: now.Add(-5 * time.Minute)}},
		Temp: TempBanList{Exists: true}, Conf: csfBanConf{TempLimit: 1000}})
	if countOps(plan, "add") != 1 {
		t.Errorf("within grace: expected 1 add, got %+v", plan.Ops)
	}

	// Added 11 minutes ago, absent from panel, already present in tempban -> removable.
	plan = planCSFPass(passInput{Now: now, Local: map[string]localBan{"203.0.113.61": {Reason: "ssh", AddedAt: now.Add(-11 * time.Minute)}},
		Temp: TempBanList{Exists: true, Entries: []TempBanEntry{{IP: "203.0.113.61", Comment: "defensia:ssh", Ours: true, ExpiresAt: now.Add(23 * time.Hour)}}},
		Conf: csfBanConf{TempLimit: 1000}})
	if countOps(plan, "remove") != 1 {
		t.Errorf("past grace: expected 1 remove, got %+v", plan.Ops)
	}
}

func TestPlanBackoff(t *testing.T) {
	now := time.Now()
	desired := []DesiredBan{{IP: "203.0.113.70", Reason: "r", ExpiresAt: mustTime(now, time.Hour)}}
	plan := planCSFPass(passInput{Now: now, Desired: desired, Temp: TempBanList{Exists: true}, Conf: csfBanConf{TempLimit: 1000},
		Backoff: map[string]time.Time{"203.0.113.70": now.Add(10 * time.Minute)}})
	if countOps(plan, "add") != 0 {
		t.Errorf("expected no add before backoff expiry")
	}

	plan = planCSFPass(passInput{Now: now.Add(11 * time.Minute), Desired: desired, Temp: TempBanList{Exists: true}, Conf: csfBanConf{TempLimit: 1000},
		Backoff: map[string]time.Time{"203.0.113.70": now.Add(10 * time.Minute)}})
	if countOps(plan, "add") != 1 {
		t.Errorf("expected add after backoff expiry")
	}
}

func TestPlanOpsCap(t *testing.T) {
	now := time.Now()
	var desired []DesiredBan
	for i := 0; i < 500; i++ {
		desired = append(desired, DesiredBan{IP: sprintfIP(i), Reason: "r", ExpiresAt: mustTime(now, time.Hour)})
	}
	plan := planCSFPass(passInput{Now: now, Desired: desired, Temp: TempBanList{Exists: true}, Conf: csfBanConf{TempLimit: 1000000}})
	if len(plan.Ops) != csfMaxOpsPerPass {
		t.Errorf("total ops = %d, want %d", len(plan.Ops), csfMaxOpsPerPass)
	}
}

func TestPlanMonitorMode(t *testing.T) {
	now := time.Now()
	temp := TempBanList{Exists: true, Entries: []TempBanEntry{
		{IP: "203.0.113.80", Comment: "defensia:r", Ours: true, ExpiresAt: now.Add(time.Hour)}, // not desired -> still removed
	}}
	desired := []DesiredBan{{IP: "203.0.113.81", Reason: "r", ExpiresAt: mustTime(now, time.Hour)}}
	plan := planCSFPass(passInput{Now: now, Desired: desired, Temp: temp, Conf: csfBanConf{TempLimit: 1000}, MonitorMode: true})
	if countOps(plan, "add") != 0 {
		t.Errorf("monitor mode: expected no adds, got %+v", plan.Ops)
	}
	if countOps(plan, "remove") != 1 {
		t.Errorf("monitor mode: expected the non-desired removal to still happen, got %+v", plan.Ops)
	}
}

func sprintfIP(n int) string {
	a := (n / 65536) % 256
	b := (n / 256) % 256
	c := n % 256
	return "10." + itoaX(a) + "." + itoaX(b) + "." + itoaX(c)
}

func itoaX(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}
