package firewall

import (
	"net/netip"
	"sort"
	"time"
)

// localBan is a Defensia-originated temp ban not driven by the panel list
// (e.g. a local SSH-session counter-ban) that the CSF pass planner must also
// apply directly, even before the panel's own ban list catches up. It gets a
// grace period (csfLocalGrace): if the panel never adopts the same IP into
// its own desired list within that window, the local entry is let go.
type localBan struct {
	Reason  string
	AddedAt time.Time
}

// passInput is everything one CSF reconcile pass needs to decide what to do.
// Pure: no I/O, no exec, no CSF CLI calls — csf_tempban.go/csf_banconf.go/
// guard.go already did the reading; executor_csf.go does the writing.
type passInput struct {
	Now         time.Time
	Desired     []DesiredBan
	Local       map[string]localBan
	Temp        TempBanList
	Conf        csfBanConf
	Backoff     map[string]time.Time
	MonitorMode bool
	Guard       func(string) (bool, string)
}

// op is one CSF CLI operation the worker must perform.
type op struct {
	Kind   string // "add" | "remove"
	IP     string
	Reason string
	TTL    time.Duration
	Renew  bool
}

// passPlan is the pure output of one planCSFPass call.
type passPlan struct {
	Ops          []op
	Deferred     int
	DeferredIPv6 int
	Covered      int
	Skipped      map[string]string
	Conflicts    []string
	Budget       int
}

// finiteRenewMargin: for a desired ban with a finite expiry, only renew an
// existing CSF entry when the new TTL would extend coverage by more than
// this margin — a 30-minute difference is noise, a 2-hour one is real
// (measured thresholds from the plan's own acceptance tests).
const finiteRenewMargin = time.Hour

type desiredEntry struct {
	IP        string
	Reason    string
	BanCount  int
	PanelID   int64
	ExpiresAt *time.Time
	isLocal   bool
}

// csfTTLFor computes the CSF -td TTL for a desired expiry, clamped to
// [csfMinTTL, csfMaxTTL]. nil (permanent panel ban) maps to csfMaxTTL — CSF
// temp bans have no true "forever", so a permanent ban is just renewed
// before it would ever lapse (see the renew rule below).
func csfTTLFor(expiresAt *time.Time, now time.Time) time.Duration {
	if expiresAt == nil {
		return csfMaxTTL
	}
	d := expiresAt.Sub(now)
	if d < csfMinTTL {
		d = csfMinTTL
	}
	if d > csfMaxTTL {
		d = csfMaxTTL
	}
	return d
}

func planCSFPass(in passInput) passPlan {
	plan := passPlan{Skipped: map[string]string{}}

	// --- Build lookup maps from the current CSF state -----------------
	oursByIP := map[string]TempBanEntry{}
	foreignByIP := map[string]bool{}
	for _, e := range in.Temp.Entries {
		if e.Ours {
			oursByIP[e.IP] = e
		} else {
			foreignByIP[e.IP] = true
		}
	}
	totalCount := len(in.Temp.Entries)
	oursCount := len(oursByIP)

	// --- Build the desired-by-IP map: panel bans + still-in-grace local bans
	desiredByIP := map[string]desiredEntry{}
	for _, b := range in.Desired {
		b := b
		desiredByIP[b.IP] = desiredEntry{
			IP: b.IP, Reason: b.Reason, BanCount: b.BanCount,
			PanelID: b.PanelID, ExpiresAt: b.ExpiresAt,
		}
	}
	for ip, lb := range in.Local {
		if _, exists := desiredByIP[ip]; exists {
			continue // panel already covers this IP; local entry is subsumed
		}
		if in.Now.Sub(lb.AddedAt) < csfLocalGrace {
			desiredByIP[ip] = desiredEntry{IP: ip, Reason: lb.Reason, isLocal: true}
		}
		// else: past grace and the panel never adopted it — fall through and
		// let the removal pass below drop it if it is present as ours.
	}

	// --- Removals: any "ours" entry no longer desired -------------------
	var removalOps []op
	for ip := range oursByIP {
		if _, desired := desiredByIP[ip]; desired {
			continue
		}
		if foreignByIP[ip] {
			plan.Conflicts = append(plan.Conflicts, ip)
			continue
		}
		removalOps = append(removalOps, op{Kind: "remove", IP: ip})
	}
	sort.Slice(removalOps, func(i, j int) bool { return removalOps[i].IP < removalOps[j].IP })

	// --- Renewals: desired IPs that already have an "ours" entry --------
	var renewalOps []op
	for ip, d := range desiredByIP {
		existing, ok := oursByIP[ip]
		if !ok {
			continue
		}
		delete(desiredByIP, ip) // handled either way; not an add candidate

		remaining := existing.ExpiresAt.Sub(in.Now)
		var newTTL time.Duration
		if d.isLocal {
			newTTL = csfLocalTTL
		} else {
			newTTL = csfTTLFor(d.ExpiresAt, in.Now)
		}

		renew := false
		if newTTL > remaining {
			if !d.isLocal && d.ExpiresAt == nil {
				renew = remaining < csfRenewBelow
			} else {
				renew = newTTL-remaining > finiteRenewMargin
			}
		}
		if !renew {
			continue
		}
		renewalOps = append(renewalOps,
			op{Kind: "remove", IP: ip, Renew: true},
			op{Kind: "add", IP: ip, Reason: d.Reason, TTL: newTTL, Renew: true},
		)
	}

	if in.MonitorMode {
		renewalOps = nil
	}

	// --- Budget, recomputed after planned removals free slots -----------
	oursAfter := oursCount - len(removalOps)
	totalAfter := totalCount - len(removalOps)

	var budget int
	if in.Conf.TempLimit <= 0 {
		budget = csfMaxDefensiaTemp - oursAfter
	} else {
		reserve := csfReserveMin
		if r := int(float64(in.Conf.TempLimit)*csfReserveRatio + 0.5); r > reserve {
			reserve = r
		}
		fromLimit := in.Conf.TempLimit - totalAfter - reserve
		fromCap := csfMaxDefensiaTemp - oursAfter
		budget = fromLimit
		if fromCap < budget {
			budget = fromCap
		}
	}
	if budget < 0 {
		budget = 0
	}
	plan.Budget = budget

	// --- Add candidates: remaining desired IPs with no existing ours entry
	var candidates []desiredEntry
	if !in.MonitorMode {
		for ip, d := range desiredByIP {
			if addr, err := netip.ParseAddr(ip); err == nil && addr.Is6() && !in.Conf.IPv6 {
				plan.DeferredIPv6++
				continue
			}
			if in.Guard != nil {
				if ok, reason := in.Guard(ip); !ok {
					plan.Skipped[ip] = reason
					continue
				}
			}
			if foreignByIP[ip] {
				plan.Covered++
				continue
			}
			if until, has := in.Backoff[ip]; has && in.Now.Before(until) {
				continue
			}
			candidates = append(candidates, d)
		}
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.isLocal != b.isLocal {
			return a.isLocal
		}
		aPerm, bPerm := a.ExpiresAt == nil, b.ExpiresAt == nil
		if aPerm != bPerm {
			return aPerm
		}
		if a.BanCount != b.BanCount {
			return a.BanCount > b.BanCount
		}
		return a.PanelID > b.PanelID
	})

	// --- Ops-per-pass cap: removals, then renewals, then adds ------------
	usedOps := len(removalOps) + len(renewalOps)
	remainingOps := csfMaxOpsPerPass - usedOps
	if remainingOps < 0 {
		remainingOps = 0
	}
	addBudget := budget
	if remainingOps < addBudget {
		addBudget = remainingOps
	}
	if addBudget < 0 {
		addBudget = 0
	}

	var addOps []op
	for i, d := range candidates {
		if i >= addBudget {
			plan.Deferred++
			continue
		}
		var ttl time.Duration
		if d.isLocal {
			ttl = csfLocalTTL
		} else {
			ttl = csfTTLFor(d.ExpiresAt, in.Now)
		}
		addOps = append(addOps, op{Kind: "add", IP: d.IP, Reason: d.Reason, TTL: ttl})
	}

	plan.Ops = append(plan.Ops, removalOps...)
	plan.Ops = append(plan.Ops, renewalOps...)
	plan.Ops = append(plan.Ops, addOps...)

	return plan
}
