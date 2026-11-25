package firewall

import (
	"log"
	"net/netip"
)

// Seams onto the Phase 17 firewall API (backend.go / iptables.go). Tests
// replace these directly; production leaves them pointed at the real
// functions. Deliberately backend-agnostic: nothing here is ipset-specific,
// it works identically on ipset, nftables, iptables and none.
var (
	applyBanEntriesFn  = ApplyBanEntries
	cleanupStaleBansFn = CleanupStaleBans
	banIPFn            = BanIP
	unbanIPFn          = UnbanIP
	// banIPForFn/generationFn are used only by executor_migrate.go's
	// migrateToDefensia (make-before-break csf->defensia migration, with a
	// Generation() guard against the backend being recreated mid-flight).
	banIPForFn   = BanIPFor
	generationFn = Generation
	// csfPausedFn wraps Phase 15's CSFPaused(): an emergency can be
	// triggered either by the panel (SyncInput.Emergency) or by the agent's
	// own CSF pause, and both must force the defensia path with zero CSF
	// commands.
	csfPausedFn = CSFPaused
)

var banMembersLoggedOnce bool

// banMembersFn returns every IP currently banned on the active Defensia
// backend, canonicalised. A Members() error is logged once and reported as
// an empty map — callers (the CSF worker's confirm step) must treat an
// empty map as "keep everything", never as "nothing is banned anywhere",
// since the two look identical but have opposite safety implications.
var banMembersFn = func() map[string]bool {
	v4, v6, err := current().Members()
	if err != nil {
		if !banMembersLoggedOnce {
			banMembersLoggedOnce = true
			log.Printf("[firewall] executor: cannot list backend members: %v", err)
		}
		return map[string]bool{}
	}

	out := make(map[string]bool, len(v4)+len(v6))
	for _, m := range append(v4, v6...) {
		if addr, err := netip.ParseAddr(m); err == nil {
			out[addr.Unmap().String()] = true
		} else {
			out[m] = true
		}
	}
	return out
}
