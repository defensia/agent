package firewall

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ErrNoBackend is returned when no firewall backend can enforce bans on this host.
var ErrNoBackend = errors.New("no usable firewall backend (ipset, nftables and iptables all unavailable)")

// BanEntry is one ban to apply. TTL 0 = no kernel timeout (panel-driven expiry).
type BanEntry struct {
	IP  string
	TTL time.Duration
}

// Backend is one way of enforcing bans, rules and country blocks.
type Backend interface {
	Name() string                        // "ipset" | "nftables" | "iptables" | "none"
	Probe() error                        // functional check; nil = usable on this host
	Ensure() (recreated bool, err error) // idempotent: sets/tables/base rules; safe to call every sync
	Ban(ip net.IP, ttl time.Duration) error
	Unban(ip net.IP) error
	BanBatch(entries []BanEntry) (applied int, err error) // entries pre-validated; split by family inside
	Members() (v4, v6 []string, err error)                // current kernel ban entries
	Count() int
	Capacity() int
	ApplyRule(spec RuleSpec) error
	RemoveRule(spec RuleSpec) error
	ListRules() ([]ParsedRule, error)
	GeoSupported() bool
	GeoReplace(cc string, cidrs []string) (loaded int, err error)
	GeoRemove(cc string) error
	EnsureAccept(ips []string) error // protected IPs, evaluated before bans/geo
}

// backendOrder is the detection order.
var backendOrder = []string{"ipset", "nftables", "iptables"}

// newBackend returns the Backend implementation for name, or nil if unknown.
func newBackend(name string) Backend {
	switch name {
	case "ipset":
		return ipsetBackend{}
	case "nftables":
		return nftSingleton
	case "iptables":
		return iptablesBackend{}
	default:
		return nil
	}
}

var (
	selectMu sync.Mutex // serialises selection

	stateMu  sync.RWMutex // guards active/selected/reason
	active   Backend      = noneBackend{}
	selected bool
	reason   string

	generation atomic.Uint64
	notApplied atomic.Uint64
)

// resetBackendState is an unexported test helper: resets all package-level
// selection state to its zero value.
func resetBackendState() {
	stateMu.Lock()
	active = noneBackend{}
	selected = false
	reason = ""
	stateMu.Unlock()
	generation.Store(0)
	notApplied.Store(0)
}

// Reselect runs detection now and returns the selected mode.
func Reselect() string {
	selectMu.Lock()
	defer selectMu.Unlock()

	forced := strings.ToLower(strings.TrimSpace(os.Getenv("DEFENSIA_FIREWALL_BACKEND")))

	var names []string
	switch {
	case forced == "none":
		names = nil
	case forced == "":
		names = backendOrder
	default:
		found := false
		for _, n := range backendOrder {
			if n == forced {
				found = true
				break
			}
		}
		if found {
			names = []string{forced}
		} else {
			log.Printf("[firewall] ignoring unknown DEFENSIA_FIREWALL_BACKEND=%q", forced)
			names = backendOrder
		}
	}

	var causes []string
	var picked Backend
	var pickedName string

	for _, name := range names {
		b := newBackend(name)
		if b == nil {
			continue
		}
		if err := b.Probe(); err != nil {
			causes = append(causes, name+": "+err.Error())
			continue
		}
		if _, err := b.Ensure(); err != nil {
			causes = append(causes, name+": ensure: "+err.Error())
			continue
		}
		picked = b
		pickedName = name
		break
	}

	var newReason string
	if picked == nil {
		picked = noneBackend{}
		pickedName = "none"
		newReason = "no usable firewall backend: " + strings.Join(causes, "; ")
		log.Printf("[firewall] CRITICAL: %s — bans will NOT be enforced", newReason)
	} else {
		switch pickedName {
		case "ipset":
			log.Printf("[firewall] ipset detected — using ipset for bans + country blocks")
		case "nftables":
			log.Printf("[firewall] using nftables backend (table inet defensia)")
		case "iptables":
			log.Printf("[firewall] using iptables backend (limited capacity, no country blocks): %s", strings.Join(causes, "; "))
		}
	}

	stateMu.Lock()
	prevName := active.Name()
	wasSelected := selected
	active = picked
	reason = newReason
	selected = true
	stateMu.Unlock()

	if !wasSelected || prevName != pickedName {
		generation.Add(1)
	}

	return pickedName
}

// current returns the active backend, lazily selecting one if needed.
func current() Backend {
	stateMu.RLock()
	sel := selected
	b := active
	stateMu.RUnlock()
	if sel {
		return b
	}
	Reselect()
	stateMu.RLock()
	defer stateMu.RUnlock()
	return active
}

// Ensure re-asserts the active backend (idempotent); if none is active, it
// (re)runs detection. Returns ErrNoBackend if still none afterward.
func Ensure() error {
	b := current()
	if b.Name() == "none" {
		Reselect()
		b = current()
		if b.Name() == "none" {
			return ErrNoBackend
		}
		return nil
	}
	recreated, err := b.Ensure()
	if recreated {
		generation.Add(1)
	}
	if err != nil {
		log.Printf("[firewall] ensure %s failed: %v — re-running detection", b.Name(), err)
		Reselect()
		if current().Name() == "none" {
			return ErrNoBackend
		}
		return nil
	}
	return nil
}

// Mode returns the active backend's name.
func Mode() string { return current().Name() }

// Generation returns the current backend generation counter: it increments
// on any backend change (including a re-create of the same backend).
func Generation() uint64 { return generation.Load() }

// SelectionReason returns the human-readable reason none was selected, or
// "" when a real backend is active.
func SelectionReason() string {
	stateMu.RLock()
	defer stateMu.RUnlock()
	return reason
}

// NotAppliedBans returns the count of bans refused because no backend exists.
func NotAppliedBans() uint64 { return notApplied.Load() }

// BanIPFor bans ip with an optional kernel ttl (0 = no timeout). Performs the
// same validation BanIP always has (parse + isSafeIP).
func BanIPFor(ip string, ttl time.Duration) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	if isSafeIP(parsed) {
		return fmt.Errorf("refusing to ban safe IP: %s", ip)
	}

	b := current()
	if b.Name() == "none" {
		notApplied.Add(1)
		return fmt.Errorf("ban %s: %w", ip, ErrNoBackend)
	}
	return b.Ban(parsed, ttl)
}

// ApplyBanEntries applies entries (pre-filtered elsewhere exactly like
// ApplyBans does today: invalid/safe IPs are skipped, not errored) and
// returns the count actually applied to the kernel.
func ApplyBanEntries(entries []BanEntry) int {
	valid := make([]BanEntry, 0, len(entries))
	for _, e := range entries {
		parsed := net.ParseIP(e.IP)
		if parsed == nil || isSafeIP(parsed) {
			continue
		}
		valid = append(valid, e)
	}

	b := current()
	if b.Name() == "none" {
		notApplied.Add(uint64(len(valid)))
		return 0
	}

	applied, err := b.BanBatch(valid)
	if err != nil {
		log.Printf("[firewall] error applying ban batch (%d entries): %v", len(valid), err)
	}
	return applied
}

// noneBackend is the Backend used when nothing is usable: every mutating
// method returns ErrNoBackend, loudly, instead of failing silently.
type noneBackend struct{}

func (noneBackend) Name() string                                      { return "none" }
func (noneBackend) Probe() error                                      { return ErrNoBackend }
func (noneBackend) Ensure() (bool, error)                             { return false, ErrNoBackend }
func (noneBackend) Ban(ip net.IP, ttl time.Duration) error            { return ErrNoBackend }
func (noneBackend) Unban(ip net.IP) error                             { return ErrNoBackend }
func (noneBackend) BanBatch(entries []BanEntry) (int, error)          { return 0, ErrNoBackend }
func (noneBackend) Members() ([]string, []string, error)              { return nil, nil, nil }
func (noneBackend) Count() int                                        { return 0 }
func (noneBackend) Capacity() int                                     { return 0 }
func (noneBackend) ApplyRule(spec RuleSpec) error                     { return ErrNoBackend }
func (noneBackend) RemoveRule(spec RuleSpec) error                    { return ErrNoBackend }
func (noneBackend) ListRules() ([]ParsedRule, error)                  { return nil, ErrNoBackend }
func (noneBackend) GeoSupported() bool                                { return false }
func (noneBackend) GeoReplace(cc string, cidrs []string) (int, error) { return 0, ErrNoBackend }
func (noneBackend) GeoRemove(cc string) error                         { return ErrNoBackend }
func (noneBackend) EnsureAccept(ips []string) error                   { return ErrNoBackend }
