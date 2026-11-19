package firewall

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// nftBackend implements Backend on top of nftables (table inet defensia).
// It never touches any other table, chain or set — that is how it coexists
// with other firewall daemons and CSF's own iptables-nft rules, which live
// elsewhere.
type nftBackend struct {
	mu            sync.Mutex
	rules         map[string]int // rule key (nftRuleKeyPrefix comment) -> handle in chain `rules`; nil = not loaded
	legacyCleaned bool           // best-effort legacy ipset->iptables rule cleanup, done once per process
}

// nftSingleton is the one nftBackend instance. It is returned by newBackend
// every time (never a fresh struct), so loadRules()'s cache and
// legacyCleaned survive across Reselect calls within the same process.
var nftSingleton = &nftBackend{}

func (b *nftBackend) Name() string       { return "nftables" }
func (b *nftBackend) Capacity() int      { return nftBanSetSize }
func (b *nftBackend) GeoSupported() bool { return true }

// Probe proves nf_tables actually works here (not just that the `nft` binary
// exists): version gate, then a real create/delete round-trip against a
// throwaway table (proves CAP_NET_ADMIN and a loaded nf_tables module).
func (b *nftBackend) Probe() error {
	if _, err := fwLookPath("nft"); err != nil {
		return fmt.Errorf("nft not in PATH: %w", err)
	}
	out, err := fwExec("nft", "--version")
	if err != nil {
		return fmt.Errorf("nft --version: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	if !nftVersionAtLeast(string(out), nftMinVersion) {
		return fmt.Errorf("nft %s below minimum %s", strings.TrimSpace(string(out)), nftMinVersion)
	}
	if out, err := fwExecIn(nftProbeScript, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("nft probe script: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// Ensure idempotently (re)creates table inet defensia. If the table already
// existed but the ensure transaction fails against it (a tampered or
// half-deleted table), it is dropped and recreated once before giving up.
// On the first successful Ensure in a process, legacy ipset-era iptables
// rules are best-effort removed so a host migrating ipset -> nftables does
// not keep two backends' rules active at once.
func (b *nftBackend) Ensure() (bool, error) {
	_, err := fwExec("nft", "list", "table", nftFamily, nftTable)
	existed := err == nil

	recreated := false
	out, ensureErr := fwExecIn(nftEnsureScript(), "nft", "-f", "-")
	if ensureErr != nil {
		if !existed {
			return false, fmt.Errorf("nft ensure: %s (%w)", strings.TrimSpace(string(out)), ensureErr)
		}
		log.Printf("[firewall] nft ensure failed on existing table (%s) — recreating table inet defensia", strings.TrimSpace(string(out)))
		_, _ = fwExec("nft", "delete", "table", "inet", "defensia")
		out2, err2 := fwExecIn(nftEnsureScript(), "nft", "-f", "-")
		if err2 != nil {
			return false, fmt.Errorf("nft ensure (after recreate): %s (%w)", strings.TrimSpace(string(out2)), err2)
		}
		recreated = true
	} else if !existed {
		recreated = true
	}

	if recreated {
		b.mu.Lock()
		b.rules = nil
		b.mu.Unlock()
	}

	b.mu.Lock()
	alreadyCleaned := b.legacyCleaned
	b.mu.Unlock()
	if !alreadyCleaned {
		if _, err := fwLookPath("iptables"); err == nil {
			_, _ = fwExec("iptables", "-D", "INPUT", "-m", "set", "--match-set", banSetName, "src", "-j", "DROP")
			_, _ = fwExec("ip6tables", "-D", "INPUT", "-m", "set", "--match-set", banSet6Name, "src", "-j", "DROP")
		}
		b.mu.Lock()
		b.legacyCleaned = true
		b.mu.Unlock()
	}

	return recreated, nil
}

func (b *nftBackend) banSetFor(ip net.IP) string {
	if ip.To4() != nil {
		return "bans4"
	}
	return "bans6"
}

func (b *nftBackend) Ban(ip net.IP, ttl time.Duration) error {
	set := b.banSetFor(ip)
	script := nftBanScript(set, []BanEntry{{IP: ip.String(), TTL: ttl}})
	if out, err := fwExecIn(script, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("nft add %s to %s: %s (%w)", ip, set, strings.TrimSpace(string(out)), err)
	}
	return nil
}

func (b *nftBackend) Unban(ip net.IP) error {
	set := b.banSetFor(ip)
	out, err := fwExecIn(nftUnbanScript(set, ip.String()), "nft", "-f", "-")
	if err != nil {
		if isNftNotFound(out) {
			return nil
		}
		return fmt.Errorf("nft delete %s from %s: %s (%w)", ip, set, strings.TrimSpace(string(out)), err)
	}
	return nil
}

func (b *nftBackend) BanBatch(entries []BanEntry) (int, error) {
	var v4, v6 []BanEntry
	for _, e := range entries {
		ip := net.ParseIP(e.IP)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			v4 = append(v4, e)
		} else {
			v6 = append(v6, e)
		}
	}

	applied := 0
	var firstErr error
	if len(v4) > 0 {
		if out, err := fwExecLong(nftBanScript("bans4", v4), "nft", "-f", "-"); err != nil {
			log.Printf("[firewall] nft batch ban failed (v4, %d IPs): %v", len(v4), err)
			if firstErr == nil {
				firstErr = fmt.Errorf("nft batch ban v4: %s (%w)", strings.TrimSpace(string(out)), err)
			}
		} else {
			applied += len(v4)
		}
	}
	if len(v6) > 0 {
		if out, err := fwExecLong(nftBanScript("bans6", v6), "nft", "-f", "-"); err != nil {
			log.Printf("[firewall] nft batch ban failed (v6, %d IPs): %v", len(v6), err)
			if firstErr == nil {
				firstErr = fmt.Errorf("nft batch ban v6: %s (%w)", strings.TrimSpace(string(out)), err)
			}
		} else {
			applied += len(v6)
		}
	}
	return applied, firstErr
}

func (b *nftBackend) Members() ([]string, []string, error) {
	out4, err := fwExec("nft", "-j", "list", "set", nftFamily, nftTable, "bans4")
	if err != nil {
		return nil, nil, fmt.Errorf("nft list set bans4: %w", err)
	}
	v4, err := parseNftSetElements(out4)
	if err != nil {
		return nil, nil, err
	}

	out6, err := fwExec("nft", "-j", "list", "set", nftFamily, nftTable, "bans6")
	if err != nil {
		return nil, nil, fmt.Errorf("nft list set bans6: %w", err)
	}
	v6, err := parseNftSetElements(out6)
	if err != nil {
		return nil, nil, err
	}

	return v4, v6, nil
}

func (b *nftBackend) Count() int {
	v4, v6, err := b.Members()
	if err != nil {
		return 0
	}
	return len(v4) + len(v6)
}

// loadRules refreshes b.rules from the `portrules` chain. Caller holds b.mu.
func (b *nftBackend) loadRules() error {
	out, err := fwExec("nft", "-j", "-a", "list", "chain", nftFamily, nftTable, "portrules")
	if err != nil {
		return fmt.Errorf("nft list chain portrules: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	refs, err := parseNftChainRules(out)
	if err != nil {
		return err
	}
	m := make(map[string]int, len(refs))
	for _, r := range refs {
		if strings.HasPrefix(r.Comment, nftRuleKeyPrefix) {
			m[r.Comment] = r.Handle
		}
	}
	b.rules = m
	return nil
}

func (b *nftBackend) ApplyRule(spec RuleSpec) error {
	expr, key, err := nftRuleExpr(spec)
	if err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.rules == nil {
		if err := b.loadRules(); err != nil {
			return err
		}
	}
	if _, exists := b.rules[key]; exists {
		log.Printf("[firewall] rule already exists, skipping")
		return nil
	}

	if out, err := fwExecIn(nftAddRuleScript(expr, key), "nft", "-f", "-"); err != nil {
		return fmt.Errorf("nft add rule: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	if err := b.loadRules(); err != nil {
		return err
	}
	log.Printf("[firewall] applied rule: %s", key)
	return nil
}

func (b *nftBackend) RemoveRule(spec RuleSpec) error {
	_, key, err := nftRuleExpr(spec)
	if err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.rules == nil {
		if err := b.loadRules(); err != nil {
			return err
		}
	}
	handle, exists := b.rules[key]
	if !exists {
		if err := b.loadRules(); err != nil {
			return err
		}
		handle, exists = b.rules[key]
		if !exists {
			return fmt.Errorf("nft rule not found: %s", key)
		}
	}

	if out, err := fwExecIn(nftDeleteRuleScript("portrules", handle), "nft", "-f", "-"); err != nil {
		return fmt.Errorf("nft delete rule: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	delete(b.rules, key)
	log.Printf("[firewall] removed rule: %s", key)
	return nil
}

func (b *nftBackend) ListRules() ([]ParsedRule, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if err := b.loadRules(); err != nil {
		return nil, err
	}
	var out []ParsedRule
	for key := range b.rules {
		if rule, ok := decodeRuleKey(key); ok {
			out = append(out, rule)
		}
	}
	log.Printf("[firewall] listed %d manageable rules from nftables", len(out))
	return out, nil
}

// geoHandle looks up the DROP rule handle for cc in the `geo` chain, or 0 if
// no such rule exists yet.
func (b *nftBackend) geoHandle(cc string) (int, error) {
	out, err := fwExec("nft", "-j", "-a", "list", "chain", nftFamily, nftTable, "geo")
	if err != nil {
		return 0, fmt.Errorf("nft list chain geo: %w", err)
	}
	refs, err := parseNftChainRules(out)
	if err != nil {
		return 0, err
	}
	want := nftGeoKeyPrefix + strings.ToLower(cc)
	for _, r := range refs {
		if r.Comment == want {
			return r.Handle, nil
		}
	}
	return 0, nil
}

// GeoReplace atomically (re)loads cc's CIDRs. If the atomic transaction
// fails with a kernel error mentioning "interval"/"conflicting" (the set has
// incompatible interval state mid-transaction), it retries as two separate
// transactions: set create+flush, then element population + the DROP rule.
func (b *nftBackend) GeoReplace(cc string, cidrs []string) (int, error) {
	valid := filterGeoCIDRs(cidrs)
	if len(valid) == 0 {
		return 0, fmt.Errorf("no valid IPv4 CIDRs for %s", cc)
	}

	handle, err := b.geoHandle(cc)
	if err != nil {
		return 0, err
	}
	addRule := handle == 0

	script, err := nftGeoReplaceScript(cc, valid, addRule)
	if err != nil {
		return 0, err
	}

	out, err := fwExecLong(script, "nft", "-f", "-")
	if err == nil {
		return len(valid), nil
	}

	outStr := string(out)
	if !strings.Contains(outStr, "interval") && !strings.Contains(outStr, "conflicting") {
		return 0, fmt.Errorf("nft geo replace for %s: %s (%w)", cc, strings.TrimSpace(outStr), err)
	}

	log.Printf("[firewall] nft geo replace for %s hit an interval/conflicting kernel error, retrying as two transactions: %s", cc, strings.TrimSpace(outStr))
	setup, err := nftGeoSetupScript(cc)
	if err != nil {
		return 0, err
	}
	if out2, err2 := fwExecLong(setup, "nft", "-f", "-"); err2 != nil {
		return 0, fmt.Errorf("nft geo setup (fallback) for %s: %s (%w)", cc, strings.TrimSpace(string(out2)), err2)
	}
	elems, err := nftGeoElementsScript(cc, valid, addRule)
	if err != nil {
		return 0, err
	}
	if out3, err3 := fwExecLong(elems, "nft", "-f", "-"); err3 != nil {
		return 0, fmt.Errorf("nft geo elements (fallback) for %s: %s (%w)", cc, strings.TrimSpace(string(out3)), err3)
	}
	return len(valid), nil
}

// GeoRemove deletes cc's DROP rule (if any) and its set. A set that is
// already gone is not an error.
func (b *nftBackend) GeoRemove(cc string) error {
	handle, err := b.geoHandle(cc)
	if err != nil {
		return err
	}
	script, err := nftGeoRemoveScript(cc, handle)
	if err != nil {
		return err
	}
	out, err := fwExecLong(script, "nft", "-f", "-")
	if err != nil {
		if isNftNotFound(out) {
			return nil
		}
		return fmt.Errorf("nft geo remove for %s: %s (%w)", cc, strings.TrimSpace(string(out)), err)
	}
	return nil
}

func (b *nftBackend) EnsureAccept(ips []string) error {
	var v4, v6 []string
	for _, raw := range ips {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			v4 = append(v4, ip.String())
		} else {
			v6 = append(v6, ip.String())
		}
	}
	script := nftProtectedScript(v4, v6)
	if out, err := fwExecIn(script, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("nft protected: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	return nil
}
