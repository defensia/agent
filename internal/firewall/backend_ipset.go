package firewall

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

// ipsetBackend implements Backend on top of ipset + iptables (existing
// ipset.go/iptables.go/geoblock.go/geochain.go helpers, migrated to the fw
// exec seam). Stateless: every method reads live kernel/CLI state.
type ipsetBackend struct{}

func (ipsetBackend) Name() string { return "ipset" }

// Probe proves ipset is not just present but functional: binary + iptables
// present, and a real create/destroy round-trip succeeds (fixes scenario C,
// where LookPath alone reports "available" for a broken ipset).
func (ipsetBackend) Probe() error {
	if _, err := fwLookPath("ipset"); err != nil {
		return fmt.Errorf("ipset not in PATH: %w", err)
	}
	if _, err := fwLookPath("iptables"); err != nil {
		return fmt.Errorf("iptables not in PATH: %w", err)
	}
	out, err := fwExec("ipset", "create", "defensia-probe", "hash:ip", "-exist")
	if err != nil {
		return fmt.Errorf("ipset create probe: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	if out, err := fwExec("ipset", "destroy", "defensia-probe"); err != nil {
		return fmt.Errorf("ipset destroy probe: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// Ensure is origin/main's Init() body: v4 set+rule are fatal, v6 set/rule
// failure is logged only (origin/main wording).
func (ipsetBackend) Ensure() (bool, error) {
	if err := createIpsetHashIP(banSetName); err != nil {
		return false, err
	}
	if err := addIptablesIpsetRule(banSetName); err != nil {
		return false, err
	}
	if err := createIpsetHashIP6(banSet6Name); err != nil {
		log.Printf("[firewall] failed to create IPv6 ban set: %v", err)
	} else if err := addIp6tablesIpsetRule(banSet6Name); err != nil {
		log.Printf("[firewall] failed to add ip6tables rule for ban set: %v", err)
	}
	return false, nil
}

func (ipsetBackend) Ban(ip net.IP, ttl time.Duration) error {
	if ip.To4() != nil {
		return ipsetAdd(banSetName, ip.String())
	}
	return ipsetAdd(banSet6Name, ip.String())
}

func (ipsetBackend) Unban(ip net.IP) error {
	if ip.To4() != nil {
		return ipsetDel(banSetName, ip.String())
	}
	return ipsetDel(banSet6Name, ip.String())
}

func (ipsetBackend) BanBatch(entries []BanEntry) (int, error) {
	var v4, v6 []string
	for _, e := range entries {
		ip := net.ParseIP(e.IP)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			v4 = append(v4, e.IP)
		} else {
			v6 = append(v6, e.IP)
		}
	}
	applied := 0
	if len(v4) > 0 {
		if err := ipsetBatchAdd(banSetName, v4); err != nil {
			log.Printf("[firewall] ipset batch ban failed (v4, %d IPs): %v", len(v4), err)
		} else {
			applied += len(v4)
		}
	}
	if len(v6) > 0 {
		if err := ipsetBatchAdd(banSet6Name, v6); err != nil {
			log.Printf("[firewall] ipset batch ban failed (v6, %d IPs): %v", len(v6), err)
		} else {
			applied += len(v6)
		}
	}
	return applied, nil
}

func (ipsetBackend) Members() ([]string, []string, error) {
	return ipsetListMembers(banSetName), ipsetListMembers(banSet6Name), nil
}

func (ipsetBackend) Count() int    { return ipsetEntryCount(banSetName) + ipsetEntryCount(banSet6Name) }
func (ipsetBackend) Capacity() int { return 65536 }

func (ipsetBackend) ApplyRule(spec RuleSpec) error    { return iptablesApplyRule(spec) }
func (ipsetBackend) RemoveRule(spec RuleSpec) error   { return iptablesRemoveRule(spec) }
func (ipsetBackend) ListRules() ([]ParsedRule, error) { return iptablesListRules() }

func (ipsetBackend) GeoSupported() bool { return true }

func (ipsetBackend) GeoReplace(cc string, cidrs []string) (int, error) {
	setName := ipsetSetName(cc)
	removeLegacyGeoRule(setName)
	if err := createIpsetHashNet(setName); err != nil {
		_ = flushIpset(setName)
		_ = destroyIpset(setName)
		if err := createIpsetHashNet(setName); err != nil {
			return 0, fmt.Errorf("create set %s: %w", setName, err)
		}
	}
	if err := flushIpset(setName); err != nil {
		return 0, fmt.Errorf("flush set %s: %w", setName, err)
	}
	if err := populateIpsetBatch(setName, cidrs); err != nil {
		_ = destroyIpset(setName)
		return 0, fmt.Errorf("populate set %s: %w", setName, err)
	}
	return ipsetEntryCount(setName), nil
}

func (ipsetBackend) GeoRemove(cc string) error {
	setName := ipsetSetName(cc)
	removeLegacyGeoRule(setName)
	_ = flushIpset(setName)
	return destroyIpset(setName)
}

func (ipsetBackend) EnsureAccept(ips []string) error {
	for _, ip := range ips {
		if fwOK("iptables", "-C", "INPUT", "-s", ip, "-j", "ACCEPT") {
			continue
		}
		if _, err := fwExec("iptables", "-I", "INPUT", "1", "-s", ip, "-j", "ACCEPT"); err != nil {
			return err
		}
	}
	return nil
}
