package firewall

import (
	"errors"
	"fmt"
	"log"
	"net"
	"time"
)

// iptablesBackend implements Backend using plain iptables/ip6tables rules
// (no ipset, no nftables). Limited capacity, no country-block support.
type iptablesBackend struct{}

func (iptablesBackend) Name() string { return "iptables" }

func (iptablesBackend) Probe() error {
	if _, err := fwLookPath("iptables"); err != nil {
		return fmt.Errorf("iptables not in PATH: %w", err)
	}
	if _, err := fwExec("iptables", "-S", "INPUT"); err != nil {
		return fmt.Errorf("iptables -S INPUT: %w", err)
	}
	return nil
}

func (iptablesBackend) Ensure() (bool, error) { return false, nil }

func (iptablesBackend) Ban(ip net.IP, ttl time.Duration) error {
	s := ip.String()
	if ip.To4() != nil {
		return iptablesApplyRule(RuleSpec{Type: "block", Protocol: "all", IPAddress: &s})
	}
	if _, err := fwLookPath("ip6tables"); err != nil {
		return fmt.Errorf("ip6tables not available for IPv6 ban %s", s)
	}
	if fwOK("ip6tables", "-C", "INPUT", "-s", s, "-j", "DROP") {
		return nil
	}
	if _, err := fwExec("ip6tables", "-I", "INPUT", "1", "-s", s, "-j", "DROP"); err != nil {
		return fmt.Errorf("ip6tables ban %s: %w", s, err)
	}
	return nil
}

func (iptablesBackend) Unban(ip net.IP) error {
	s := ip.String()
	if ip.To4() != nil {
		return iptablesRemoveRule(RuleSpec{Type: "block", Protocol: "all", IPAddress: &s})
	}
	if _, err := fwExec("ip6tables", "-D", "INPUT", "-s", s, "-j", "DROP"); err != nil {
		return fmt.Errorf("ip6tables unban %s: %w", s, err)
	}
	return nil
}

func (b iptablesBackend) BanBatch(entries []BanEntry) (int, error) {
	applied := 0
	var firstErr error
	for _, e := range entries {
		ip := net.ParseIP(e.IP)
		if ip == nil {
			continue
		}
		if err := b.Ban(ip, e.TTL); err != nil {
			log.Printf("[firewall] error applying ban for %s: %v", e.IP, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		applied++
	}
	return applied, firstErr
}

func (iptablesBackend) Members() ([]string, []string, error) {
	v4rules, err := iptablesListRules()
	if err != nil {
		return nil, nil, err
	}
	v6rules, _ := ip6tablesListRules() // ip6tables absence is not fatal here

	var v4, v6 []string
	for _, r := range v4rules {
		if r.Type == "block" && r.Source != "" && r.Port == 0 && r.Protocol == "all" {
			v4 = append(v4, r.Source)
		}
	}
	for _, r := range v6rules {
		if r.Type == "block" && r.Source != "" && r.Port == 0 && r.Protocol == "all" {
			v6 = append(v6, r.Source)
		}
	}
	return v4, v6, nil
}

func (b iptablesBackend) Count() int {
	v4, v6, err := b.Members()
	if err != nil {
		return 0
	}
	return len(v4) + len(v6)
}

func (iptablesBackend) Capacity() int { return 500 }

func (iptablesBackend) ApplyRule(spec RuleSpec) error    { return iptablesApplyRule(spec) }
func (iptablesBackend) RemoveRule(spec RuleSpec) error   { return iptablesRemoveRule(spec) }
func (iptablesBackend) ListRules() ([]ParsedRule, error) { return iptablesListRules() }

func (iptablesBackend) GeoSupported() bool { return false }

func (iptablesBackend) GeoReplace(cc string, cidrs []string) (int, error) {
	return 0, errors.New("country blocks need ipset or nftables")
}

func (iptablesBackend) GeoRemove(cc string) error {
	return errors.New("country blocks need ipset or nftables")
}

func (iptablesBackend) EnsureAccept(ips []string) error { return nil }
