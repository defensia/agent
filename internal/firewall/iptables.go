package firewall

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"
)

// RuleSpec describes a firewall rule to apply.
type RuleSpec struct {
	Type      string  // "block" or "allow"
	Protocol  string  // "tcp", "udp", "icmp", "all"
	IPAddress *string // single IP
	IPRange   *string // CIDR range
	Port      *int    // destination port (only for tcp/udp)
}

// ApplyRule adds an iptables rule based on a RuleSpec.
// Returns nil if the rule was applied successfully.
func ApplyRule(spec RuleSpec) error {
	args := buildRuleArgs(spec)

	// Check if rule already exists
	checkArgs := append([]string{"-C", "INPUT"}, args...)
	if exec.Command("iptables", checkArgs...).Run() == nil {
		log.Printf("[firewall] rule already exists, skipping")
		return nil
	}

	// Insert at top of chain
	insertArgs := append([]string{"-I", "INPUT", "1"}, args...)
	if err := exec.Command("iptables", insertArgs...).Run(); err != nil {
		return fmt.Errorf("iptables apply rule: %w", err)
	}

	log.Printf("[firewall] applied rule: %v", args)
	return nil
}

// RemoveRule removes an iptables rule matching the given RuleSpec.
func RemoveRule(spec RuleSpec) error {
	args := buildRuleArgs(spec)
	deleteArgs := append([]string{"-D", "INPUT"}, args...)

	if err := exec.Command("iptables", deleteArgs...).Run(); err != nil {
		return fmt.Errorf("iptables remove rule: %w", err)
	}

	log.Printf("[firewall] removed rule: %v", args)
	return nil
}

// buildRuleArgs constructs iptables arguments for a RuleSpec.
func buildRuleArgs(spec RuleSpec) []string {
	var args []string

	// Source IP/range
	src := source(spec)
	if src != "" {
		args = append(args, "-s", src)
	}

	// Protocol
	proto := spec.Protocol
	if proto == "" || proto == "all" {
		// Only add protocol if port is specified (port requires tcp/udp)
		if spec.Port != nil {
			proto = "tcp"
			args = append(args, "-p", proto)
		}
	} else {
		args = append(args, "-p", proto)
	}

	// Destination port (only for tcp/udp)
	if spec.Port != nil && (proto == "tcp" || proto == "udp") {
		args = append(args, "--dport", strconv.Itoa(*spec.Port))
	}

	// Target (ACCEPT or DROP)
	target := "DROP"
	if spec.Type == "allow" {
		target = "ACCEPT"
	}
	args = append(args, "-j", target)

	return args
}

// source returns the source argument from the RuleSpec.
func source(spec RuleSpec) string {
	if spec.IPAddress != nil && *spec.IPAddress != "" {
		return *spec.IPAddress
	}
	if spec.IPRange != nil && *spec.IPRange != "" {
		return *spec.IPRange
	}
	return ""
}

// BanIP adds a DROP rule for the given IP address.
func BanIP(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	return ApplyRule(RuleSpec{
		Type:      "block",
		Protocol:  "all",
		IPAddress: &ip,
	})
}

// UnbanIP removes the DROP rule for the given IP address.
func UnbanIP(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	return RemoveRule(RuleSpec{
		Type:      "block",
		Protocol:  "all",
		IPAddress: &ip,
	})
}

// ApplyBans applies a list of IPs from the server sync.
func ApplyBans(ips []string) {
	for _, ip := range ips {
		if err := BanIP(ip); err != nil {
			log.Printf("[firewall] error applying ban for %s: %v", ip, err)
		}
	}
}
