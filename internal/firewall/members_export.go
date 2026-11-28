package firewall

// DefensiaBanMembers lists the Defensia ban entries of the active Phase 17
// backend (ipset, nftables or iptables). Read-only; used by lab integration
// tests so they can assert "no burst IP ever reached the Defensia backend"
// without shelling out to a backend-specific tool (`ipset list`, `nft list
// set`, ...) that would silently miss whichever backend the VM actually
// selected.
func DefensiaBanMembers() (v4, v6 []string, err error) {
	return current().Members()
}
