//go:build !linux

package firewall

import "net/netip"

// defaultActiveSSHSessionIPs: production always runs Linux (utmp/loginctl).
// On any other platform (unit tests on macOS), there is no notion of a
// logged-in system session to protect, so this returns nothing — tests
// that need SSH-session protection override the activeSSHSessionIPs seam
// directly.
func defaultActiveSSHSessionIPs() []netip.Addr { return nil }
