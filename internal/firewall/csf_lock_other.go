//go:build !linux

package firewall

// csfRestarting always reports false on non-Linux (syscall.Flock semantics
// used by the real check are Linux-specific; CSF itself only ever runs on
// Linux, so non-Linux builds — dev/test on macOS — never need the real
// check and must not block on a lock file that will never exist here).
func csfRestarting() bool {
	return false
}
