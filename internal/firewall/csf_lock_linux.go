//go:build linux

package firewall

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// csfRestarting reports whether CSF itself currently holds an exclusive
// lock on its own csf.lock file — the real, lab-measured signal that CSF
// is mid-restart, NOT merely whether the file exists.
//
// csf.lock is created once (by csf's own init/first run) and is NEVER
// removed afterward — confirmed live in the OrbStack lab (2026-11-25,
// alma9-csf-orig): the file's mtime stayed unchanged across a full
// successful `csf -r`. Treating its mere presence as "restarting" (the
// original, untested assumption) would have permanently stuck the
// executor in the paused/restarting branch on every real CSF host, never
// writing a single ban — caught here, not in production, specifically
// because this plan runs against the real lab VMs instead of only a fake
// binary. The actual signal is whether something else holds an exclusive
// lock on it right now: try a non-blocking exclusive flock — acquiring it
// means nobody else holds it (not restarting); EWOULDBLOCK means CSF
// itself has it locked (restarting); any other error, or the file not
// existing at all, is treated as "not restarting" (fail open on the read
// side — the breaker's own 3-strikes rule is what catches a genuinely
// misbehaving CSF, not this best-effort heuristic).
func csfRestarting() bool {
	path := filepath.Join(csfVarDir, "csf.lock")
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return false
	}
	defer f.Close()

	fd := int(f.Fd())
	flockErr := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
	if flockErr == nil {
		syscall.Flock(fd, syscall.LOCK_UN)
		return false
	}
	return errors.Is(flockErr, syscall.EWOULDBLOCK)
}
