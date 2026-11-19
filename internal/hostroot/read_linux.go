//go:build linux

package hostroot

import (
	"io"
	"os"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// openat2Unavailable records that the kernel rejected openat2, so the fallback
// is taken once rather than re-probing on every read. openat2 landed in Linux
// 5.6; older kernels answer ENOSYS.
var openat2Unavailable atomic.Bool

// readWithin reads rel relative to root, refusing to follow any path component
// out of it.
//
// The refusal is the feature. Resolving "<root>/etc/os-release" with a plain
// open lets an absolute symlink inside root escape to the reader's own
// filesystem, and the file that comes back then gets attributed to the wrong
// machine — silently, because it is a perfectly valid file. RESOLVE_IN_ROOT
// makes the kernel resolve every component against the opened directory, so an
// absolute link points back inside instead of out.
func readWithin(root, rel string) ([]byte, bool) {
	if rel == "" {
		return nil, false
	}

	if !openat2Unavailable.Load() {
		if b, ok := readOpenat2(root, rel); ok {
			return b, true
		}
	}

	// No openat2: read normally only when the root is this process's own, where
	// there is no second filesystem to escape to and therefore nothing to
	// misattribute. Reading a *different* root unsafely would trade a missing
	// answer for a wrong one, and a wrong answer about which machine is
	// vulnerable is worse than no answer.
	if root != selfRoot {
		return nil, false
	}

	b, err := readCapped(rel)
	if err != nil {
		return nil, false
	}

	return b, true
}

func readOpenat2(root, rel string) ([]byte, bool) {
	dirFd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, false
	}
	defer unix.Close(dirFd)

	fd, err := unix.Openat2(dirFd, rel, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_IN_ROOT,
	})
	if err != nil {
		// ENOSYS is the kernel saying it has no openat2 at all, which is a
		// property of the machine rather than of this path: stop asking.
		if err == unix.ENOSYS {
			openat2Unavailable.Store(true)
		}

		return nil, false
	}

	f := os.NewFile(uintptr(fd), root+"/"+rel)
	defer f.Close()

	b, err := io.ReadAll(io.LimitReader(f, maxReadBytes))
	if err != nil && len(b) == 0 {
		return nil, false
	}

	return b, true
}

func readCapped(rel string) ([]byte, error) {
	f, err := os.Open("/" + rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return io.ReadAll(io.LimitReader(f, maxReadBytes))
}
