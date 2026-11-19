//go:build linux

package hostroot

import (
	"io"
	"os"
	"path/filepath"
	"strings"
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

	if root == selfRoot {
		b, err := readCapped(filepath.Join(root, rel))
		if err != nil {
			return nil, false
		}

		return b, true
	}

	// No openat2 and a foreign root. openat2 landed in Linux 5.6, and this is not
	// a hypothetical gap: our own production host answers ENOSYS, because it is an
	// OpenVZ VPS on an older kernel. Refusing outright would mean the fix does not
	// work on exactly the machines we run ourselves.
	//
	// So resolve by hand, and resolve it the way openat2 would. The danger is an
	// ABSOLUTE symlink: the kernel resolves it against the reader's root, so it
	// leaves the node's filesystem and hands back our own file under the node's
	// name. A RELATIVE symlink cannot do that as long as the result stays inside
	// the root, and relative links are not an edge case here — on Ubuntu 24.04
	// /etc/os-release is itself a symlink to ../usr/lib/os-release, measured. A
	// check that refused all links would refuse to read the os-release of the most
	// common distribution in the fleet.
	resolved, ok := resolveWithin(root, rel)
	if !ok {
		return nil, false
	}

	b, err := readCapped(resolved)
	if err != nil {
		return nil, false
	}

	return b, true
}

// maxSymlinkHops bounds resolution, so a link that points at itself cannot spin
// forever. The kernel's own limit is 40; the paths here need one or two.
const maxSymlinkHops = 16

// resolveWithin walks rel under root, following relative symlinks and refusing
// absolute ones, and returns the real path to open.
//
// The invariant is that the result never leaves root. An absolute link is
// refused outright rather than reinterpreted, because reinterpreting it is
// guesswork about what the node meant; a relative link is followed and the
// result re-checked against root, which is what makes "../usr/lib/os-release"
// safe and "../../../etc/passwd" not.
func resolveWithin(root, rel string) (string, bool) {
	path := root

	parts := strings.Split(filepath.Clean(rel), string(filepath.Separator))
	for len(parts) > 0 {
		part, rest := parts[0], parts[1:]
		parts = rest

		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			return "", false // a traversal is exactly what must not be followed
		}

		next := filepath.Join(path, part)

		fi, err := os.Lstat(next)
		if err != nil {
			return "", false
		}

		if fi.Mode()&os.ModeSymlink == 0 {
			path = next

			continue
		}

		target, err := os.Readlink(next)
		if err != nil {
			return "", false
		}
		if filepath.IsAbs(target) {
			return "", false
		}

		hops := 0
		for {
			hops++
			if hops > maxSymlinkHops {
				return "", false
			}

			candidate := filepath.Join(filepath.Dir(next), target)
			if !withinRoot(root, candidate) {
				return "", false
			}

			fi, err = os.Lstat(candidate)
			if err != nil {
				return "", false
			}
			if fi.Mode()&os.ModeSymlink == 0 {
				path = candidate

				break
			}

			next = candidate
			if target, err = os.Readlink(candidate); err != nil || filepath.IsAbs(target) {
				return "", false
			}
		}
	}

	return path, true
}

// withinRoot reports whether a resolved path is still inside root, which is the
// property the whole fallback rests on.
func withinRoot(root, path string) bool {
	root = filepath.Clean(root)
	path = filepath.Clean(path)

	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
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

func readCapped(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return io.ReadAll(io.LimitReader(f, maxReadBytes))
}
