// Package hostroot answers one question: when the agent runs inside a
// container, where is the filesystem of the machine it is supposed to be
// reporting on?
//
// It exists because the answer used to be "nowhere", silently. In Kubernetes our
// chart runs the agent as a DaemonSet, so it runs in a container — and every
// read it made went to its own image. A node running Ubuntu with eighty packages
// was reported as "alpine 3.20.10", which is the agent's own base image, because
// that is what /etc/os-release says from inside. Measured in production on
// 19 Nov 2026: eight agents reporting exactly that, and they are not all
// Kubernetes — any agent in a container had the same blind spot.
//
// The failure mode is the dangerous kind. It does not error, it does not warn,
// and it does not produce a wrong-looking answer: it produces a small, plausible
// inventory of the wrong machine. Nobody notices an empty list.
//
// With hostPID, which our chart already requests, PID 1 is the node's init and
// /proc/1/root is the node's filesystem root. Verified on a real k3s cluster:
// from inside the agent's pod, /proc/1/root/etc/os-release reads
// PRETTY_NAME="K3s v1.35.5+k3s1" while /etc/os-release reads alpine 3.20.10.
//
// Reads go through openat2 with RESOLVE_IN_ROOT, and that is not a detail. An
// absolute symlink inside the target root is resolved by the kernel against the
// *reader's* root, so a plain open of "<root>/etc/os-release" on a distro where
// that path is an absolute symlink would quietly return the container's own file
// and attribute it to the node. The same trap was measured this morning reading
// container filesystems from the host: /proc/<pid>/root/bin/sh came back as a
// broken link to /bin/busybox because the kernel resolved it against the host.
// It failed visibly there only because the host happened not to have that path.
package hostroot

// selfRoot is where this process's own filesystem root lives, and hostPid1Root
// is where PID 1's does. Both are variables rather than constants so tests can
// point them at fixtures.
var (
	selfRoot      = "/"
	hostPid1Root  = "/proc/1/root"
	osReleasePath = "etc/os-release"
)

// maxReadBytes caps any single read, so a file that is enormous or a device that
// never ends cannot make the agent allocate without bound. The files this
// package is for — os-release, package databases — are kilobytes to low
// megabytes; rpmdb.sqlite on AlmaLinux 9 measures ~20 MB, which is the number
// this cap has to clear.
const maxReadBytes = 64 << 20 // 64 MiB

// Root returns the filesystem root of the machine to report on.
//
// "/" when the agent runs on the host, which is the common case and the one that
// must not change behaviour. "/proc/1/root" when the agent runs in a container
// that can see the host's PID 1 and that root is demonstrably a different
// filesystem from its own.
//
// The test for "different" is deliberately an observation rather than a guess:
// both os-release files are read and compared. Detecting containers by looking
// for /.dockerenv or parsing cgroups answers a related but different question —
// "am I containerised?" — and would say yes in a container with no hostPID,
// where /proc/1/root is the container's own root and switching to it changes
// nothing. Comparing the files answers the question actually being asked.
func Root() string {
	// Read through the PID 1 root as its own root, never as a path under ours.
	// /proc/1/root is a magic link: it is opened as a directory once, which
	// crosses into the node deliberately, and every read after that is confined
	// inside the root it lands in. Crossing is the one hop we want; escaping
	// afterwards is what must be impossible.
	//
	// Reading it needs CAP_SYS_PTRACE, measured: a container with --pid=host and
	// no added capabilities gets EACCES on every attempt, including a plain
	// os.ReadFile. The chart's privileged: true covers it. Without it this
	// returns "/" and the agent reports its own image, which is wrong but at
	// least not a claim about a machine we cannot see.
	hostData, ok := readWithin(hostPid1Root, osReleasePath)
	if !ok {
		return selfRoot
	}

	ownData, ok := readWithin(selfRoot, osReleasePath)
	if ok && string(ownData) == string(hostData) {
		return selfRoot
	}

	return hostPid1Root
}

// IsContainerised reports whether Root() resolved to something other than this
// process's own root — that is, whether the agent is reading a machine it is not
// itself running directly on.
//
// Worth reporting alongside an inventory: a reader who knows the figures came
// from a node seen through a container can judge them, and one who does not
// cannot.
func IsContainerised() bool {
	return Root() != selfRoot
}

// ReadFileIn reads a path relative to an arbitrary root, with the same
// confinement as ReadFile.
//
// Exists for container filesystems, where the root is /proc/<pid>/root of some
// container rather than of PID 1. The guarantees matter more there, not less: a
// container image is written by whoever built it, so an absolute symlink inside
// one is not a hypothetical — and following it would read the agent's own
// filesystem and report it as the container's contents.
func ReadFileIn(root, rel string) ([]byte, bool) {
	if root == "" {
		return nil, false
	}

	return readWithin(root, rel)
}

// ReadFile reads a path relative to the host root, returning false when it
// cannot be read at all.
//
// false means no answer. It must never be read as "the file is empty" or "the
// package is absent" — the whole point of this package is that a missing answer
// used to be indistinguishable from a small one.
func ReadFile(rel string) ([]byte, bool) {
	return readWithin(Root(), rel)
}
