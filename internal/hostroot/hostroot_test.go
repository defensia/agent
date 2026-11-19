package hostroot

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

const (
	alpineRelease = "ID=alpine\nVERSION_ID=3.20.10\nPRETTY_NAME=\"Alpine Linux v3.20\"\n"
	nodeRelease   = "ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.3 LTS\"\n"
)

// withRoots points the package at fixture directories for the duration of a
// test, restoring the real paths afterwards.
func withRoots(t *testing.T, self, pid1 string) {
	t.Helper()

	origSelf, origPid1 := selfRoot, hostPid1Root
	selfRoot, hostPid1Root = self, pid1
	t.Cleanup(func() { selfRoot, hostPid1Root = origSelf, origPid1 })
}

func writeRelease(t *testing.T, dir, content string) string {
	t.Helper()

	if err := os.MkdirAll(filepath.Join(dir, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "etc", "os-release"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	return dir
}

// The production bug: the agent's own image is Alpine, the node is Ubuntu, and
// reading /etc/os-release directly reported the image. Eight agents in the fleet
// were doing exactly this.
func TestADifferentRootAtPid1IsTheMachineToReport(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("reads outside the process root are Linux-only")
	}

	self := writeRelease(t, t.TempDir(), alpineRelease)
	node := writeRelease(t, t.TempDir(), nodeRelease)
	withRoots(t, self, node)

	if got := Root(); got != node {
		t.Fatalf("Root() = %q, want the node root %q", got, node)
	}

	if !IsContainerised() {
		t.Error("IsContainerised() = false, but the agent is reading a root that is not its own")
	}

	data, ok := ReadFile("etc/os-release")
	if !ok {
		t.Fatal("want the node's os-release to be readable")
	}
	if string(data) != nodeRelease {
		t.Errorf("read the wrong machine's os-release:\n%s", data)
	}
}

// The common case, and the one that must not change: on a host install PID 1's
// root is the process's own, so nothing moves.
func TestAHostInstallIsUnchanged(t *testing.T) {
	root := writeRelease(t, t.TempDir(), nodeRelease)
	withRoots(t, root, root)

	if got := Root(); got != root {
		t.Fatalf("Root() = %q, want %q — a host install must not switch roots", got, root)
	}

	if IsContainerised() {
		t.Error("IsContainerised() = true on a host install")
	}
}

// A container with no hostPID sees its own PID 1, so /proc/1/root is its own
// root. Switching to it would change nothing, and claiming to be reading the
// node would be a lie — this is why Root() compares the files rather than
// detecting containers.
func TestAContainerWithoutHostPidDoesNotClaimToSeeTheNode(t *testing.T) {
	root := writeRelease(t, t.TempDir(), alpineRelease)
	withRoots(t, root, root)

	if IsContainerised() {
		t.Error("IsContainerised() = true, but this container cannot see the node at all")
	}
}

// An unreadable PID 1 root — no hostPID, a hardened kernel, not running as root
// — must fall back to the process's own root rather than returning a path that
// reads as nothing.
func TestAnUnreadablePid1RootFallsBackToOurOwn(t *testing.T) {
	self := writeRelease(t, t.TempDir(), alpineRelease)
	withRoots(t, self, filepath.Join(t.TempDir(), "does-not-exist"))

	if got := Root(); got != self {
		t.Fatalf("Root() = %q, want our own root %q", got, self)
	}
}

// Reads are confined to the root, so an absolute symlink inside it cannot reach
// the reader's filesystem. Without this, a distro whose /etc/os-release is an
// absolute link would hand back the *container's* file and attribute it to the
// node — a valid file about the wrong machine, which is the failure mode this
// package exists to prevent.
func TestAnAbsoluteSymlinkCannotEscapeTheRoot(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("RESOLVE_IN_ROOT is Linux-only")
	}

	node := t.TempDir()
	if err := os.MkdirAll(filepath.Join(node, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Inside the node root, /etc/os-release points at an absolute path.
	if err := os.Symlink("/escaped", filepath.Join(node, "etc", "os-release")); err != nil {
		t.Fatal(err)
	}
	// And the target exists *inside* the root, where a correct resolution lands.
	if err := os.WriteFile(filepath.Join(node, "escaped"), []byte(nodeRelease), 0o644); err != nil {
		t.Fatal(err)
	}

	data, ok := readWithin(node, "etc/os-release")
	if !ok {
		t.Skip("openat2 unavailable on this kernel; the fallback refuses foreign roots by design")
	}

	if string(data) != nodeRelease {
		t.Errorf("the absolute symlink did not resolve inside the root; got:\n%s", data)
	}
}

// An absent file is no answer, never an empty one. The original bug produced a
// small plausible inventory instead of an error, so this distinction is the
// whole point.
func TestAMissingFileIsNoAnswerNotAnEmptyOne(t *testing.T) {
	root := writeRelease(t, t.TempDir(), nodeRelease)
	withRoots(t, root, root)

	if data, ok := ReadFile("etc/absent"); ok {
		t.Errorf("want no answer for a missing file, got %d bytes", len(data))
	}

	if _, ok := ReadFile(""); ok {
		t.Error("want no answer for an empty path")
	}
}

// The cap has to clear the largest real file this will read: rpmdb.sqlite on
// AlmaLinux 9 measured ~20 MB.
func TestTheReadCapClearsAnRpmDatabase(t *testing.T) {
	const rpmdbMeasured = 20 << 20
	if maxReadBytes < rpmdbMeasured {
		t.Errorf("maxReadBytes = %d, too small for a measured %d-byte rpmdb.sqlite", maxReadBytes, rpmdbMeasured)
	}
}

// Ubuntu 24.04's /etc/os-release is itself a symlink to ../usr/lib/os-release,
// measured on our own host. A check that refused every link would refuse to read
// the os-release of the most common distribution in the fleet — which is exactly
// what the first version of the no-openat2 fallback did.
func TestARelativeSymlinkInsideTheRootIsFollowed(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("foreign-root reads are Linux-only")
	}

	node := t.TempDir()
	if err := os.MkdirAll(filepath.Join(node, "usr", "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(node, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(node, "usr", "lib", "os-release"), []byte(nodeRelease), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../usr/lib/os-release", filepath.Join(node, "etc", "os-release")); err != nil {
		t.Fatal(err)
	}

	self := writeRelease(t, t.TempDir(), alpineRelease)
	withRoots(t, self, node)

	data, ok := ReadFile("etc/os-release")
	if !ok {
		t.Fatal("a relative symlink inside the root must be followed")
	}
	if string(data) != nodeRelease {
		t.Errorf("followed the link to the wrong place:\n%s", data)
	}
}

// A relative link with enough ".." to climb out of the root must be refused,
// which is the case that makes following relative links safe at all.
func TestARelativeSymlinkThatClimbsOutOfTheRootIsRefused(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("foreign-root reads are Linux-only")
	}

	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("not the node\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	node := t.TempDir()
	if err := os.MkdirAll(filepath.Join(node, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	// ../../<outside>/secret, built relative so it is not rejected for being absolute.
	rel, err := filepath.Rel(filepath.Join(node, "etc"), filepath.Join(outside, "secret"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(rel, filepath.Join(node, "etc", "os-release")); err != nil {
		t.Fatal(err)
	}

	if _, ok := readWithin(node, "etc/os-release"); ok {
		t.Error("a link climbing out of the root was followed")
	}
}

// ".." in the requested path itself is a traversal attempt, not a link.
func TestATraversalInTheRequestedPathIsRefused(t *testing.T) {
	root := writeRelease(t, t.TempDir(), nodeRelease)
	withRoots(t, root, root)

	if _, ok := ReadFile("etc/../../escaped"); ok {
		t.Error("a traversal in the requested path was followed")
	}
}
