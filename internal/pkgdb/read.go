package pkgdb

import "github.com/defensia/agent/internal/hostroot"

// knownDatabases are the files to try, in order, relative to a machine's root.
// dpkg first because a Debian-family node is the common case in the fleet; a
// machine has one of these, not several.
var knownDatabases = []struct {
	path   string
	format Format
	parse  func(string) map[string]string
}{
	{"var/lib/dpkg/status", Dpkg, ParseDpkgStatus},
	{"lib/apk/db/installed", Apk, ParseApkInstalled},
}

// FromHostRoot reads the installed-package database of the machine the agent is
// reporting on — the node when the agent runs in a container with hostPID, its
// own host otherwise.
//
// The second return is false when no database could be read: an RPM machine,
// whose format is deliberately unsupported; an immutable node like Flatcar or
// Bottlerocket, which has no package manager at all; or a root we cannot see.
// That is "no answer", and a caller must not read it as "no packages".
func FromHostRoot() (DB, bool) {
	return fromReader(hostroot.ReadFile)
}

// FromRoot reads the installed-package database of an arbitrary root — a
// container's /proc/<pid>/root.
//
// Same "no answer" contract as FromHostRoot, and it fires far more often here:
// a distroless or scratch image has no package manager at all, and an image
// built from source has the software without a package that names it. Both must
// read as unknown, never as a clean machine.
func FromRoot(root string) (DB, bool) {
	return fromReader(func(rel string) ([]byte, bool) {
		return hostroot.ReadFileIn(root, rel)
	})
}

func fromReader(read func(string) ([]byte, bool)) (DB, bool) {
	for _, db := range knownDatabases {
		content, ok := read(db.path)
		if !ok {
			continue
		}

		packages := db.parse(string(content))
		if len(packages) == 0 {
			continue
		}

		return DB{Packages: packages, Format: db.format}, true
	}

	return DB{Format: Unknown}, false
}
