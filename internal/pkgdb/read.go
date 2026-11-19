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
	for _, db := range knownDatabases {
		content, ok := hostroot.ReadFile(db.path)
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
