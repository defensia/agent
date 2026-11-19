//go:build !linux

package hostroot

import (
	"io"
	"os"
	"path/filepath"
)

// readWithin on a non-Linux build exists so the package compiles on a developer
// Mac. There is no openat2 outside Linux and no container to misattribute a read
// to, since the agent only ever runs on Linux in production: reads are plain and
// confined to the process's own root.
func readWithin(root, rel string) ([]byte, bool) {
	if rel == "" || root != selfRoot {
		return nil, false
	}

	f, err := os.Open(filepath.Join(root, rel))
	if err != nil {
		return nil, false
	}
	defer f.Close()

	b, err := io.ReadAll(io.LimitReader(f, maxReadBytes))
	if err != nil && len(b) == 0 {
		return nil, false
	}

	return b, true
}
