//go:build !linux

package firewall

import (
	"io"
	"os"
	"path/filepath"
)

// readTempBanFile is the non-Linux fallback (used by unit tests on macOS and
// any other dev platform): a plain read, no advisory lock. Production always
// runs Linux, where csf_tempban_linux.go's flock(LOCK_SH) path is used.
func readTempBanFile() (data []byte, exists bool, err error) {
	path := filepath.Join(csfVarDir, "csf.tempban")

	f, openErr := os.Open(path)
	if openErr != nil {
		if os.IsNotExist(openErr) {
			return nil, false, nil
		}

		return nil, false, openErr
	}
	defer f.Close()

	data, readErr := io.ReadAll(f)
	if readErr != nil {
		return nil, true, readErr
	}

	return data, true, nil
}
