//go:build linux

package firewall

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const (
	tempBanLockRetries = 20
	tempBanLockDelay   = 100 * time.Millisecond
)

// readTempBanFile opens csf.tempban under a shared (read) advisory lock,
// retrying briefly if another process (CSF/lfd rewriting the file) holds an
// exclusive lock. A missing file is a normal "no temp bans yet" state, not
// an error. A lock that never clears within the retry window returns
// ErrTempBanBusy — never an empty successful read.
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

	fd := int(f.Fd())
	locked := false
	for i := 0; i < tempBanLockRetries; i++ {
		flockErr := syscall.Flock(fd, syscall.LOCK_SH|syscall.LOCK_NB)
		if flockErr == nil {
			locked = true

			break
		}
		if !errors.Is(flockErr, syscall.EWOULDBLOCK) {
			return nil, true, flockErr
		}
		time.Sleep(tempBanLockDelay)
	}
	if !locked {
		return nil, true, ErrTempBanBusy
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)

	data, readErr := io.ReadAll(f)
	if readErr != nil {
		return nil, true, readErr
	}

	return data, true, nil
}
