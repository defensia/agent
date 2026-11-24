package firewall

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/defensia/agent/internal/csfsotwire"
)

// csfSotStatePath is where the engine's local state survives an agent
// restart; a test seam.
var csfSotStatePath = "/etc/defensia/csf_sot.json"

// sotLocalState is everything the reconcile engine needs to remember
// across restarts: which tokens it already consumed, the drift/auto-fix
// bookkeeping windows, and the intentional-change retry schedule.
type sotLocalState struct {
	GenerationSeen, GenerationAcked uint64

	LastRevertToken, LastResumeToken, LastRetryToken string

	AutoFixes  []time.Time
	Paused     bool
	HoldUntil  time.Time
	HoldReason string

	DriftFirstSeen  map[string]time.Time
	DriftSeenCycles map[string]int

	LastSelfWriteHash, LastFork, LastVersion string
	LastIPv6                                 *bool

	IntentGen      uint64
	IntentAttempts int
	IntentNextAt   time.Time

	Refused   []csfsotwire.Refusal
	LastError *csfsotwire.Refusal

	DriftReported bool
	Adopted       bool
}

// loadSotState reads the persisted state file. exists is false (with a
// fresh, zero-value state and a nil error) when the file is simply
// absent -- that is the normal "never activated, or already exited"
// case, not an error. A corrupt file logs a warning and also returns a
// fresh state with exists=true (so the caller knows there WAS a file,
// just an unreadable one) rather than panicking or propagating the
// parse error.
func loadSotState() (*sotLocalState, bool, error) {
	data, err := os.ReadFile(csfSotStatePath)
	if err != nil {
		if os.IsNotExist(err) {
			return &sotLocalState{}, false, nil
		}

		return &sotLocalState{}, false, err
	}

	var st sotLocalState
	if err := json.Unmarshal(data, &st); err != nil {
		log.Printf("[csf-sot] state file corrupt, starting fresh: %v", err)

		return &sotLocalState{}, true, nil
	}

	return &st, true, nil
}

// saveSotState writes the state file atomically (temp file in the same
// directory, then rename) with mode 0600 in a 0700 directory.
func saveSotState(s *sotLocalState) error {
	dir := filepath.Dir(csfSotStatePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	data, err := json.Marshal(s)
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".csf_sot.json.tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)

		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpPath)

		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)

		return err
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		os.Remove(tmpPath)

		return err
	}

	return os.Rename(tmpPath, csfSotStatePath)
}

// deleteSotState removes the state file (SOT-08: exit leaves nothing
// behind). Deleting an already-absent file is not an error.
func deleteSotState() (existed bool, err error) {
	err = os.Remove(csfSotStatePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}

		return false, err
	}

	return true, nil
}
