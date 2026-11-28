package firewall

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
)

// banStatePath is the default persisted-state location; ManagerOptions.StatePath
// overrides it (tests always do).
var banStatePath = "/etc/defensia/ban_executor.json"

// banState is the ban executor's crash-resumable persisted state: which
// executor is in effect, whether a switch is still converging, and the
// undo/degraded fields plan 08 adds on top of this plan's fields.
type banState struct {
	Mode            string `json:"mode"` // "" (= defensia) | "defensia" | "csf"
	Migrating       bool   `json:"migrating"`
	MigrationTarget string `json:"migration_target"`
	LastUndoToken   string `json:"last_undo_token"`
	LastUndoRemoved int    `json:"last_undo_removed"`
	Degraded        bool   `json:"degraded"`
	DegradedReason  string `json:"degraded_reason"`
	UpdatedAt       string `json:"updated_at"`
}

// loadBanState reads the persisted state. A missing file is not an error
// (zero state, Mode "" == defensia, matching a fresh install); corrupt JSON
// is logged once and treated the same as missing — it must never panic or
// block startup.
func loadBanState(path string) banState {
	data, err := os.ReadFile(path)
	if err != nil {
		return banState{}
	}

	var s banState
	if err := json.Unmarshal(data, &s); err != nil {
		log.Printf("[firewall] ban executor state at %s is corrupt, starting from defensia: %v", path, err)
		return banState{}
	}

	return s
}

// saveBanState writes s atomically: a temp file in the same directory,
// fsynced, then renamed over the real path — a crash mid-write leaves the
// previous (valid) state in place, never a torn file. A leftover .tmp from
// an earlier crash is simply overwritten by the next save.
func saveBanState(path string, s banState) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	data, err := json.Marshal(s)
	if err != nil {
		return err
	}

	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	return os.Rename(tmp, path)
}
