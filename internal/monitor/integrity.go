package monitor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defensia/agent/internal/api"
)

const (
	integrityCooldown = 6 * time.Hour
	maxFileSize       = 10 * 1024 * 1024 // 10MB
)

type fileBaseline struct {
	hash string
	size int64
}

type IntegrityDetector struct {
	baselines map[string]fileBaseline
	reported  map[string]time.Time
	firstRun  bool
}

var monitoredFiles = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/group",
	"/etc/sudoers",
	"/etc/ssh/sshd_config",
	"/etc/crontab",
	"/etc/hosts",
	"/etc/resolv.conf",
	"/root/.ssh/authorized_keys",
}

var monitoredGlobs = []string{
	"/home/*/.ssh/authorized_keys",
	"/etc/sudoers.d/*",
	"/etc/cron.d/*",
}

func NewIntegrityDetector() *IntegrityDetector {
	return &IntegrityDetector{
		baselines: make(map[string]fileBaseline),
		reported:  make(map[string]time.Time),
		firstRun:  true,
	}
}

func (d *IntegrityDetector) Scan() []api.EventRequest {
	now := time.Now()

	// Prune expired cooldowns
	for k, t := range d.reported {
		if now.Sub(t) > integrityCooldown {
			delete(d.reported, k)
		}
	}

	// Gather all files to check
	files := make([]string, 0, len(monitoredFiles)+20)
	files = append(files, monitoredFiles...)
	for _, pattern := range monitoredGlobs {
		matches, _ := filepath.Glob(pattern)
		files = append(files, matches...)
	}

	var events []api.EventRequest

	for _, path := range files {
		info, err := os.Stat(path)
		if err != nil {
			// File doesn't exist or not accessible — remove baseline if had one
			if _, had := d.baselines[path]; had {
				delete(d.baselines, path)
			}
			continue
		}

		if info.Size() > maxFileSize {
			continue
		}

		hash, err := hashFile(path)
		if err != nil {
			continue
		}

		current := fileBaseline{hash: hash, size: info.Size()}
		prev, exists := d.baselines[path]

		if !exists {
			// First time seeing this file — set baseline
			d.baselines[path] = current
			continue
		}

		if prev.hash == current.hash {
			continue
		}

		// Hash changed
		d.baselines[path] = current

		if d.firstRun {
			continue
		}

		if _, cooled := d.reported[path]; cooled {
			continue
		}

		severity := fileSeverity(path)

		events = append(events, api.EventRequest{
			Type:     "integrity_change",
			Severity: severity,
			Details: map[string]string{
				"file":     path,
				"old_hash": prev.hash,
				"new_hash": current.hash,
				"old_size": fmt.Sprintf("%d", prev.size),
				"new_size": fmt.Sprintf("%d", current.size),
			},
			OccurredAt: now.UTC().Format(time.RFC3339),
		})
		d.reported[path] = now
	}

	d.firstRun = false
	return events
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func fileSeverity(path string) string {
	base := filepath.Base(path)

	// Critical: sudoers, authorized_keys
	if base == "sudoers" || base == "authorized_keys" || strings.Contains(path, "sudoers.d/") {
		return "critical"
	}

	// Warning: shadow, sshd_config, crontab
	if base == "shadow" || base == "sshd_config" || base == "crontab" || strings.Contains(path, "cron.d/") {
		return "warning"
	}

	// Info: passwd, group, hosts, resolv.conf
	return "info"
}

