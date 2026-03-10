package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

var updateMu sync.Mutex

const targetPath = "/usr/local/bin/defensia-agent"
const backupPath = "/usr/local/bin/defensia-agent.bak"
const crashMarkerPath = "/tmp/defensia-agent-crash-count"
const maxCrashesBeforeRollback = 3

// EventReporter is a callback to send events to the server without
// coupling the updater to the full API client.
type EventReporter func(eventType, severity string, details map[string]string)

// CheckStartupHealth should be called once at agent startup. It detects
// repeated crash loops after an update and automatically rolls back to the
// previous binary. The crash marker is a simple file in /tmp that holds
// a count — it gets cleared after 2 minutes of stable running.
func CheckStartupHealth(currentVersion string, reportEvent EventReporter) {
	// Read crash counter
	data, err := os.ReadFile(crashMarkerPath)
	crashes := 0
	if err == nil {
		fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &crashes)
	}

	// If backup exists and we've crashed too many times, rollback
	if crashes >= maxCrashesBeforeRollback {
		if _, err := os.Stat(backupPath); err == nil {
			log.Printf("[updater] detected %d consecutive crashes — rolling back to backup", crashes)
			stagingPath := targetPath + ".new"
			if err := copyFile(backupPath, stagingPath); err == nil {
				if err := os.Rename(stagingPath, targetPath); err == nil {
					os.Remove(crashMarkerPath)
					log.Printf("[updater] rollback successful, restarting with previous version")
					if reportEvent != nil {
						logs := recentLogs(30)
						details := map[string]string{
							"version_before_rollback": currentVersion,
							"crashes":                 fmt.Sprintf("%d", crashes),
							"reason":                  "repeated_crash_after_update",
							"arch":                    runtime.GOARCH,
						}
						if logs != "" {
							details["recent_logs"] = logs
						}
						reportEvent("update_rollback", "critical", details)
					}
					restartService()
					return
				}
				os.Remove(stagingPath)
			}
			log.Printf("[updater] rollback failed — manual intervention needed")
			if reportEvent != nil {
				reportEvent("update_rollback_failed", "critical", map[string]string{
					"version":  currentVersion,
					"crashes":  fmt.Sprintf("%d", crashes),
					"reason":   "rollback_copy_or_rename_failed",
				})
			}
		}
		return
	}

	// Increment crash counter (assume we might crash)
	os.WriteFile(crashMarkerPath, []byte(fmt.Sprintf("%d", crashes+1)), 0644)

	// After 2 minutes of stable running, clear the counter
	go func() {
		time.Sleep(2 * time.Minute)
		os.Remove(crashMarkerPath)
		if crashes > 0 {
			log.Printf("[updater] agent stable for 2min — cleared crash counter (was %d)", crashes)
			if reportEvent != nil {
				reportEvent("update_stable", "info", map[string]string{
					"version":           currentVersion,
					"previous_crashes":  fmt.Sprintf("%d", crashes),
				})
			}
		}
	}()
}

// CheckAndUpdate compares the current version with the latest version.
// If a newer version is available, it downloads, verifies, runs a preflight
// check, and only then replaces the binary with automatic rollback on failure.
// The reportEvent callback is used to notify the server about update outcomes.
func CheckAndUpdate(currentVersion, latestVersion, downloadBaseURL string, reportEvent EventReporter) {
	if latestVersion == "" || downloadBaseURL == "" {
		return
	}

	if !isNewer(currentVersion, latestVersion) {
		return
	}

	if !updateMu.TryLock() {
		return // another update already in progress
	}
	defer updateMu.Unlock()

	log.Printf("[updater] new version available: %s -> %s", currentVersion, latestVersion)

	arch := runtime.GOARCH // amd64 or arm64
	binaryName := fmt.Sprintf("defensia-agent-linux-%s", arch)
	checksumName := fmt.Sprintf("%s.sha256", binaryName)

	binaryURL := fmt.Sprintf("%s/%s", strings.TrimRight(downloadBaseURL, "/"), binaryName)
	checksumURL := fmt.Sprintf("%s/%s", strings.TrimRight(downloadBaseURL, "/"), checksumName)

	versionDetails := map[string]string{
		"current_version": currentVersion,
		"target_version":  latestVersion,
		"arch":            arch,
		"download_url":    binaryURL,
	}

	// Report update_started so we know an attempt was made even if process dies mid-update
	reportEvent("update_started", "info", versionDetails)

	// 1. Download checksum
	expectedHash, err := downloadText(checksumURL)
	if err != nil {
		log.Printf("[updater] failed to download checksum: %v", err)
		reportFailure(reportEvent, "high", mergeDetails(versionDetails, map[string]string{
			"reason": "download_failed", "error": fmt.Sprintf("checksum download: %v", err),
		}))
		return
	}
	expectedHash = strings.TrimSpace(strings.Fields(expectedHash)[0])

	// 2. Download binary to temp file
	tmpFile, err := os.CreateTemp("", "defensia-agent-update-*")
	if err != nil {
		log.Printf("[updater] failed to create temp file: %v", err)
		return
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()

	if err := downloadFile(binaryURL, tmpPath); err != nil {
		log.Printf("[updater] failed to download binary: %v", err)
		os.Remove(tmpPath)
		reportFailure(reportEvent, "high", mergeDetails(versionDetails, map[string]string{
			"reason": "download_failed", "error": fmt.Sprintf("binary download: %v", err),
		}))
		return
	}

	// 3. Verify checksum
	actualHash, err := fileHash(tmpPath)
	if err != nil {
		log.Printf("[updater] failed to hash downloaded binary: %v", err)
		os.Remove(tmpPath)
		return
	}

	if actualHash != expectedHash {
		log.Printf("[updater] checksum mismatch: expected %s, got %s", expectedHash, actualHash)
		os.Remove(tmpPath)
		reportFailure(reportEvent, "high", mergeDetails(versionDetails, map[string]string{
			"reason": "checksum_mismatch",
			"error":  fmt.Sprintf("expected %s, got %s", expectedHash[:16], actualHash[:16]),
		}))
		return
	}

	log.Printf("[updater] checksum verified")

	// 4. Make downloaded binary executable
	if err := os.Chmod(tmpPath, 0755); err != nil {
		log.Printf("[updater] failed to chmod: %v", err)
		os.Remove(tmpPath)
		return
	}

	// 5. PRE-FLIGHT CHECK: run the new binary with "check" to verify it works
	out, err := exec.Command(tmpPath, "check").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "OK") {
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		}
		log.Printf("[updater] pre-flight check FAILED (err=%v, output=%q) — aborting update", err, string(out))
		os.Remove(tmpPath)
		reportFailure(reportEvent, "critical", mergeDetails(versionDetails, map[string]string{
			"reason": "preflight_failed",
			"error":  errMsg,
			"output": strings.TrimSpace(string(out)),
		}))
		return
	}
	log.Printf("[updater] pre-flight check passed: %s", strings.TrimSpace(string(out)))

	// 6. BACKUP current binary before replacing
	if err := copyFile(targetPath, backupPath); err != nil {
		log.Printf("[updater] failed to backup current binary: %v", err)
		os.Remove(tmpPath)
		return
	}
	log.Printf("[updater] backed up current binary to %s", backupPath)

	// 7. Replace binary — use staging on same filesystem + atomic rename.
	// On Linux, rename(2) atomically replaces the target even if it's a running
	// executable (unlike open(O_WRONLY) which gives ETXTBSY). We NEVER remove
	// the old binary first, so there's no window where the binary is missing.
	stagingPath := targetPath + ".new"
	if err := copyFile(tmpPath, stagingPath); err != nil {
		log.Printf("[updater] CRITICAL: failed to stage new binary: %v — aborting (old binary still in place)", err)
		os.Remove(tmpPath)
		reportFailure(reportEvent, "critical", mergeDetails(versionDetails, map[string]string{
			"reason": "replace_failed", "error": fmt.Sprintf("staging copy: %v", err),
		}))
		return
	}
	os.Remove(tmpPath)
	if err := os.Rename(stagingPath, targetPath); err != nil {
		log.Printf("[updater] CRITICAL: failed to rename staging binary: %v — aborting (old binary still in place)", err)
		os.Remove(stagingPath)
		reportFailure(reportEvent, "critical", mergeDetails(versionDetails, map[string]string{
			"reason": "replace_failed", "error": fmt.Sprintf("staging rename: %v", err),
		}))
		return
	}

	// 8. Verify the target binary exists
	if _, err := os.Stat(targetPath); err != nil {
		log.Printf("[updater] CRITICAL: binary not found at %s after replace — rolling back", targetPath)
		rollback()
		reportFailure(reportEvent, "critical", mergeDetails(versionDetails, map[string]string{
			"reason": "binary_missing_after_replace", "error": err.Error(),
		}))
		return
	}

	log.Printf("[updater] updated to v%s, restarting service...", latestVersion)

	// 9. Report success BEFORE restart (restart kills the current process)
	// Enrich with checksum for audit trail
	versionDetails["checksum_sha256"] = expectedHash
	reportEvent("update_completed", "info", versionDetails)

	// 10. Restart the service.
	// IMPORTANT: systemctl restart sends SIGTERM to the current process (we ARE
	// the service). The exec.Command will return an error ("signal: terminated")
	// because our own process is dying. This is EXPECTED — do NOT rollback here.
	// The binary is verified and in place. If the new binary fails to start,
	// CheckStartupHealth() handles rollback via crash-loop detection.
	restartService()
}

// reportFailure is a convenience wrapper that attaches recent service logs
// to the event details before reporting an update failure.
func reportFailure(reportEvent EventReporter, severity string, details map[string]string) {
	if logs := recentLogs(50); logs != "" {
		details["recent_logs"] = logs
	}
	reportEvent("update_failed", severity, details)
}

// mergeDetails merges two maps, with b overriding a.
func mergeDetails(a, b map[string]string) map[string]string {
	m := make(map[string]string, len(a)+len(b))
	for k, v := range a {
		m[k] = v
	}
	for k, v := range b {
		m[k] = v
	}
	return m
}

// rollback restores the backup binary to the target path using atomic rename.
func rollback() {
	if _, err := os.Stat(backupPath); err != nil {
		log.Printf("[updater] no backup found at %s — cannot rollback", backupPath)
		return
	}
	stagingPath := targetPath + ".rollback"
	if err := copyFile(backupPath, stagingPath); err != nil {
		log.Printf("[updater] CRITICAL: rollback staging failed: %v", err)
		return
	}
	if err := os.Rename(stagingPath, targetPath); err != nil {
		log.Printf("[updater] CRITICAL: rollback rename failed: %v", err)
		os.Remove(stagingPath)
		return
	}
	log.Printf("[updater] rolled back to previous version from %s", backupPath)
}

// restartService tries systemd, then upstart, then sysvinit.
// Returns an error if all methods fail.
func restartService() error {
	// systemd
	if _, err := exec.LookPath("systemctl"); err == nil {
		if err := exec.Command("systemctl", "restart", "defensia-agent").Run(); err == nil {
			return nil
		} else {
			log.Printf("[updater] systemctl restart failed: %v", err)
		}
	}

	// upstart
	if _, err := exec.LookPath("initctl"); err == nil {
		if err := exec.Command("initctl", "restart", "defensia-agent").Run(); err == nil {
			return nil
		} else {
			log.Printf("[updater] initctl restart failed: %v", err)
		}
	}

	// sysvinit
	initScript := "/etc/init.d/defensia-agent"
	if _, err := os.Stat(initScript); err == nil {
		if err := exec.Command(initScript, "restart").Run(); err == nil {
			return nil
		} else {
			log.Printf("[updater] sysvinit restart failed: %v", err)
		}
	}

	return fmt.Errorf("no init system could restart the service")
}

// isNewer returns true if latest > current using simple semver comparison.
func isNewer(current, latest string) bool {
	current = strings.TrimPrefix(current, "v")
	latest = strings.TrimPrefix(latest, "v")
	return compareSemver(latest, current) > 0
}

func compareSemver(a, b string) int {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")

	for i := 0; i < 3; i++ {
		av, bv := 0, 0
		if i < len(aParts) {
			fmt.Sscanf(aParts[i], "%d", &av)
		}
		if i < len(bParts) {
			fmt.Sscanf(bParts[i], "%d", &bv)
		}
		if av > bv {
			return 1
		}
		if av < bv {
			return -1
		}
	}
	return 0
}

func downloadText(url string) (string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func downloadFile(url, dest string) error {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body)
	return err
}

func fileHash(path string) (string, error) {
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

// recentLogs captures the last N lines from the agent's systemd journal.
// Returns empty string if journalctl is not available.
func recentLogs(lines int) string {
	if _, err := exec.LookPath("journalctl"); err != nil {
		return ""
	}
	out, err := exec.Command("journalctl", "-u", "defensia-agent", "--no-pager",
		"-n", fmt.Sprintf("%d", lines), "--output", "short-iso").CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	// Create with execute permission from the start, so even if the process
	// is killed mid-copy, the file is already executable.
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}

	// Sync to disk before we rename — ensures the full binary is persisted
	// even if the system crashes or the process is killed shortly after.
	return out.Sync()
}
