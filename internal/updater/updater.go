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

// CheckAndUpdate compares the current version with the latest version.
// If a newer version is available, it downloads, verifies, runs a preflight
// check, and only then replaces the binary with automatic rollback on failure.
func CheckAndUpdate(currentVersion, latestVersion, downloadBaseURL string) {
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

	// 1. Download checksum
	expectedHash, err := downloadText(checksumURL)
	if err != nil {
		log.Printf("[updater] failed to download checksum: %v", err)
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
		log.Printf("[updater] pre-flight check FAILED (err=%v, output=%q) — aborting update", err, string(out))
		os.Remove(tmpPath)
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

	// 7. Replace binary — unlink first (Linux allows unlinking a running executable),
	// then rename the new file into place. This avoids "text file busy".
	os.Remove(targetPath)
	if err := os.Rename(tmpPath, targetPath); err != nil {
		// Cross-device: copy + rename
		stagingPath := targetPath + ".new"
		if err := copyFile(tmpPath, stagingPath); err != nil {
			log.Printf("[updater] CRITICAL: failed to stage new binary: %v — rolling back", err)
			rollback()
			os.Remove(tmpPath)
			return
		}
		os.Remove(tmpPath)
		if err := os.Rename(stagingPath, targetPath); err != nil {
			log.Printf("[updater] CRITICAL: failed to rename staging binary: %v — rolling back", err)
			os.Remove(stagingPath)
			rollback()
			return
		}
	}

	// 8. Verify the target binary exists
	if _, err := os.Stat(targetPath); err != nil {
		log.Printf("[updater] CRITICAL: binary not found at %s after replace — rolling back", targetPath)
		rollback()
		return
	}

	log.Printf("[updater] updated to v%s, restarting service...", latestVersion)

	// 9. Restart the service
	if err := restartService(); err != nil {
		log.Printf("[updater] restart failed: %v — rolling back", err)
		rollback()
		// Try restart again with the old binary
		if err := restartService(); err != nil {
			log.Printf("[updater] CRITICAL: rollback restart also failed: %v", err)
		}
	}
}

// rollback restores the backup binary to the target path.
func rollback() {
	if _, err := os.Stat(backupPath); err != nil {
		log.Printf("[updater] no backup found at %s — cannot rollback", backupPath)
		return
	}
	os.Remove(targetPath)
	if err := copyFile(backupPath, targetPath); err != nil {
		log.Printf("[updater] CRITICAL: rollback copy failed: %v", err)
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

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}

	return out.Chmod(0755)
}
