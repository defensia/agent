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

// CheckAndUpdate compares the current version with the latest version.
// If a newer version is available, it downloads, verifies, and replaces the binary.
// A mutex prevents concurrent calls (heartbeat + sync) from racing.
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

	// Download checksum
	expectedHash, err := downloadText(checksumURL)
	if err != nil {
		log.Printf("[updater] failed to download checksum: %v", err)
		return
	}
	expectedHash = strings.TrimSpace(strings.Fields(expectedHash)[0])

	// Download binary to unique temp file to avoid conflicts
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

	// Verify checksum
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

	log.Printf("[updater] checksum verified, replacing binary...")

	// Replace the current binary
	targetPath := "/usr/local/bin/defensia-agent"
	if err := os.Chmod(tmpPath, 0755); err != nil {
		log.Printf("[updater] failed to chmod: %v", err)
		os.Remove(tmpPath)
		return
	}

	// Try atomic rename first (works if same filesystem)
	if err := os.Rename(tmpPath, targetPath); err != nil {
		// Cross-device or "text file busy": copy to a staging path next to
		// the target, then atomic-rename the staging file into place.
		stagingPath := targetPath + ".new"
		if err := copyFile(tmpPath, stagingPath); err != nil {
			log.Printf("[updater] failed to copy to staging: %v", err)
			os.Remove(tmpPath)
			os.Remove(stagingPath)
			return
		}
		os.Remove(tmpPath)

		// Remove old binary and rename staging into place.
		// Linux allows unlinking a running executable — the old inode stays
		// alive until the process exits, but the path becomes free.
		os.Remove(targetPath)
		if err := os.Rename(stagingPath, targetPath); err != nil {
			log.Printf("[updater] failed to rename staging binary: %v", err)
			os.Remove(stagingPath)
			return
		}
	}

	// Final safety check: verify the target binary exists and is executable
	if _, err := os.Stat(targetPath); err != nil {
		log.Printf("[updater] CRITICAL: binary not found at %s after replace — not restarting", targetPath)
		return
	}

	log.Printf("[updater] updated to v%s, restarting...", latestVersion)

	// Restart the service — detect init system
	restartService()
}

// restartService tries systemd, then upstart, then sysvinit.
func restartService() {
	// systemd
	if _, err := exec.LookPath("systemctl"); err == nil {
		if err := exec.Command("systemctl", "restart", "defensia-agent").Run(); err == nil {
			return
		}
		log.Printf("[updater] systemctl restart failed, trying alternatives...")
	}

	// upstart
	if _, err := exec.LookPath("initctl"); err == nil {
		if err := exec.Command("initctl", "restart", "defensia-agent").Run(); err == nil {
			return
		}
		log.Printf("[updater] initctl restart failed, trying alternatives...")
	}

	// sysvinit
	initScript := "/etc/init.d/defensia-agent"
	if _, err := os.Stat(initScript); err == nil {
		if err := exec.Command(initScript, "restart").Run(); err == nil {
			return
		}
		log.Printf("[updater] sysvinit restart failed")
	}

	log.Printf("[updater] could not restart service via any init system")
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
