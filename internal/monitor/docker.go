package monitor

import (
	"os"
	"os/exec"
	"sync"
)

// dockerBinaryPaths are known locations for the Docker CLI binary.
var dockerBinaryPaths = []string{
	"docker",                        // PATH lookup (standard installs)
	"/usr/bin/docker",               // Debian/Ubuntu/RHEL packages
	"/usr/local/bin/docker",         // manual installs, Homebrew
	"/snap/bin/docker",              // Snap installs (Ubuntu)
	"/usr/libexec/docker/cli-plugins/docker", // some Docker Desktop installs
}

var (
	dockerBinary     string
	dockerBinaryOnce sync.Once
)

// FindDockerBinary returns the path to the Docker CLI binary, or "" if not found.
// It first tries exec.LookPath, then checks well-known paths, then checks for
// the Docker socket (which proves Docker daemon is running even if CLI is missing).
// The result is cached after the first call.
func FindDockerBinary() string {
	dockerBinaryOnce.Do(func() {
		// 1. Standard PATH lookup
		if path, err := exec.LookPath("docker"); err == nil {
			dockerBinary = path
			return
		}

		// 2. Check well-known paths
		for _, p := range dockerBinaryPaths[1:] { // skip "docker" (already tried via LookPath)
			if _, err := os.Stat(p); err == nil {
				dockerBinary = p
				return
			}
		}

		// 3. Check Podman as Docker-compatible alternative
		if path, err := exec.LookPath("podman"); err == nil {
			dockerBinary = path
			return
		}
	})
	return dockerBinary
}

// HasDockerSocket returns true if the Docker daemon socket exists,
// indicating Docker is running even if the CLI binary isn't in PATH.
func HasDockerSocket() bool {
	for _, sock := range []string{
		"/var/run/docker.sock",
		"/run/docker.sock",
		"/run/podman/podman.sock",
	} {
		if fi, err := os.Stat(sock); err == nil && fi.Mode()&os.ModeSocket != 0 {
			return true
		}
	}
	return false
}
