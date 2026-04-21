package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// staticSocketPaths are well-known locations for Docker/Podman sockets.
var staticSocketPaths = []string{
	"/var/run/docker.sock",
	"/run/docker.sock",
	"/run/podman/podman.sock",
	"/var/snap/docker/common/run/docker.sock",      // Snap Docker
	"/run/user/0/docker.sock",                       // rootless Docker (root)
	"/run/user/0/podman/podman.sock",                // rootless Podman (root)
	"/var/run/podman/podman.sock",                   // system Podman
}

var (
	resolvedSocket     string
	resolvedSocketOnce sync.Once
)

// findDockerSocket returns the Docker/Podman socket path.
// First checks static paths, then scans /run for sockets if not found.
func findDockerSocket() string {
	resolvedSocketOnce.Do(func() {
		// 1. Check static well-known paths
		for _, sock := range staticSocketPaths {
			if isSocket(sock) {
				resolvedSocket = sock
				log.Printf("[docker] found socket at %s", sock)
				return
			}
		}

		// 2. Check rootless Docker/Podman for other UIDs in /run/user/
		entries, err := os.ReadDir("/run/user")
		if err == nil {
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				if _, err := strconv.Atoi(e.Name()); err != nil {
					continue
				}
				for _, name := range []string{"docker.sock", "podman/podman.sock"} {
					sock := filepath.Join("/run/user", e.Name(), name)
					if isSocket(sock) {
						resolvedSocket = sock
						log.Printf("[docker] found rootless socket at %s", sock)
						return
					}
				}
			}
		}

		// 3. Scan common directories for any docker*.sock or podman*.sock
		for _, dir := range []string{"/run", "/var/run", "/tmp"} {
			filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return nil
				}
				// Don't recurse too deep
				if strings.Count(path, "/") > 5 {
					return filepath.SkipDir
				}
				if info.Mode()&os.ModeSocket != 0 {
					base := strings.ToLower(info.Name())
					if strings.Contains(base, "docker") || strings.Contains(base, "podman") {
						resolvedSocket = path
						log.Printf("[docker] found socket via scan at %s", path)
						return fmt.Errorf("found") // stop walking
					}
				}
				return nil
			})
			if resolvedSocket != "" {
				return
			}
		}
	})
	return resolvedSocket
}

func isSocket(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode()&os.ModeSocket != 0
}

// dockerHTTPClient creates an HTTP client that talks over a Unix socket.
func dockerHTTPClient(sockPath string) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.DialTimeout("unix", sockPath, 5*time.Second)
			},
		},
	}
}

// DockerContainer represents a running container from the Docker API.
type DockerContainer struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Image  string            `json:"Image"`
	Labels map[string]string `json:"Labels"`
	Ports  []DockerPort      `json:"Ports"`
}

// DockerPort represents a port mapping.
type DockerPort struct {
	PrivatePort int    `json:"PrivatePort"`
	PublicPort  int    `json:"PublicPort"`
	Type        string `json:"Type"`
}

// DockerMount represents a bind mount from container inspect.
type DockerMount struct {
	Type        string `json:"Type"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
}

type dockerInspectResult struct {
	Mounts []DockerMount `json:"Mounts"`
}

// ListDockerContainers returns running containers via the Docker socket API.
// Falls back to CLI if socket is not available.
func ListDockerContainers() ([]DockerContainer, error) {
	sock := findDockerSocket()
	if sock == "" {
		return nil, fmt.Errorf("no docker socket found")
	}

	client := dockerHTTPClient(sock)
	filters := url.QueryEscape(`{"status":["running"]}`)
	resp, err := client.Get("http://localhost/containers/json?filters=" + filters)
	if err != nil {
		return nil, fmt.Errorf("docker API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("docker API read: %w", err)
	}

	var containers []DockerContainer
	if err := json.Unmarshal(body, &containers); err != nil {
		return nil, fmt.Errorf("docker API parse: %w", err)
	}

	return containers, nil
}

// InspectDockerMounts returns the bind mounts for a container via the Docker socket API.
func InspectDockerMounts(containerID string) map[string]string {
	sock := findDockerSocket()
	if sock == "" {
		return nil
	}

	client := dockerHTTPClient(sock)
	resp, err := client.Get("http://localhost/containers/" + containerID + "/json")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var result dockerInspectResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}

	mounts := make(map[string]string)
	for _, m := range result.Mounts {
		if m.Type == "bind" && m.Source != "" && m.Destination != "" {
			mounts[m.Destination] = m.Source
		}
	}
	return mounts
}

// DockerVersion returns the Docker daemon version via the socket API.
func DockerVersion() string {
	sock := findDockerSocket()
	if sock == "" {
		return ""
	}

	client := dockerHTTPClient(sock)
	resp, err := client.Get("http://localhost/version")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	var v struct {
		Version string `json:"Version"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return ""
	}
	return v.Version
}
