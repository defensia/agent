package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

// dockerSocketPaths are the locations to check for the Docker daemon socket.
var dockerSocketPaths = []string{
	"/var/run/docker.sock",
	"/run/docker.sock",
	"/run/podman/podman.sock",
}

// findDockerSocket returns the first existing Docker/Podman socket path, or "".
func findDockerSocket() string {
	for _, sock := range dockerSocketPaths {
		if fi, err := os.Stat(sock); err == nil && fi.Mode()&os.ModeSocket != 0 {
			return sock
		}
	}
	return ""
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
