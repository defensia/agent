package cri

import (
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// k3s does not put its socket where containerd's upstream default is, and a
// chart that probed only the upstream path found nothing on a k3s node —
// measured on the lab cluster, where the socket is at
// /run/k3s/containerd/containerd.sock. The list has to carry the paths the
// distributions actually use, not the one the documentation implies.
func TestTheEndpointListCoversTheDistributionsWeSupport(t *testing.T) {
	required := []string{
		"/run/containerd/containerd.sock",                        // containerd upstream
		"/run/k3s/containerd/containerd.sock",                    // k3s, k3d, RKE2
		"/var/lib/rancher/rke2/agent/containerd/containerd.sock", // RKE2 agent-local
		"/var/snap/microk8s/common/run/containerd.sock",          // MicroK8s
		"/run/crio/crio.sock",                                    // CRI-O
	}

	for _, path := range required {
		if !slices.Contains(knownEndpoints, path) {
			t.Errorf("%s is not probed: a node running it reports no containers at all", path)
		}
	}
}

// The same escape hatch WEB_LOG_PATH is for log autodetection, and crictl's own
// variable, so a node already configured for crictl needs nothing new.
func TestTheEnvironmentOverridesTheSearch(t *testing.T) {
	cases := []struct {
		set  string
		want string
	}{
		{"/tmp/custom-runtime.sock", "/tmp/custom-runtime.sock"},
		// crictl's form carries a scheme, which is not a path.
		{"unix:///tmp/custom-runtime.sock", "/tmp/custom-runtime.sock"},
	}

	for _, c := range cases {
		t.Setenv("CONTAINER_RUNTIME_ENDPOINT", c.set)

		if got := Endpoint(); got != c.want {
			t.Errorf("Endpoint() with CONTAINER_RUNTIME_ENDPOINT=%q = %q, want %q", c.set, got, c.want)
		}
	}
}

// A path that exists but is not a socket must not be taken for a runtime. This
// is not hypothetical: the kubelet silently creates a *directory* where a
// missing socket was mounted from, which is how the chart ended up with a
// directory named docker.sock on every node that had no Docker.
func TestOnlyAnActualSocketCounts(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "cri")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	regular := filepath.Join(dir, "regular-file.sock")
	if err := os.WriteFile(regular, nil, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	directory := filepath.Join(dir, "directory.sock")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	socket := filepath.Join(dir, "real.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	if isSocket(regular) {
		t.Error("a regular file read as a socket")
	}
	if isSocket(directory) {
		t.Error("a directory read as a socket")
	}
	if isSocket(filepath.Join(dir, "absent.sock")) {
		t.Error("a path that does not exist read as a socket")
	}
	if !isSocket(socket) {
		t.Error("a real unix socket did not read as one")
	}
}
