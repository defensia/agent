//go:build integration

package cri

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestLabCaptureFixtures writes the raw CRI responses of a real runtime to disk,
// which is where the fixtures in testdata came from.
//
// It exists so those fixtures can be regenerated rather than trusted: run this
// on a node with a CRI socket, pointing CRI_FIXTURE_DIR at a writable directory,
// and copy the result into testdata. The unit tests then decode real bytes from
// a real runtime instead of bytes this package encoded itself, which would only
// prove it agrees with itself.
//
//	GOOS=linux GOARCH=arm64 go test -c -tags integration ./internal/cri
//	# on the node:
//	CRI_FIXTURE_DIR=/tmp/fx ./cri.test -test.run TestLabCaptureFixtures
func TestLabCaptureFixtures(t *testing.T) {
	dir := os.Getenv("CRI_FIXTURE_DIR")
	if dir == "" {
		t.Skip("set CRI_FIXTURE_DIR to capture fixtures")
	}

	endpoint := Endpoint()
	if endpoint == "" {
		t.Skip("no CRI socket on this machine")
	}

	ctx := context.Background()
	c := dial(endpoint)

	write := func(name string, b []byte) {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		t.Logf("wrote %s (%d bytes)", path, len(b))
	}

	list, err := c.call(ctx, methodListContainers, encodeListRunningContainers())
	if err != nil {
		t.Fatalf("ListContainers: %v", err)
	}
	write("list_containers.pb", list)

	containers, err := decodeListContainersResponse(list)
	if err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(containers) == 0 {
		t.Fatal("no running containers to capture")
	}

	status, err := c.call(ctx, methodContainerStatus, encodeStatusRequest(containers[0].ID, true))
	if err != nil {
		t.Fatalf("ContainerStatus: %v", err)
	}
	write("container_status.pb", status)

	// The info blob on its own, because it is the part whose shape differs
	// between runtimes and the part the parse tests are really about.
	info, _, err := decodeStatusResponse(status)
	if err != nil {
		t.Fatalf("decode status: %v", err)
	}
	write("container_info.json", []byte(info["info"]))

	for _, candidate := range containers {
		if candidate.SandboxID == "" {
			continue
		}

		sandbox, err := c.call(ctx, methodPodSandboxStatus, encodeStatusRequest(candidate.SandboxID, true))
		if err != nil {
			t.Fatalf("PodSandboxStatus: %v", err)
		}

		sandboxInfo, hostNetwork, err := decodeSandboxStatusResponse(sandbox)
		if err != nil {
			t.Fatalf("decode sandbox: %v", err)
		}

		// Capture a sandbox that actually publishes host ports if there is one,
		// and a hostNetwork sandbox too: an empty port list proves nothing.
		switch {
		case len(hostPortsFromInfo(sandboxInfo)) > 0:
			write("sandbox_status_hostports.pb", sandbox)
			write("sandbox_info_hostports.json", []byte(sandboxInfo["info"]))
		case hostNetwork:
			write("sandbox_status_hostnetwork.pb", sandbox)
		}
	}
}
