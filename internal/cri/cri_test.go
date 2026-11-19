package cri

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

// oneContainer is a ListContainersResponse the way a runtime would send it.
func oneContainer(id, name, pod, namespace, image, sandbox string) []byte {
	metadata := protowire.AppendTag(nil, fMetadataName, protowire.BytesType)
	metadata = protowire.AppendString(metadata, name)

	imageSpec := protowire.AppendTag(nil, fImageSpecUserSpecifiedName, protowire.BytesType)
	imageSpec = protowire.AppendString(imageSpec, image)

	c := protowire.AppendTag(nil, fContainerID, protowire.BytesType)
	c = protowire.AppendString(c, id)
	c = protowire.AppendTag(c, fContainerSandboxID, protowire.BytesType)
	c = protowire.AppendString(c, sandbox)
	c = protowire.AppendTag(c, fContainerMetadata, protowire.BytesType)
	c = protowire.AppendBytes(c, metadata)
	c = protowire.AppendTag(c, fContainerImage, protowire.BytesType)
	c = protowire.AppendBytes(c, imageSpec)
	c = protowire.AppendTag(c, fContainerState, protowire.VarintType)
	c = protowire.AppendVarint(c, stateRunning)
	c = appendMapEntry(c, fContainerLabels, labelPodName, pod)
	c = appendMapEntry(c, fContainerLabels, labelPodNamespace, namespace)

	list := protowire.AppendTag(nil, fListContainersContainers, protowire.BytesType)
	return protowire.AppendBytes(list, c)
}

func appendMapEntry(b []byte, field protowire.Number, key, value string) []byte {
	entry := protowire.AppendTag(nil, fMapKey, protowire.BytesType)
	entry = protowire.AppendString(entry, key)
	entry = protowire.AppendTag(entry, fMapValue, protowire.BytesType)
	entry = protowire.AppendString(entry, value)

	b = protowire.AppendTag(b, field, protowire.BytesType)
	return protowire.AppendBytes(b, entry)
}

// containerStatus is a ContainerStatusResponse carrying a verbose info blob.
func containerStatus(running bool, infoJSON string) []byte {
	state := uint64(2) // CONTAINER_EXITED
	if running {
		state = stateRunning
	}

	status := protowire.AppendTag(nil, fContainerStatusState, protowire.VarintType)
	status = protowire.AppendVarint(status, state)

	b := protowire.AppendTag(nil, fStatusResponseStatus, protowire.BytesType)
	b = protowire.AppendBytes(b, status)

	if infoJSON != "" {
		b = appendMapEntry(b, fStatusResponseInfo, "info", infoJSON)
	}

	return b
}

// sandboxStatus is a PodSandboxStatusResponse with a namespace mode and an info
// blob.
func sandboxStatus(networkMode uint64, infoJSON string) []byte {
	options := protowire.AppendTag(nil, fNamespaceOptionNetwork, protowire.VarintType)
	options = protowire.AppendVarint(options, networkMode)

	namespaces := protowire.AppendTag(nil, fNamespaceOptions, protowire.BytesType)
	namespaces = protowire.AppendBytes(namespaces, options)

	linux := protowire.AppendTag(nil, fLinuxSandboxNamespaces, protowire.BytesType)
	linux = protowire.AppendBytes(linux, namespaces)

	status := protowire.AppendTag(nil, fSandboxStatusLinux, protowire.BytesType)
	status = protowire.AppendBytes(status, linux)

	b := protowire.AppendTag(nil, fStatusResponseStatus, protowire.BytesType)
	b = protowire.AppendBytes(b, status)

	if infoJSON != "" {
		b = appendMapEntry(b, fStatusResponseInfo, "info", infoJSON)
	}

	return b
}

// The whole package through its public entry point, against a runtime that
// answers the way containerd does.
func TestContainersResolvesPidsAndExposure(t *testing.T) {
	server := fakeCRI{
		reply: func(method string, _ []byte) ([]byte, int, string) {
			switch method {
			case methodListContainers:
				return oneContainer("c1", "nginx", "shop-nginx", "cliente", "nginx:1.27-alpine", "s1"), 0, ""
			case methodContainerStatus:
				return containerStatus(true, `{"pid":4242,"sandboxID":"s1","snapshotKey":"abc"}`), 0, ""
			case methodPodSandboxStatus:
				return sandboxStatus(0, `{"config":{"port_mappings":[{"container_port":80,"host_port":8081}]}}`), 0, ""
			}
			return nil, 12, "unimplemented"
		},
	}.start(t)

	t.Setenv("CONTAINER_RUNTIME_ENDPOINT", server.socket)

	containers, err := Containers(context.Background())
	if err != nil {
		t.Fatalf("Containers: %v", err)
	}

	if len(containers) != 1 {
		t.Fatalf("want 1 container, got %d", len(containers))
	}

	got := containers[0]
	if got.Pid != 4242 {
		t.Errorf("Pid = %d, want 4242", got.Pid)
	}
	if !got.Running {
		t.Error("the container is running")
	}
	if got.PodNamespace != "cliente" || got.PodName != "shop-nginx" || got.Name != "nginx" {
		t.Errorf("identity lost: %+v", got)
	}
	if got.Image != "nginx:1.27-alpine" {
		t.Errorf("Image = %q", got.Image)
	}
	if !got.Exposed() || len(got.HostPorts) != 1 || got.HostPorts[0] != 8081 {
		t.Errorf("exposure not read: exposed=%v ports=%v", got.Exposed(), got.HostPorts)
	}
	if got.HostNetwork {
		t.Error("this sandbox does not use hostNetwork")
	}

	// An HTTP/2 connection sits in the transport's pool with a read goroutine
	// holding it open, so it is not collected when the transport goes out of
	// scope. One leaked socket and goroutine per inventory run, on a process
	// that runs for months, would be carried for the agent's whole uptime.
	select {
	case <-server.ended:
	case <-time.After(5 * time.Second):
		t.Error("the connection to the runtime was never released")
	}
}

// hostNetwork is the one exposure fact every runtime reports identically, and it
// has to count as exposure on its own: a pod on the node's network namespace is
// reachable exactly as the node is, whatever it publishes.
func TestAHostNetworkPodIsExposedWithoutAnyPorts(t *testing.T) {
	server := fakeCRI{
		reply: func(method string, _ []byte) ([]byte, int, string) {
			switch method {
			case methodListContainers:
				return oneContainer("c1", "agent", "defensia-agent-x", "defensia", "ghcr.io/defensia/agent", "s1"), 0, ""
			case methodContainerStatus:
				return containerStatus(true, `{"pid":99}`), 0, ""
			case methodPodSandboxStatus:
				return sandboxStatus(namespaceModeNode, `{"config":{}}`), 0, ""
			}
			return nil, 12, "unimplemented"
		},
	}.start(t)

	t.Setenv("CONTAINER_RUNTIME_ENDPOINT", server.socket)

	containers, err := Containers(context.Background())
	if err != nil {
		t.Fatalf("Containers: %v", err)
	}

	if !containers[0].HostNetwork {
		t.Error("the pod shares the node's network namespace and must read as such")
	}
	if !containers[0].Exposed() {
		t.Error("a hostNetwork pod is reachable from outside the node even with no published ports")
	}
}

// A container the runtime will not describe still has to come back, with Pid
// zero, so the inventory can report it as present and unidentified. Dropping it
// here would make it invisible further up, and an unreadable container must
// never look like no container.
func TestAContainerTheRuntimeWillNotDescribeIsStillReturned(t *testing.T) {
	server := fakeCRI{
		reply: func(method string, _ []byte) ([]byte, int, string) {
			switch method {
			case methodListContainers:
				return oneContainer("c1", "nginx", "shop-nginx", "cliente", "nginx:alpine", "s1"), 0, ""
			case methodContainerStatus:
				return nil, 5, "container not found" // NOT_FOUND
			case methodPodSandboxStatus:
				return sandboxStatus(0, `{"config":{}}`), 0, ""
			}
			return nil, 12, "unimplemented"
		},
	}.start(t)

	t.Setenv("CONTAINER_RUNTIME_ENDPOINT", server.socket)

	containers, err := Containers(context.Background())
	if err != nil {
		t.Fatalf("Containers must not fail because one container did not answer: %v", err)
	}

	if len(containers) != 1 {
		t.Fatalf("want the container reported anyway, got %d", len(containers))
	}
	if containers[0].Pid != 0 {
		t.Errorf("Pid = %d, want 0: nothing was read", containers[0].Pid)
	}
}

// A runtime that reports a container as no longer running is reporting a corpse,
// and the inventory needs to tell that apart from a container it could not read.
func TestAContainerThatStoppedMidPassIsMarkedNotRunning(t *testing.T) {
	server := fakeCRI{
		reply: func(method string, _ []byte) ([]byte, int, string) {
			switch method {
			case methodListContainers:
				return oneContainer("c1", "nginx", "shop-nginx", "cliente", "nginx:alpine", "s1"), 0, ""
			case methodContainerStatus:
				return containerStatus(false, `{}`), 0, ""
			case methodPodSandboxStatus:
				return sandboxStatus(0, `{"config":{}}`), 0, ""
			}
			return nil, 12, "unimplemented"
		},
	}.start(t)

	t.Setenv("CONTAINER_RUNTIME_ENDPOINT", server.socket)

	containers, err := Containers(context.Background())
	if err != nil {
		t.Fatalf("Containers: %v", err)
	}

	if containers[0].Running {
		t.Error("the runtime said the container had exited")
	}
	if containers[0].Pid != 0 {
		t.Errorf("Pid = %d, want 0", containers[0].Pid)
	}
}

// A runtime that refuses the container list is not a node with no containers,
// and the difference must reach the caller. This is the failure that would
// matter most: a socket mounted read-only by the wrong user, or a runtime
// speaking an interface we do not, reported as a clean node.
func TestARefusedListIsAnErrorNotAnEmptyNode(t *testing.T) {
	server := fakeCRI{
		reply: func(string, []byte) ([]byte, int, string) {
			return nil, 7, "permission denied"
		},
	}.start(t)

	t.Setenv("CONTAINER_RUNTIME_ENDPOINT", server.socket)

	containers, err := Containers(context.Background())
	if err == nil {
		t.Fatal("a refused ListContainers returned no error")
	}
	if errors.Is(err, ErrNoRuntime) {
		t.Error("a refused call is not the same as no runtime being present")
	}
	if len(containers) != 0 {
		t.Errorf("want no containers alongside the error, got %d", len(containers))
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("the error must say what the runtime said: %v", err)
	}
}

// No socket anywhere is the ordinary case on a plain server, and it has to be
// distinguishable from a runtime that would not answer.
func TestNoRuntimeIsItsOwnSentinel(t *testing.T) {
	t.Setenv("CONTAINER_RUNTIME_ENDPOINT", "")

	// With the env cleared, discovery runs. On a machine that genuinely has a
	// runtime this is not the case under test.
	if Endpoint() != "" {
		t.Skip("this machine has a container runtime")
	}

	_, err := Containers(context.Background())
	if !errors.Is(err, ErrNoRuntime) {
		t.Errorf("want ErrNoRuntime, got %v", err)
	}
}

// A pass that runs out of time has to say so. Returning the containers it got
// to, with the rest unidentified, would look like a node of unreadable images
// rather than like an enumeration that was cut short — and the versions already
// read would be reported as if the inventory were complete.
func TestAnExpiredBudgetEndsThePassWithAnError(t *testing.T) {
	server := fakeCRI{
		reply: func(method string, _ []byte) ([]byte, int, string) {
			if method == methodListContainers {
				return oneContainer("c1", "nginx", "shop-nginx", "cliente", "nginx:alpine", "s1"), 0, ""
			}
			return containerStatus(true, `{"pid":4242}`), 0, ""
		},
	}.start(t)

	t.Setenv("CONTAINER_RUNTIME_ENDPOINT", server.socket)

	// Cancelled after the list call succeeds, which is the window the loop has
	// to notice.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	containers, err := Containers(ctx)
	if err == nil {
		t.Fatal("a cancelled pass returned no error")
	}
	if len(containers) != 0 {
		t.Errorf("want nothing alongside the error, got %d containers", len(containers))
	}
}
