// Package cri enumerates the containers running on a node through the Container
// Runtime Interface, and finds the host PID of each one.
//
// It exists because the container inventory could only see Docker. On a
// Kubernetes node there is no Docker: the runtime is containerd or CRI-O, spoken
// to over the CRI, and so the agent reported nothing at all about what runs on
// the node it is installed on — on the whole K8s fleet, which is the product we
// sell per node.
//
// The host PID is the entire point of this package. Everything after it already
// exists: /proc/<pid>/root is a readable filesystem, internal/hostroot reads
// inside it safely, internal/pkgdb parses the package database it finds there,
// and internal/collector turns that into inventory rows. The CRI is only how the
// PID is obtained.
//
// Nothing here runs a process. No crictl, no nsenter, no exec into a container:
// two RPCs per container and file reads, so a wedged container cannot hang the
// agent and a node with fifty pods does not fork fifty times.
package cri

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"
)

// ErrNoRuntime means no CRI socket was found on this machine, which is the
// ordinary case on a plain server and not a failure.
var ErrNoRuntime = errors.New("no CRI endpoint found")

// Container is one running container as the node's own runtime describes it.
type Container struct {
	ID        string
	SandboxID string

	// Name, PodName and PodNamespace come from the labels the kubelet sets, so
	// they are empty when something other than Kubernetes drives the runtime.
	Name         string
	PodName      string
	PodNamespace string

	Image string

	// Pid is the host PID of the container's main process, or zero when the
	// runtime did not report one. Zero is "unknown" and never PID 0.
	Pid int

	Running bool

	// HostNetwork means the pod shares the node's network namespace, so whatever
	// it listens on is reachable exactly as the node is. Reported identically by
	// every CRI runtime.
	HostNetwork bool

	// HostPorts are the published ports reachable from outside the node.
	// containerd reports these; CRI-O does not expose them over the CRI at all,
	// so on CRI-O this is empty and says nothing either way.
	HostPorts []int
}

// Exposed reports whether this container is reachable from outside the node.
func (c Container) Exposed() bool {
	return c.HostNetwork || len(c.HostPorts) > 0
}

const (
	runtimeService         = "/runtime.v1.RuntimeService"
	methodListContainers   = runtimeService + "/ListContainers"
	methodContainerStatus  = runtimeService + "/ContainerStatus"
	methodPodSandboxStatus = runtimeService + "/PodSandboxStatus"
)

// Containers returns every running container on this machine, with the host PID
// of each one where the runtime gave it up.
//
// A container whose PID could not be read is still returned, with Pid zero. That
// is the contract the rest of the inventory depends on: a container the agent
// cannot identify has to be reported as present and unidentified, because
// dropping it makes an unreadable container indistinguishable from no container
// at all — and this is a security inventory, where those two must never look the
// same.
func Containers(ctx context.Context) ([]Container, error) {
	endpoint := Endpoint()
	if endpoint == "" {
		return nil, ErrNoRuntime
	}

	started := time.Now()

	c := dial(endpoint)
	defer c.close()

	response, err := c.call(ctx, methodListContainers, encodeListRunningContainers())
	if err != nil {
		return nil, err
	}

	containers, err := decodeListContainersResponse(response)
	if err != nil {
		return nil, fmt.Errorf("cri: decode container list: %w", err)
	}

	calls := 1
	sandboxes := make(map[string]sandboxExposure)

	for i := range containers {
		// An expired budget has to end the pass, not run it out one container at
		// a time. Carrying on would return every remaining container as
		// unidentified, which looks like a node of unreadable images rather than
		// like a pass that ran out of time — and the versions already read would
		// be reported alongside, as if the inventory were complete.
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("cri: enumeration cut short after %d of %d containers: %w", i, len(containers), err)
		}

		pid, running, err := c.containerPid(ctx, containers[i].ID)
		calls++
		if err != nil {
			// Logged and carried: one container the runtime will not talk about
			// must not cost us the other forty.
			log.Printf("[cri] container %s: %v", short(containers[i].ID), err)
		}
		containers[i].Pid = pid

		// ListContainers already filtered on running, so a container that is no
		// longer running stopped in between. Keeping the list's answer would
		// report a corpse.
		if err == nil {
			containers[i].Running = running
		}

		if containers[i].SandboxID == "" {
			continue
		}

		exposure, known := sandboxes[containers[i].SandboxID]
		if !known {
			exposure = c.sandboxExposure(ctx, containers[i].SandboxID)
			calls++
			sandboxes[containers[i].SandboxID] = exposure
		}

		containers[i].HostNetwork = exposure.hostNetwork
		containers[i].HostPorts = exposure.hostPorts
	}

	log.Printf("[cri] %s: %d containers, %d sandboxes, %d rpcs in %s",
		endpoint, len(containers), len(sandboxes), calls, time.Since(started).Round(time.Millisecond))

	return containers, nil
}

// containerPid asks the runtime for one container's verbose status and pulls the
// host PID out of it.
func (c *conn) containerPid(ctx context.Context, id string) (pid int, running bool, err error) {
	response, err := c.call(ctx, methodContainerStatus, encodeStatusRequest(id, true))
	if err != nil {
		return 0, false, err
	}

	info, running, err := decodeStatusResponse(response)
	if err != nil {
		return 0, false, fmt.Errorf("decode status: %w", err)
	}

	return pidFromInfo(info), running, nil
}

type sandboxExposure struct {
	hostNetwork bool
	hostPorts   []int
}

// sandboxExposure reads how a pod is reachable from outside the node.
//
// Failure is silent here, unlike the PID: exposure that cannot be read leaves a
// container reported with its version and no exposure flag, which is a smaller
// and more recoverable loss than not reporting the container.
func (c *conn) sandboxExposure(ctx context.Context, sandboxID string) sandboxExposure {
	response, err := c.call(ctx, methodPodSandboxStatus, encodeStatusRequest(sandboxID, true))
	if err != nil {
		log.Printf("[cri] sandbox %s: %v", short(sandboxID), err)
		return sandboxExposure{}
	}

	info, hostNetwork, err := decodeSandboxStatusResponse(response)
	if err != nil {
		log.Printf("[cri] sandbox %s: decode: %v", short(sandboxID), err)
		return sandboxExposure{}
	}

	return sandboxExposure{hostNetwork: hostNetwork, hostPorts: hostPortsFromInfo(info)}
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}

	return id
}
