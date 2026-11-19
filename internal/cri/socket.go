package cri

import (
	"os"
	"strings"
)

// knownEndpoints are the CRI sockets the agent goes looking for, in the order it
// tries them.
//
// Every one of these is a real distribution's real path, not a guess, and the
// list exists because the upstream default is the minority case on a Kubernetes
// node. A chart that mounted only /run/containerd/containerd.sock found nothing
// on k3s — measured today, on the lab cluster — because k3s puts its socket
// somewhere else entirely.
//
// Order matters only for speed. Each entry costs one stat when absent.
var knownEndpoints = []string{
	// containerd upstream, and the socket a Docker install runs underneath.
	"/run/containerd/containerd.sock",
	"/var/run/containerd/containerd.sock",

	// k3s and k3d. RKE2 reuses k3s's path, documented and the same string.
	"/run/k3s/containerd/containerd.sock",

	// RKE2's agent-local path, used when it is not sharing k3s's.
	"/var/lib/rancher/rke2/agent/containerd/containerd.sock",

	// MicroK8s, from its own containerd args file: --address ${SNAP_COMMON}/run/containerd.sock
	"/var/snap/microk8s/common/run/containerd.sock",

	// CRI-O, which OpenShift and kubeadm-on-RHEL use.
	"/run/crio/crio.sock",
	"/var/run/crio/crio.sock",
}

// Endpoint returns the CRI socket to talk to, or "" when there is none here.
//
// CONTAINER_RUNTIME_ENDPOINT overrides the search entirely. That is crictl's own
// variable, so an operator who already configured crictl on a node with a
// non-standard socket has nothing new to learn — the same escape hatch
// WEB_LOG_PATH is for log autodetection.
func Endpoint() string {
	if env := os.Getenv("CONTAINER_RUNTIME_ENDPOINT"); env != "" {
		return strings.TrimPrefix(env, "unix://")
	}

	for _, path := range knownEndpoints {
		if isSocket(path) {
			return path
		}
	}

	return ""
}

func isSocket(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode()&os.ModeSocket != 0
}
