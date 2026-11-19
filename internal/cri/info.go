package cri

import (
	"encoding/json"
	"strconv"
)

// The verbose info map, which is where the host PID lives and the only reason
// ContainerStatus is called at all.
//
// CRI declares info as map<string, string> with "value should be in json
// format" and says nothing more, so what is inside it is each runtime's own
// business. Both runtimes that matter put everything under a single "info" key
// and the JSON there is a different struct in each:
//
//	containerd  {"pid":1157,"sandboxID":"…","snapshotKey":"…","snapshotter":"overlayfs",…}
//	CRI-O       {"pid":1157,"sandboxID":"…","runtimeSpec":{…},"privileged":false}
//
// containerd's shape is verified against the lab cluster (k3s 1.35.5,
// containerd 2.2.3) and is in testdata. CRI-O's is verified against the struct
// in its server/container_status.go, not against a running CRI-O: there is no
// CRI-O in the lab.
//
// Only "pid" is read, and both runtimes spell it the same. Parsing is written to
// take either shape and to ignore everything else, so neither runtime's extra
// fields nor a third runtime's different ones can break it.

// containerInfo is the subset of the info blob this package reads.
//
// json.Number rather than int because a runtime is free to write the pid as a
// string, and a type error on one field would otherwise discard the whole blob.
type containerInfo struct {
	Pid       json.Number `json:"pid"`
	SandboxID string      `json:"sandboxID"`
}

// pidFromInfo extracts the host PID of a container's main process.
//
// Zero means the runtime did not tell us, and a caller must never read zero as
// PID 0: that would make it read the agent's own root and report the agent's
// packages as the container's.
func pidFromInfo(info map[string]string) int {
	// The documented shape: one "info" key holding JSON.
	if blob, ok := info["info"]; ok {
		var parsed containerInfo
		if err := json.Unmarshal([]byte(blob), &parsed); err == nil {
			if pid, err := strconv.Atoi(parsed.Pid.String()); err == nil && pid > 0 {
				return pid
			}
		}
	}

	// A flat "pid" key is not what either runtime does today, but the map is
	// typed map<string,string> and a runtime putting the pid straight in it
	// would be within the contract. Cheap to accept, and the alternative is
	// reporting a whole node's containers as unidentified.
	if flat, ok := info["pid"]; ok {
		if pid, err := strconv.Atoi(flat); err == nil && pid > 0 {
			return pid
		}
	}

	return 0
}

// sandboxInfo is the subset of a pod sandbox's info blob this package reads.
//
// Only containerd provides it: CRI-O's sandbox info carries the runtime spec,
// the image and the pid and no port mappings at all, verified in its
// server/sandbox_status.go. So hostPort exposure is a containerd-only reading,
// and on CRI-O the only exposure the CRI reports is hostNetwork, which comes
// from a first-class proto field instead.
type sandboxInfo struct {
	Config struct {
		PortMappings []struct {
			HostPort json.Number `json:"host_port"`
			HostIP   string      `json:"host_ip"`
		} `json:"port_mappings"`
	} `json:"config"`
}

// hostPortsFromInfo returns the host ports a sandbox publishes that are
// reachable from outside the node.
//
// The bind address decides it, exactly as it does for Docker: an empty host_ip
// or 0.0.0.0 or :: is every interface, and a loopback binding is reachable only
// by something already on the node. Calling loopback "exposed" would inflate
// every finding on a cluster that fronts its pods with an ingress — which is
// every cluster.
func hostPortsFromInfo(info map[string]string) []int {
	blob, ok := info["info"]
	if !ok {
		return nil
	}

	var parsed sandboxInfo
	if err := json.Unmarshal([]byte(blob), &parsed); err != nil {
		return nil
	}

	var ports []int
	seen := make(map[int]struct{})

	for _, m := range parsed.Config.PortMappings {
		port, err := strconv.Atoi(m.HostPort.String())
		if err != nil || port == 0 {
			continue
		}

		if m.HostIP != "" && m.HostIP != "0.0.0.0" && m.HostIP != "::" {
			continue
		}

		if _, dup := seen[port]; dup {
			continue
		}

		seen[port] = struct{}{}
		ports = append(ports, port)
	}

	return ports
}
