package cri

import (
	"os"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

func fixtureBytes(t *testing.T, name string) []byte {
	t.Helper()

	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}

	return b
}

// Decoded from bytes a real containerd wrote, not from bytes this package
// encoded: a hand-rolled codec that is only ever tested against its own output
// proves that it agrees with itself and nothing more.
func TestARealContainerListDecodes(t *testing.T) {
	containers, err := decodeListContainersResponse(fixtureBytes(t, "list_containers.pb"))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(containers) != 9 {
		t.Fatalf("want the 9 containers captured on the node, got %d", len(containers))
	}

	var nginx *Container
	for i := range containers {
		if containers[i].PodName == "shop-nginx" {
			nginx = &containers[i]
		}

		// Every row has to be addressable and nameable, or a finding cannot be
		// chased back to a pod.
		if containers[i].ID == "" {
			t.Errorf("container with no ID: %+v", containers[i])
		}
		if containers[i].SandboxID == "" {
			t.Errorf("container with no sandbox ID: %+v", containers[i])
		}
		if containers[i].Image == "" {
			t.Errorf("container with no image: %+v", containers[i])
		}
		if !containers[i].Running {
			t.Errorf("the list was filtered to running containers: %+v", containers[i])
		}
	}

	if nginx == nil {
		t.Fatal("the shop-nginx pod is missing from the decoded list")
	}

	// The image as it was written in the pod spec, not a digest: it is what the
	// panel shows and what someone has to go and change.
	if nginx.Image != "nginx:1.27-alpine" {
		t.Errorf("Image = %q, want nginx:1.27-alpine", nginx.Image)
	}
	if nginx.Name != "nginx" {
		t.Errorf("Name = %q, want nginx", nginx.Name)
	}
	if nginx.PodNamespace != "cliente" {
		t.Errorf("PodNamespace = %q, want cliente", nginx.PodNamespace)
	}
}

// The PID is the only reason ContainerStatus is called, so this is the assertion
// the whole package stands on.
func TestARealContainerStatusCarriesThePid(t *testing.T) {
	info, running, err := decodeStatusResponse(fixtureBytes(t, "container_status.pb"))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if !running {
		t.Error("the captured container was running")
	}

	if pid := pidFromInfo(info); pid != 1166 {
		t.Errorf("pid = %d, want 1166", pid)
	}
}

// hostNetwork comes from a first-class proto field rather than the info blob
// because it is the one exposure fact every CRI runtime reports the same way.
// Both captures are real: the agent's own DaemonSet pod runs hostNetwork, the
// svclb pod does not and publishes host ports instead.
func TestARealSandboxStatusDistinguishesHostNetworkFromHostPorts(t *testing.T) {
	info, hostNetwork, err := decodeSandboxStatusResponse(fixtureBytes(t, "sandbox_status_hostnetwork.pb"))
	if err != nil {
		t.Fatalf("decode hostNetwork sandbox: %v", err)
	}
	if !hostNetwork {
		t.Error("the agent's own pod runs with hostNetwork and must read as such")
	}
	if ports := hostPortsFromInfo(info); len(ports) != 0 {
		t.Errorf("a hostNetwork pod publishes no host ports; got %v", ports)
	}

	info, hostNetwork, err = decodeSandboxStatusResponse(fixtureBytes(t, "sandbox_status_hostports.pb"))
	if err != nil {
		t.Fatalf("decode hostPorts sandbox: %v", err)
	}
	if hostNetwork {
		t.Error("the svclb pod does not use hostNetwork")
	}
	if ports := hostPortsFromInfo(info); len(ports) != 2 {
		t.Errorf("want the 2 published ports, got %v", ports)
	}
}

// The request has to say RUNNING and has to say verbose, and both are easy to
// get silently wrong: a filter encoded on the wrong field number is ignored by
// the server rather than rejected, and without verbose the info map comes back
// empty, which would read as "no runtime reports PIDs".
func TestTheListRequestAsksForRunningContainersOnly(t *testing.T) {
	var (
		sawFilter bool
		state     uint64 = 99
	)

	err := walk(encodeListRunningContainers(), func(f field) error {
		if f.num != fListContainersFilter {
			t.Errorf("unexpected field %d in ListContainersRequest", f.num)
			return nil
		}
		sawFilter = true

		return walk(f.bytes, func(filter field) error {
			if filter.num != fFilterState {
				t.Errorf("unexpected field %d in ContainerFilter", filter.num)
				return nil
			}
			return walk(filter.bytes, func(sv field) error {
				if sv.num == fStateValueState {
					state = sv.varint
				}
				return nil
			})
		})
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	if !sawFilter {
		t.Error("the request carries no filter: every container that ever ran would come back")
	}
	if state != stateRunning {
		t.Errorf("filter state = %d, want CONTAINER_RUNNING (%d)", state, stateRunning)
	}
}

func TestTheStatusRequestAsksForVerboseInfo(t *testing.T) {
	var (
		id      string
		verbose uint64
	)

	err := walk(encodeStatusRequest("abc123", true), func(f field) error {
		switch f.num {
		case fStatusRequestID:
			id = string(f.bytes)
		case fStatusRequestVerbose:
			verbose = f.varint
		default:
			t.Errorf("unexpected field %d in status request", f.num)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	if id != "abc123" {
		t.Errorf("container id = %q", id)
	}
	if verbose != 1 {
		t.Error("verbose must be set, or the info map comes back empty and every container looks unidentifiable")
	}
}

// A newer runtime will add fields, and some of them will be types this decoder
// does not read. Skipping them is the protobuf contract; refusing the message
// would mean one new float somewhere upstream makes a whole node invisible.
func TestFieldTypesThisDecoderDoesNotReadAreSkipped(t *testing.T) {
	// A Container message with a fixed64 and a fixed32 wedged between the fields
	// we do want.
	b := protowire.AppendTag(nil, fContainerID, protowire.BytesType)
	b = protowire.AppendString(b, "deadbeef")
	b = protowire.AppendTag(b, 77, protowire.Fixed64Type)
	b = protowire.AppendFixed64(b, 1234567890)
	b = protowire.AppendTag(b, 78, protowire.Fixed32Type)
	b = protowire.AppendFixed32(b, 42)
	b = protowire.AppendTag(b, fContainerSandboxID, protowire.BytesType)
	b = protowire.AppendString(b, "sandbox1")

	c, err := decodeContainer(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if c.ID != "deadbeef" || c.SandboxID != "sandbox1" {
		t.Errorf("fields around the unknown ones were lost: %+v", c)
	}
}

// Truncated bytes have to be an error. Returning a partial list would be the
// worst possible failure for this package: fewer containers than the node runs,
// reported as if that were all of them.
func TestTruncatedBytesAreAnErrorRatherThanAShortList(t *testing.T) {
	full := fixtureBytes(t, "list_containers.pb")

	if _, err := decodeListContainersResponse(full[:len(full)/2]); err == nil {
		t.Error("a truncated response decoded without complaint")
	}
}
