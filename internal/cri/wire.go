package cri

import (
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"
)

// The handful of CRI messages this package needs, encoded and decoded by hand
// against the wire format.
//
// Hand-rolled rather than generated because generating them means depending on
// k8s.io/cri-api and google.golang.org/grpc, measured at +2.9 MB on a binary
// that is already 42.7 MB and whose size is published. Nothing here is guesswork:
// every field number below is copied from api.proto in k8s.io/cri-api v0.35.3,
// and the CRI is a versioned, frozen interface — v1 field numbers cannot be
// renumbered without becoming v2, which would arrive at a different gRPC path.
//
// Only the fields the inventory actually uses are decoded. Unknown fields are
// skipped, which is the protobuf contract and means a newer runtime adding
// fields cannot break this.

// Field numbers, named so they can be checked against api.proto by eye.
const (
	// ListContainersRequest
	fListContainersFilter = 1
	// ContainerFilter
	fFilterState = 2
	// ContainerStateValue
	fStateValueState = 1

	// ListContainersResponse
	fListContainersContainers = 1

	// Container
	fContainerID        = 1
	fContainerSandboxID = 2
	fContainerMetadata  = 3
	fContainerImage     = 4
	fContainerImageRef  = 5
	fContainerState     = 6
	fContainerLabels    = 8
	fContainerImageID   = 10

	// ContainerMetadata
	fMetadataName = 1

	// ImageSpec
	fImageSpecImage             = 1
	fImageSpecUserSpecifiedName = 18

	// ContainerStatusRequest / PodSandboxStatusRequest
	fStatusRequestID      = 1
	fStatusRequestVerbose = 2

	// ContainerStatusResponse / PodSandboxStatusResponse
	fStatusResponseStatus = 1
	fStatusResponseInfo   = 2

	// ContainerStatus
	fContainerStatusState = 3

	// PodSandboxStatus
	fSandboxStatusLinux = 6
	// LinuxPodSandboxStatus
	fLinuxSandboxNamespaces = 1
	// Namespace
	fNamespaceOptions = 2
	// NamespaceOption
	fNamespaceOptionNetwork = 1

	// map<string, string> entry
	fMapKey   = 1
	fMapValue = 2
)

// stateRunning is ContainerState.CONTAINER_RUNNING. A created-but-not-started
// container is deliberately not treated as running: it has no process, so it has
// no PID and no readable root.
const stateRunning = 1

// namespaceModeNode is NamespaceMode.NODE: the container shares the node's
// namespace. On the network namespace that is hostNetwork, and it is the one
// exposure fact the CRI reports identically on every runtime.
const namespaceModeNode = 2

// encodeListRunningContainers builds ListContainersRequest{filter:{state:RUNNING}}.
//
// Filtering in the runtime rather than here is deliberate: an exited container's
// root is gone, so asking about every container that ever ran on the node would
// buy a ContainerStatus call per corpse and produce nothing.
func encodeListRunningContainers() []byte {
	stateValue := protowire.AppendTag(nil, fStateValueState, protowire.VarintType)
	stateValue = protowire.AppendVarint(stateValue, stateRunning)

	filter := protowire.AppendTag(nil, fFilterState, protowire.BytesType)
	filter = protowire.AppendBytes(filter, stateValue)

	req := protowire.AppendTag(nil, fListContainersFilter, protowire.BytesType)
	req = protowire.AppendBytes(req, filter)

	return req
}

// encodeStatusRequest builds a ContainerStatusRequest or a
// PodSandboxStatusRequest: the two messages have the same shape, an id and a
// verbose flag.
func encodeStatusRequest(id string, verbose bool) []byte {
	req := protowire.AppendTag(nil, fStatusRequestID, protowire.BytesType)
	req = protowire.AppendString(req, id)

	if verbose {
		req = protowire.AppendTag(req, fStatusRequestVerbose, protowire.VarintType)
		req = protowire.AppendVarint(req, 1)
	}

	return req
}

// field is one decoded protobuf field: either a varint or a length-delimited
// payload, which is all the CRI messages read here contain.
type field struct {
	num    protowire.Number
	varint uint64
	bytes  []byte
}

// walk visits every field of a protobuf message in order.
//
// Fields of a type we do not read (fixed32, fixed64, groups) are skipped rather
// than rejected: a message that carries one is still perfectly readable for the
// fields we do want, and refusing it would mean a runtime that sets a float
// somewhere makes the whole node invisible.
func walk(b []byte, visit func(field) error) error {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return fmt.Errorf("protobuf tag: %w", protowire.ParseError(n))
		}
		b = b[n:]

		switch typ {
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(b)
			if n < 0 {
				return fmt.Errorf("protobuf varint field %d: %w", num, protowire.ParseError(n))
			}
			if err := visit(field{num: num, varint: v}); err != nil {
				return err
			}
			b = b[n:]

		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return fmt.Errorf("protobuf bytes field %d: %w", num, protowire.ParseError(n))
			}
			if err := visit(field{num: num, bytes: v}); err != nil {
				return err
			}
			b = b[n:]

		default:
			n := protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				return fmt.Errorf("protobuf field %d: %w", num, protowire.ParseError(n))
			}
			b = b[n:]
		}
	}

	return nil
}

// decodeListContainersResponse reads the container list, keeping only what the
// inventory needs to find and name each one.
func decodeListContainersResponse(b []byte) ([]Container, error) {
	var out []Container

	err := walk(b, func(f field) error {
		if f.num != fListContainersContainers || f.bytes == nil {
			return nil
		}

		c, err := decodeContainer(f.bytes)
		if err != nil {
			return err
		}

		out = append(out, c)
		return nil
	})

	return out, err
}

func decodeContainer(b []byte) (Container, error) {
	var (
		c         Container
		specImage string
		userImage string
		imageRef  string
		imageID   string
	)

	err := walk(b, func(f field) error {
		switch f.num {
		case fContainerID:
			c.ID = string(f.bytes)
		case fContainerSandboxID:
			c.SandboxID = string(f.bytes)
		case fContainerMetadata:
			return walk(f.bytes, func(m field) error {
				if m.num == fMetadataName {
					c.Name = string(m.bytes)
				}
				return nil
			})
		case fContainerImage:
			return walk(f.bytes, func(i field) error {
				switch i.num {
				case fImageSpecImage:
					specImage = string(i.bytes)
				case fImageSpecUserSpecifiedName:
					userImage = string(i.bytes)
				}
				return nil
			})
		case fContainerImageRef:
			imageRef = string(f.bytes)
		case fContainerImageID:
			imageID = string(f.bytes)
		case fContainerState:
			c.Running = f.varint == stateRunning
		case fContainerLabels:
			k, v, err := decodeMapEntry(f.bytes)
			if err != nil {
				return err
			}
			switch k {
			case labelPodName:
				c.PodName = v
			case labelPodNamespace:
				c.PodNamespace = v
			case labelContainerName:
				if c.Name == "" {
					c.Name = v
				}
			}
		}

		return nil
	})

	// Prefer the reference a human typed into the pod spec. Falling back to a
	// digest is ugly but it still identifies the image, and an empty image field
	// would leave an unidentified container with nothing to chase.
	for _, candidate := range []string{userImage, specImage, imageRef, imageID} {
		if candidate != "" {
			c.Image = candidate
			break
		}
	}

	return c, err
}

// Labels every CRI runtime sets, because the kubelet puts them there rather than
// the runtime inventing them. They are how a container gets a pod name without a
// second RPC.
const (
	labelPodName       = "io.kubernetes.pod.name"
	labelPodNamespace  = "io.kubernetes.pod.namespace"
	labelContainerName = "io.kubernetes.container.name"
)

func decodeMapEntry(b []byte) (key, value string, err error) {
	err = walk(b, func(f field) error {
		switch f.num {
		case fMapKey:
			key = string(f.bytes)
		case fMapValue:
			value = string(f.bytes)
		}
		return nil
	})

	return key, value, err
}

// decodeStatusResponse reads the verbose info map and the container state out of
// a ContainerStatusResponse.
//
// The info map is the entire reason this call is made: it is where both
// containerd and CRI-O put the host PID, and the PID is what turns a container
// into a filesystem the agent can read.
func decodeStatusResponse(b []byte) (info map[string]string, running bool, err error) {
	info = make(map[string]string)

	err = walk(b, func(f field) error {
		switch f.num {
		case fStatusResponseStatus:
			return walk(f.bytes, func(s field) error {
				if s.num == fContainerStatusState {
					running = s.varint == stateRunning
				}
				return nil
			})
		case fStatusResponseInfo:
			k, v, err := decodeMapEntry(f.bytes)
			if err != nil {
				return err
			}
			info[k] = v
		}

		return nil
	})

	return info, running, err
}

// decodeSandboxStatusResponse reads the verbose info map and whether the sandbox
// shares the node's network namespace.
//
// hostNetwork comes from a first-class proto field rather than from the info
// JSON on purpose: it is the one piece of exposure that every runtime reports
// the same way, where port mappings are only in containerd's info blob.
func decodeSandboxStatusResponse(b []byte) (info map[string]string, hostNetwork bool, err error) {
	info = make(map[string]string)

	err = walk(b, func(f field) error {
		switch f.num {
		case fStatusResponseStatus:
			return walk(f.bytes, func(s field) error {
				if s.num != fSandboxStatusLinux {
					return nil
				}
				return walk(s.bytes, func(l field) error {
					if l.num != fLinuxSandboxNamespaces {
						return nil
					}
					return walk(l.bytes, func(n field) error {
						if n.num != fNamespaceOptions {
							return nil
						}
						return walk(n.bytes, func(o field) error {
							if o.num == fNamespaceOptionNetwork {
								hostNetwork = o.varint == namespaceModeNode
							}
							return nil
						})
					})
				})
			})
		case fStatusResponseInfo:
			k, v, err := decodeMapEntry(f.bytes)
			if err != nil {
				return err
			}
			info[k] = v
		}

		return nil
	})

	return info, hostNetwork, err
}
