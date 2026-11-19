package cri

import (
	"os"
	"testing"
)

// The fixtures in testdata, and where each one came from.
//
//	container_info.json           captured from the lab cluster: k3d/k3s v1.35.5,
//	sandbox_info_hostports.json   containerd 2.2.3, via the capture test in this
//	list_containers.pb            package. Real bytes off a real socket.
//	container_status.pb
//	sandbox_status_hostports.pb
//	sandbox_status_hostnetwork.pb
//
//	container_info_crio.json      NOT captured: there is no CRI-O in the lab.
//	                              Written from the containerInfo struct in
//	                              CRI-O's server/container_status.go, which is
//	                              what it marshals into info["info"]. It proves
//	                              the parser takes CRI-O's shape; it does not
//	                              prove the agent works on CRI-O.
func fixture(t *testing.T, name string) string {
	t.Helper()

	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}

	return string(b)
}

// The PID is the only thing this package exists to obtain, and the two runtimes
// wrap it in different structs: containerd's info carries snapshotKey and
// snapshotter, CRI-O's carries privileged, and neither knows about the other's.
// Parsing has to take both, which is why it reads one field instead of
// unmarshalling into a runtime's struct.
func TestThePidIsReadFromBothRuntimesInfoShapes(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
		want    int
	}{
		{"containerd", "container_info.json", 1166},
		{"cri-o", "container_info_crio.json", 24817},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := pidFromInfo(map[string]string{"info": fixture(t, c.fixture)})
			if got != c.want {
				t.Errorf("pidFromInfo = %d, want %d", got, c.want)
			}
		})
	}
}

// Zero means "the runtime did not tell us" and must survive every way the answer
// can be missing. A caller that read zero as a PID would read /proc/0/root —
// the agent's own root — and report the agent's packages as the container's,
// which is a false clean bill of health for a container nobody could see inside.
func TestAnUnreadablePidIsZeroRatherThanAGuess(t *testing.T) {
	cases := []struct {
		name string
		info map[string]string
	}{
		{"no info at all", nil},
		{"verbose was not requested", map[string]string{}},
		{"info is not json", map[string]string{"info": "not json at all"}},
		{"json without a pid", map[string]string{"info": `{"sandboxID":"abc","privileged":true}`}},
		{"pid is null", map[string]string{"info": `{"pid":null}`}},
		{"pid is zero", map[string]string{"info": `{"pid":0}`}},
		{"pid is negative", map[string]string{"info": `{"pid":-1}`}},
		{"pid is a bool", map[string]string{"info": `{"pid":true}`}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := pidFromInfo(c.info); got != 0 {
				t.Errorf("pidFromInfo = %d, want 0", got)
			}
		})
	}
}

// The map is typed map<string,string> and the CRI says only that values "should
// be in json format", so a runtime writing the pid as a string, or straight into
// the map, is within the contract. Taking those costs nothing and the
// alternative is reporting a whole node's containers as unidentified.
func TestThePidIsTakenInEveryShapeTheContractAllows(t *testing.T) {
	cases := []struct {
		name string
		info map[string]string
	}{
		{"json number", map[string]string{"info": `{"pid":4242}`}},
		{"json string", map[string]string{"info": `{"pid":"4242"}`}},
		{"flat map key", map[string]string{"pid": "4242"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := pidFromInfo(c.info); got != 4242 {
				t.Errorf("pidFromInfo = %d, want 4242", got)
			}
		})
	}
}

// Captured from the lab: the svclb pod publishes 80 and 443 on the node, which
// is the difference between software behind an ingress and software on the
// public internet.
func TestHostPortsAreReadFromTheSandboxInfo(t *testing.T) {
	got := hostPortsFromInfo(map[string]string{"info": fixture(t, "sandbox_info_hostports.json")})

	if len(got) != 2 {
		t.Fatalf("want 2 host ports, got %v", got)
	}

	want := map[int]bool{80: true, 443: true}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected host port %d in %v", p, got)
		}
	}
}

// Loopback is not exposure, exactly as it is not for Docker: a port published on
// 127.0.0.1 is reachable only by something already on the node, and counting it
// would inflate every finding on a cluster that fronts its pods with an ingress
// — which is every cluster.
func TestOnlyHostPortsReachableFromOutsideCount(t *testing.T) {
	cases := []struct {
		name string
		info string
		want int
	}{
		{"all interfaces by omission", `{"config":{"port_mappings":[{"host_port":8081}]}}`, 1},
		{"all interfaces explicitly", `{"config":{"port_mappings":[{"host_port":8081,"host_ip":"0.0.0.0"}]}}`, 1},
		{"all interfaces v6", `{"config":{"port_mappings":[{"host_port":8081,"host_ip":"::"}]}}`, 1},
		{"loopback", `{"config":{"port_mappings":[{"host_port":8081,"host_ip":"127.0.0.1"}]}}`, 0},
		{"a specific private address", `{"config":{"port_mappings":[{"host_port":8081,"host_ip":"10.0.0.5"}]}}`, 0},
		{"container port only, nothing published", `{"config":{"port_mappings":[{"container_port":80}]}}`, 0},
		{"no mappings", `{"config":{}}`, 0},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := hostPortsFromInfo(map[string]string{"info": c.info})
			if len(got) != c.want {
				t.Errorf("hostPortsFromInfo = %v, want %d ports", got, c.want)
			}
		})
	}
}

// CRI-O does not report port mappings over the CRI at all — its sandbox info
// carries the runtime spec, the image and the pid, and nothing else. That has to
// read as no ports found, not as a parse failure that takes the container with
// it.
func TestASandboxInfoWithoutPortMappingsIsNotAnError(t *testing.T) {
	got := hostPortsFromInfo(map[string]string{"info": `{"image":"nginx","pid":24817,"runtimeSpec":{"ociVersion":"1.0.2-dev"}}`})
	if got != nil {
		t.Errorf("want no ports, got %v", got)
	}
}
