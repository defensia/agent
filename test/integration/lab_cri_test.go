//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/defensia/agent/internal/cri"
	"github.com/defensia/agent/internal/pkgdb"
)

// TestLabCRIEnumeratesTheNodesContainers runs against a real CRI runtime — the
// lab's k3s node, or any node with a containerd or CRI-O socket — and asserts
// the one thing the inventory cannot work without: a host PID per container.
//
// It skips rather than fails where there is no runtime, because the same suite
// runs on the plain Linux lab VMs.
func TestLabCRIEnumeratesTheNodesContainers(t *testing.T) {
	endpoint := cri.Endpoint()
	if endpoint == "" {
		t.Skip("no CRI socket on this machine")
	}

	t.Logf("CRI endpoint: %s", endpoint)

	started := time.Now()
	containers, err := cri.Containers(context.Background())
	elapsed := time.Since(started)

	if errors.Is(err, cri.ErrNoRuntime) {
		t.Skip("no CRI socket on this machine")
	}
	if err != nil {
		t.Fatalf("cri.Containers: %v", err)
	}
	if len(containers) == 0 {
		t.Fatal("the runtime answered but reported no running containers: on a Kubernetes node there is always at least the agent's own pod")
	}

	t.Logf("%d containers in %s (%s per container)", len(containers), elapsed.Round(time.Millisecond),
		(elapsed / time.Duration(len(containers))).Round(time.Millisecond))

	// The table the inventory is built on: what is running, what its host PID
	// is, what version the package database inside it reports, and whether it is
	// reachable from outside the node.
	t.Log("POD/CONTAINER | PID | PKGDB | NGINX | EXPOSED")

	identified := 0

	for _, c := range containers {
		version := "-"
		format := "none"

		if c.Pid > 0 {
			identified++

			if db, ok := pkgdb.FromRoot(fmt.Sprintf("/proc/%d/root", c.Pid)); ok {
				format = string(db.Format)
				if _, v, found := db.Version("nginx", "nginx-core"); found {
					version = v
				}
			}
		}

		exposure := "no"
		if c.HostNetwork {
			exposure = "hostNetwork"
		} else if len(c.HostPorts) > 0 {
			exposure = fmt.Sprintf("hostPorts %v", c.HostPorts)
		}

		t.Logf("%s/%s/%s | %d | %s | %s | %s",
			c.PodNamespace, c.PodName, c.Name, c.Pid, format, version, exposure)
	}

	if identified == 0 {
		t.Errorf("not one of %d containers yielded a host PID: the runtime's verbose ContainerStatus info did not carry one, and without it the inventory cannot read inside any container", len(containers))
	}

	// The agent's own pod runs with hostPID and hostNetwork in the lab chart, so
	// when this test runs inside it that container must come back exposed. It is
	// the only exposure assertion that holds on any cluster.
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		found := false
		for _, c := range containers {
			if c.Name == "defensia-agent" {
				found = true
				if !c.Exposed() {
					t.Errorf("the agent's own hostNetwork pod must read as exposed: %+v", c)
				}
			}
		}
		if !found {
			t.Log("note: no container named defensia-agent on this node, exposure assertion skipped")
		}
	}
}
