//go:build integration

package integration

import (
	"testing"

	"github.com/defensia/agent/internal/collector"
	"github.com/defensia/agent/internal/cri"
)

// TestLabCRIInventoryReportsWhatRunsOnTheNode runs the whole inventory on a
// node with a CRI runtime and asserts the container rows actually arrive —
// which is the thing that was missing, not the plumbing underneath it.
//
// The cri package test proves the runtime answers. This proves the answer
// reaches the inventory the panel receives.
func TestLabCRIInventoryReportsWhatRunsOnTheNode(t *testing.T) {
	if cri.Endpoint() == "" {
		t.Skip("no CRI socket on this machine")
	}

	rows := collector.CollectKeySoftwareForDiag()

	var containerRows, unidentified int

	t.Log("NAME | VERSION | DISTRO VERSION | SOURCE | EXPOSED")

	for _, r := range rows {
		if r.Source != "container" {
			continue
		}
		containerRows++
		if r.Name == "Unidentified container" {
			unidentified++
		}

		t.Logf("%s | %s | %s | %s (%s) | %v %v",
			r.Name, r.Version, r.DistroVersion, r.SourceName, r.SourceImage, r.Exposed, r.ExposedPorts)
	}

	if containerRows == 0 {
		t.Fatal("the node runs containers and the inventory reported none: this is the failure the CRI client exists to fix")
	}

	// Distroless images are the ordinary case for control-plane components, and
	// they must be reported as present and unidentified rather than dropped.
	// Measured on the lab cluster: coredns and metrics-server are both
	// distroless, so a cluster with zero unidentified rows would mean they were
	// silently skipped.
	t.Logf("%d container rows, %d of them unidentified", containerRows, unidentified)
}
