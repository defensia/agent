package collector

import (
	"testing"

	"github.com/defensia/agent/internal/monitor"
	"github.com/defensia/agent/internal/pkgdb"
)

// container builds the normalised reference the inventory works on, through the
// Docker conversion, so these cases still exercise how a Docker container's
// name and published ports are read.
func container(name, image string, ports ...monitor.DockerPort) containerRef {
	c := monitor.DockerContainer{ID: "deadbeef1234", Names: []string{"/" + name}, Image: image, Ports: ports}
	exposed, open := dockerExposure(c)

	return containerRef{
		ID:           c.ID,
		Name:         dockerName(c),
		Image:        image,
		Pid:          1,
		Running:      true,
		Exposed:      exposed,
		ExposedPorts: open,
	}
}

// 0.0.0.0 is reachable from outside the machine. Loopback is not, and treating
// it as exposure would inflate every finding on a host that fronts its
// containers with a reverse proxy — the normal arrangement.
func TestOnlyPortsReachableFromOutsideCountAsExposed(t *testing.T) {
	cases := []struct {
		port monitor.DockerPort
		want bool
	}{
		{monitor.DockerPort{IP: "0.0.0.0", PrivatePort: 443, PublicPort: 443, Type: "tcp"}, true},
		{monitor.DockerPort{IP: "::", PrivatePort: 443, PublicPort: 443, Type: "tcp"}, true},
		{monitor.DockerPort{IP: "127.0.0.1", PrivatePort: 3100, PublicPort: 3100, Type: "tcp"}, false},
		{monitor.DockerPort{IP: "::1", PrivatePort: 3100, PublicPort: 3100, Type: "tcp"}, false},
		// Not published at all: no PublicPort.
		{monitor.DockerPort{PrivatePort: 9000, Type: "tcp"}, false},
	}

	for _, c := range cases {
		if got := c.port.Exposed(); got != c.want {
			t.Errorf("DockerPort{IP:%q, PublicPort:%d}.Exposed() = %v, want %v", c.port.IP, c.port.PublicPort, got, c.want)
		}
	}
}

// Measured on our own platform server: nine containers all carry openssl
// 3.5.9-r0 because they share a base image. Nine identical rows would multiply
// every OpenSSL advisory by the container count.
func TestTheSameVersionAcrossContainersCollapsesToOneRow(t *testing.T) {
	rows := []KeySoftware{
		{Name: "OpenSSL", Version: "3.5.9-r0", Source: "container", SourceName: "app"},
		{Name: "OpenSSL", Version: "3.5.9-r0", Source: "container", SourceName: "queue"},
		{Name: "OpenSSL", Version: "3.5.9-r0", Source: "container", SourceName: "scheduler"},
	}

	got := collapseByVersion(rows)

	if len(got) != 1 {
		t.Fatalf("want 1 collapsed row, got %d", len(got))
	}
	if got[0].SourceName != "3 containers: app, queue, scheduler" {
		t.Errorf("the collapsed row must name what it covers; got %q", got[0].SourceName)
	}
}

// The exposed instance must not hide behind the unexposed ones: it is a
// different finding with a different urgency.
func TestAnExposedInstanceStaysSeparateFromUnexposedOnes(t *testing.T) {
	rows := []KeySoftware{
		{Name: "OpenSSL", Version: "3.5.9-r0", Source: "container", SourceName: "nginx", Exposed: true, ExposedPorts: []int{443}},
		{Name: "OpenSSL", Version: "3.5.9-r0", Source: "container", SourceName: "app"},
		{Name: "OpenSSL", Version: "3.5.9-r0", Source: "container", SourceName: "queue"},
	}

	got := collapseByVersion(rows)

	if len(got) != 2 {
		t.Fatalf("want the exposed row kept separate, got %d rows", len(got))
	}
	if !got[0].Exposed || got[0].SourceName != "nginx" {
		t.Errorf("the first row should be the exposed one; got %+v", got[0])
	}
}

// Two containers at the same version can publish different ports, and both are
// reachable.
func TestExposedPortsAreUnioned(t *testing.T) {
	rows := []KeySoftware{
		{Name: "Nginx", Version: "1.31.6-r1", Exposed: true, ExposedPorts: []int{8081}, SourceName: "a"},
		{Name: "Nginx", Version: "1.31.6-r1", Exposed: true, ExposedPorts: []int{8083}, SourceName: "b"},
	}

	got := collapseByVersion(rows)
	if len(got) != 1 {
		t.Fatalf("want 1 row, got %d", len(got))
	}
	if len(got[0].ExposedPorts) != 2 {
		t.Errorf("want both ports kept, got %v", got[0].ExposedPorts)
	}
}

// The doctrine the whole inventory rests on: "I do not know" must never come
// out as "it is fine". A running container the agent could not get a PID for —
// a runtime that does not report one, a container the runtime declined — is
// reported as present and unidentified, because a container nobody could look
// inside must not be indistinguishable from a container that is not there.
func TestARunningContainerWithNoPidIsReportedRatherThanOmitted(t *testing.T) {
	rows := inventoryRows([]containerRef{{
		ID:      "abc123def456",
		Name:    "cliente/shop-nginx/nginx",
		Image:   "nginx:1.27-alpine",
		Pid:     0,
		Running: true,
	}})

	if len(rows) != 1 {
		t.Fatalf("want the container reported, got %d rows", len(rows))
	}
	if rows[0].Name != "Unidentified container" {
		t.Errorf("Name = %q, want Unidentified container", rows[0].Name)
	}
	if rows[0].SourceName != "cliente/shop-nginx/nginx" || rows[0].SourceImage != "nginx:1.27-alpine" {
		t.Errorf("the row must say which pod and image to go and look at: %+v", rows[0])
	}
	if rows[0].Version != "-" {
		t.Errorf("Version = %q: nothing was read, so nothing may be claimed", rows[0].Version)
	}
}

// A container that stopped between listing and inspecting is a different case
// from one we could not read: there is nothing there any more, and reporting a
// corpse would be a finding about software that is not running.
func TestAContainerThatIsNoLongerRunningIsDropped(t *testing.T) {
	rows := inventoryRows([]containerRef{{
		ID:      "abc123def456",
		Name:    "cliente/shop-nginx/nginx",
		Image:   "nginx:1.27-alpine",
		Pid:     0,
		Running: false,
	}})

	if len(rows) != 0 {
		t.Errorf("want no rows for a stopped container, got %+v", rows)
	}
}

// Both enumerators run on every machine, because a node can have a Docker
// socket and a CRI socket at once. The same container must not be counted twice
// if both report it.
func TestTheSameContainerFoundTwiceIsReportedOnce(t *testing.T) {
	ref := containerRef{ID: "abc123def456", Name: "web", Image: "nginx:alpine", Pid: 0, Running: true}

	rows := inventoryRows([]containerRef{ref, ref})

	if len(rows) != 1 {
		t.Errorf("want 1 row for one container seen by two enumerators, got %d", len(rows))
	}
}

// An Alpine version is upstream plus a build revision, so it can be compared
// against a CVE's fixed version. A Debian version is a backport where the
// upstream number deliberately does not move, so comparing it reports a patched
// build as vulnerable forever — and there is no changelog inside an image to
// settle it. Those rows carry the real version where the panel can show it and
// leave Version empty so nothing matches on it.
func TestOnlyComparableVersionsReachTheVersionField(t *testing.T) {
	alpine := containerEntry(container("web", "nginx:alpine"), "Nginx", "1.31.9-r1", "nginx", "webserver", pkgdb.Apk)
	if alpine.Version != "1.31.9-r1" {
		t.Errorf("an Alpine version must be comparable; Version = %q", alpine.Version)
	}

	debian := containerEntry(container("api", "myapp:latest"), "Nginx", "1.26.3-3+deb13u2", "nginx", "webserver", pkgdb.Dpkg)
	if debian.Version != "-" {
		t.Errorf("a Debian backport must not reach the version field; Version = %q", debian.Version)
	}
	if debian.DistroVersion != "1.26.3-3+deb13u2" {
		t.Errorf("the real version must still be reported for display; DistroVersion = %q", debian.DistroVersion)
	}
}

// Every container row must say it is a container, or the panel cannot tell a
// host finding from one inside an image — and the remediation differs: patching
// the host does nothing for a container.
func TestEveryContainerRowCarriesItsProvenance(t *testing.T) {
	e := containerEntry(container("web", "nginx:alpine",
		monitor.DockerPort{IP: "0.0.0.0", PublicPort: 443, PrivatePort: 443, Type: "tcp"}),
		"Nginx", "1.31.9-r1", "nginx", "webserver", pkgdb.Apk)

	if e.Source != "container" {
		t.Errorf("Source = %q, want container", e.Source)
	}
	if e.SourceName != "web" {
		t.Errorf("SourceName = %q, want the container name without the API's leading slash", e.SourceName)
	}
	if e.SourceImage != "nginx:alpine" {
		t.Errorf("SourceImage = %q", e.SourceImage)
	}
	if !e.Exposed || len(e.ExposedPorts) != 1 || e.ExposedPorts[0] != 443 {
		t.Errorf("exposure not recorded: exposed=%v ports=%v", e.Exposed, e.ExposedPorts)
	}
	if e.PkgVerdict != "unknown" {
		t.Errorf("PkgVerdict = %q, want unknown: we never asked a package manager inside the container", e.PkgVerdict)
	}
}

// A container we cannot identify is still a container that may be serving
// traffic. Omitting it would make an unreadable image indistinguishable from an
// absent one.
func TestAnUnreadableContainerIsReportedRatherThanOmitted(t *testing.T) {
	got := softwareInContainer(container("db", "mysql:8.0"), "/proc/999999/root")

	if len(got) != 1 {
		t.Fatalf("want one row for an unreadable container, got %d", len(got))
	}
	if got[0].Name != "Unidentified container" || got[0].SourceImage != "mysql:8.0" {
		t.Errorf("the row must name the image so it can be chased: %+v", got[0])
	}
	if got[0].Version != "-" {
		t.Errorf("an unidentified container must carry no version; got %q", got[0].Version)
	}
}
