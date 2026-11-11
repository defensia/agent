package firewall

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// COL-06's integration assertion ("CollectCSF runs ZERO commands on a host
// with no CSF") is enforced by ObserveCommands, which only sees commands that
// go through run(). That makes the choke point load-bearing: a CSF code path
// calling exec.Command directly would spawn a real process that the COL-06
// test cannot see, and the test would still pass. Verified by mutation — a
// probe added via run() fails the no-CSF CI pass, the same probe added via a
// bare exec.CommandContext does not.
//
// run()'s own doc comment already calls itself "the single choke point every
// CSF (and related) command in this package goes through"; this is the test
// that makes that sentence true rather than aspirational. Scoped to the CSF
// files on purpose: iptables.go, ipset.go and geoblock.go predate this rule
// and hold ~20 legitimate direct calls for the ban/ipset paths, which
// CollectCSF never touches.
func TestCSFFilesGoThroughTheCommandChokePoint(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "csf") || !strings.HasSuffix(name, ".go") {
			continue
		}
		if strings.HasSuffix(name, "_test.go") || name == "csf_exec.go" {
			// csf_exec.go is the choke point itself: it holds the one
			// exec.CommandContext every other CSF file must route through.
			continue
		}

		src, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		checked++

		for _, bad := range []string{"exec.Command(", "exec.CommandContext("} {
			if strings.Contains(string(src), bad) {
				t.Errorf("%s calls %s directly; route it through run() instead, or COL-06's "+
					"zero-command assertion cannot see it (see csf_exec.go)", name, bad)
			}
		}
	}

	if checked == 0 {
		t.Fatal("no csf*.go files were checked — the guard is looking in the wrong place")
	}
	t.Logf("choke point enforced across %d CSF files", checked)
}
