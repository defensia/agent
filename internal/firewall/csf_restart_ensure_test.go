package firewall

import (
	"errors"
	"testing"
)

// TestAfterCSFRestartEnsuresActiveBackend proves the phase-17 default body
// of afterCSFRestart (Ensure(), not Init()) re-asserts the currently active
// backend's rules without re-running detection.
func TestAfterCSFRestartEnsuresActiveBackend(t *testing.T) {
	f := withFakeFW(t, []string{"ipset", "iptables", "ip6tables"}, nil)

	Init() // selects ipset via Reselect internally
	if Mode() != "ipset" {
		t.Fatalf("Mode() after Init() = %q, want ipset", Mode())
	}

	// CSF flushed INPUT: the -C existence check for the bans4 match rule now
	// fails, as if the rule were gone.
	f.fn = func(c fakeCall) ([]byte, error) {
		if c.Name == "iptables" && len(c.Args) > 0 && c.Args[0] == "-C" {
			return []byte(""), errors.New("exit 1")
		}
		return []byte{}, nil
	}
	f.Clear()

	afterCSFRestart()

	var sawReassert, sawProbe bool
	for _, c := range f.Calls() {
		if c.Argv() == "iptables -A INPUT -m set --match-set defensia-bans src -j DROP" {
			sawReassert = true
		}
		if c.Name == "ipset" && len(c.Args) > 0 && (c.Args[0] == "create" || c.Args[0] == "destroy") && contains(c.Argv(), "defensia-probe") {
			sawProbe = true
		}
	}
	if !sawReassert {
		t.Fatalf("afterCSFRestart() did not re-assert the bans4 match rule; calls: %v", argvList(f.Calls()))
	}
	if sawProbe {
		t.Fatalf("afterCSFRestart() re-ran backend detection (saw a defensia-probe call) — it must call Ensure(), not Init()/Reselect()")
	}
	if Mode() != "ipset" {
		t.Fatalf("Mode() after afterCSFRestart() = %q, want ipset (unchanged)", Mode())
	}
}

// TestAfterCSFRestartNftKeepsMode proves the same for the nftables backend:
// a failed `nft list table` (table flushed by something external) makes
// Ensure() recreate the table, bumping Generation(), while Mode() stays
// nftables (no backend switch, no re-detection).
func TestAfterCSFRestartNftKeepsMode(t *testing.T) {
	withFakeFW(t, []string{"nft"}, nftVersionOKFn(func(c fakeCall) ([]byte, error) {
		if c.Name == "nft" && len(c.Args) >= 2 && c.Args[0] == "list" && c.Args[1] == "table" {
			return []byte(""), errors.New("No such file or directory")
		}
		return []byte{}, nil
	}))

	if got := Reselect(); got != "nftables" {
		t.Fatalf("Reselect() = %q, want nftables", got)
	}
	g1 := Generation()

	afterCSFRestart()

	if Mode() != "nftables" {
		t.Fatalf("Mode() after afterCSFRestart() = %q, want nftables (unchanged)", Mode())
	}
	if Generation() == g1 {
		t.Fatalf("Generation() did not change after Ensure() recreated the table")
	}
}
