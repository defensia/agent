package firewall

import (
	"strings"
	"testing"
)

func TestDefensiaBanMembers(t *testing.T) {
	var v4members []string
	f := withFakeFW(t, []string{"ipset", "iptables", "ip6tables"}, func(c fakeCall) ([]byte, error) {
		switch {
		case c.Name == "ipset" && len(c.Args) > 0 && c.Args[0] == "add":
			v4members = append(v4members, c.Args[2])
			return []byte{}, nil
		case c.Name == "ipset" && len(c.Args) > 0 && c.Args[0] == "list" && len(c.Args) > 1 && c.Args[1] == "defensia-bans":
			return []byte("Members:\n" + strings.Join(v4members, "\n") + "\n"), nil
		}
		return []byte{}, nil
	})
	Reselect()
	f.Clear()

	if err := BanIP("203.0.113.40"); err != nil {
		t.Fatalf("BanIP: %v", err)
	}

	v4, _, err := DefensiaBanMembers()
	if err != nil {
		t.Fatalf("DefensiaBanMembers: %v", err)
	}
	found := false
	for _, ip := range v4 {
		if ip == "203.0.113.40" {
			found = true
		}
	}
	if !found {
		t.Errorf("DefensiaBanMembers v4 = %v, want 203.0.113.40 present", v4)
	}
}
