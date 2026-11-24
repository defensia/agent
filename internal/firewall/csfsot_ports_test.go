package firewall

import (
	"math/rand"
	"strconv"
	"strings"
	"testing"
)

func TestCanonPorts(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"22,80,443", "22,80,443", true},
		{"443, 22,80", "22,80,443", true},
		{"22,80,80,443", "22,80,443", true},
		{"30000:35000,30001", "30000:35000", true},
		{"80,81,82", "80:82", true},
		{"1:10,5:20", "1:20", true},
		{"", "", true},
		{" ", "", true},
		{"abc", "", false},
		{"0", "", false},
		{"65536", "", false},
		{"5:3", "", false},
		{"22,,80", "", false},
		{"22:", "", false},
	}

	for _, c := range cases {
		got, ok := canonPorts(c.in)
		if ok != c.ok {
			t.Errorf("canonPorts(%q) ok = %v, want %v", c.in, ok, c.ok)

			continue
		}
		if ok && got != c.want {
			t.Errorf("canonPorts(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestPortSetCovers(t *testing.T) {
	s, ok := parsePortSet("20:30")
	if !ok {
		t.Fatal("parsePortSet(20:30) failed")
	}
	if !s.covers(22) {
		t.Error("covers(20:30, 22) = false, want true")
	}
	if s.covers(31) {
		t.Error("covers(20:30, 31) = true, want false")
	}

	s2, ok := parsePortSet("22,2222")
	if !ok {
		t.Fatal("parsePortSet(22,2222) failed")
	}
	if !s2.coversAll([]int{22, 2222}) {
		t.Error("coversAll(22,2222, [22,2222]) = false, want true")
	}

	s3, ok := parsePortSet("22")
	if !ok {
		t.Fatal("parsePortSet(22) failed")
	}
	if s3.coversAll([]int{22, 2222}) {
		t.Error("coversAll(22, [22,2222]) = true, want false")
	}
}

func TestPortDiff(t *testing.T) {
	added, removed := portDiff("22,80,443", "22,443,8080")
	assertStrSlice(t, "added", added, []string{"8080"})
	assertStrSlice(t, "removed", removed, []string{"80"})

	added, removed = portDiff("30000:35000", "30000:34000")
	assertStrSlice(t, "added", added, nil)
	assertStrSlice(t, "removed", removed, []string{"34001:35000"})
}

func assertStrSlice(t *testing.T, label string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s = %v, want %v", label, got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s = %v, want %v", label, got, want)
		}
	}
}

func TestCanonIdempotent(t *testing.T) {
	r := rand.New(rand.NewSource(42))
	for i := 0; i < 200; i++ {
		n := r.Intn(5) + 1
		toks := make([]string, 0, n)
		for j := 0; j < n; j++ {
			a := r.Intn(65535) + 1
			toks = append(toks, strconv.Itoa(a))
		}
		raw := strings.Join(toks, ",")

		c1, ok1 := canonPorts(raw)
		if !ok1 {
			t.Fatalf("canonPorts(%q) failed unexpectedly", raw)
		}
		c2, ok2 := canonPorts(c1)
		if !ok2 || c1 != c2 {
			t.Fatalf("canon not idempotent: canon(%q)=%q, canon(canon(%q))=%q", raw, c1, raw, c2)
		}
	}
}
