package api

import "testing"

func TestCleanSourceIP(t *testing.T) {
	cases := map[string]string{
		"":                "",
		"203.0.113.7":     "203.0.113.7",
		" 203.0.113.7 ":   "203.0.113.7",
		"2001:db8::1":     "2001:db8::1",
		"[2001:db8::1]":   "2001:db8::1",
		"203.0.113.7:443": "",
		"unknown":         "",
		"-":               "",
	}
	for in, want := range cases {
		if got := cleanSourceIP("test", in); got != want {
			t.Errorf("cleanSourceIP(%q) = %q, want %q", in, got, want)
		}
	}
}
