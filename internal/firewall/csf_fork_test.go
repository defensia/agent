package firewall

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixtureForkWant maps every Phase 14 fixture dir to the fork detectFork must
// report for it (see 15-01-PLAN.md <interfaces> table).
var fixtureForkWant = map[string]string{
	"original-15.00":    ForkOriginal1500,
	"aetherinox-15.10":  ForkAetherinox,
	"sentinel-15.13":    ForkSentinel,
	"directadmin-15.12": ForkDirectAdmin,
	"cwp-orphan-15.00":  ForkOriginal1500,
}

// activeDownloadServers returns the non-comment, non-empty lines of a
// downloadservers file content — the same notion of "active" the collector
// itself will use.
func activeDownloadServers(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// TestDetectForkFixtures runs detectFork against every real Phase 14 fixture
// dir, built entirely from that fixture's own files through the existing
// csfDir/csfPath seam — no VM, no root.
func TestDetectForkFixtures(t *testing.T) {
	for name, want := range fixtureForkWant {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join("testdata", name)
			withCSFDir(t, dir)

			version := readCSFVersionFile()

			csfv, err := os.ReadFile(filepath.Join(dir, "csf-v.txt"))
			if err != nil {
				t.Fatalf("read csf-v.txt: %v", err)
			}

			confVals, _, err := readCSFConf()
			if err != nil {
				t.Fatalf("readCSFConf: %v", err)
			}

			dsRaw, err := os.ReadFile(filepath.Join(dir, "downloadservers"))
			if err != nil {
				t.Fatalf("read downloadservers: %v", err)
			}

			env := forkEnv{
				Version:         version,
				CSFVOutput:      string(csfv),
				Conf:            confVals,
				DownloadServers: activeDownloadServers(string(dsRaw)),
				HasPath:         func(string) bool { return false },
				RPMHasCPanelCSF: false,
			}

			fork, evidence := detectFork(env)
			if fork != want {
				t.Errorf("detectFork(%s) = %q, want %q (version=%q evidence=%v)", name, fork, want, version, evidence)
			}
			if len(evidence) == 0 {
				t.Errorf("detectFork(%s) evidence is empty, want non-empty", name)
			}
		})
	}
}

// TestDetectForkSynthetic exercises detectFork against hand-built forkEnv
// values (t.TempDir trees are not needed here — HasPath/ReadHead are stubbed
// directly) covering every rule and the ordering between them.
func TestDetectForkSynthetic(t *testing.T) {
	cases := []struct {
		name string
		env  forkEnv
		want string
	}{
		{
			name: "cpanel-rpm",
			env: forkEnv{
				Version:         "16.34-1",
				RPMHasCPanelCSF: true,
				HasPath:         func(string) bool { return false },
			},
			want: ForkCPanel,
		},
		{
			name: "cpanel-path",
			env: forkEnv{
				Version: "16.34",
				HasPath: func(p string) bool { return p == "/usr/local/cpanel" },
			},
			want: ForkCPanel,
		},
		{
			name: "original-on-cpanel-host",
			env: forkEnv{
				// csf -v prints "(cPanel)" here, but that suffix is a
				// csf.conf flag, not evidence: original CSF v15.00 with no
				// rpm and major version < 16 must stay original-15.00.
				Version: "15.00",
				HasPath: func(p string) bool { return p == "/usr/local/cpanel" },
			},
			want: ForkOriginal1500,
		},
		{
			name: "sentinel-module",
			env: forkEnv{
				HasPath: func(p string) bool { return p == "/usr/local/csf/lib/Sentinel" },
			},
			want: ForkSentinel,
		},
		{
			name: "sentinel-script",
			env: forkEnv{
				HasPath: func(string) bool { return false },
				ReadHead: func(p string, n int) string {
					if p == "/usr/local/csf/bin/csf.pl" {
						return "use Sentinel::Config;\n1;"
					}
					return ""
				},
			},
			want: ForkSentinel,
		},
		{
			name: "aetherinox-banner",
			env: forkEnv{
				CSFVOutput:      "ConfigServer Security & Firewall\nv15.10 (generic)\nLicense: None\nChannel: Stable Channel",
				DownloadServers: nil,
				HasPath:         func(string) bool { return false },
			},
			want: ForkAetherinox,
		},
		{
			name: "da-binary-only",
			env: forkEnv{
				Version: "15.12",
				HasPath: func(p string) bool { return p == "/usr/local/directadmin/directadmin" },
			},
			want: ForkDirectAdmin,
		},
		{
			name: "original-pre-gpl-on-da",
			env: forkEnv{
				Version: "14.20",
				Conf:    map[string]string{"DIRECTADMIN": "1"},
				HasPath: func(string) bool { return false },
			},
			want: ForkUnknown,
		},
		{
			name: "empty",
			env:  forkEnv{},
			want: ForkUnknown,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fork, evidence := detectFork(tc.env)
			if fork != tc.want {
				t.Errorf("detectFork(%s) = %q, want %q (evidence=%v)", tc.name, fork, tc.want, evidence)
			}
			if len(evidence) == 0 {
				t.Errorf("detectFork(%s) evidence is empty, want non-empty", tc.name)
			}
			if tc.name == "empty" && tc.env.Version != "" {
				t.Errorf("empty case Version = %q, want empty", tc.env.Version)
			}
		})
	}
}

// TestDetectForkNeverPanics proves detectFork degrades to a value from the
// fixed fork set instead of panicking on garbage/nil input — including nil
// Conf and nil HasPath/ReadHead funcs, which detectFork must default itself.
func TestDetectForkNeverPanics(t *testing.T) {
	validForks := map[string]bool{
		ForkCPanel: true, ForkDirectAdmin: true, ForkAetherinox: true,
		ForkSentinel: true, ForkOriginal1500: true, ForkUnknown: true,
	}

	cases := []forkEnv{
		{},
		{Version: "garbage-not-a-version"},
		{Version: "15.00.00.00.00"},
		{Version: "-1"},
		{Conf: nil, DownloadServers: nil, HasPath: nil, ReadHead: nil},
		{CSFVOutput: "\x1b[garbage not a real escape"},
		{DownloadServers: []string{"", "   ", "#comment only"}},
		{RPMHasCPanelCSF: true, Version: ""},
		{Conf: map[string]string{"DIRECTADMIN": "1"}, Version: "not-a-number"},
	}

	for i, env := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("case %d panicked: %v", i, r)
				}
			}()
			fork, evidence := detectFork(env)
			if !validForks[fork] {
				t.Errorf("case %d: detectFork returned %q, not in the fixed fork set", i, fork)
			}
			if len(evidence) == 0 {
				t.Errorf("case %d: evidence is empty, want non-empty", i)
			}
		}()
	}
}
