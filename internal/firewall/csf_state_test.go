package firewall

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// withHostRoot points hostRoot at dir for the duration of the test and
// restores the production default afterwards. Mirrors withCSFDir.
func withHostRoot(t *testing.T, dir string) {
	t.Helper()
	prev := hostRoot
	hostRoot = dir
	t.Cleanup(func() { hostRoot = prev })
}

// withRunCmd replaces the run() execution seam for the duration of the test.
func withRunCmd(t *testing.T, fn func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error)) {
	t.Helper()
	prev := runCmd
	runCmd = fn
	t.Cleanup(func() { runCmd = prev })
}

// mustWriteFile creates path (and any missing parent directories) with
// content, failing the test on any error.
func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}

func boolPtr(b bool) *bool { return &b }
func intPtr(n int) *int    { return &n }

// TestCSFStateKeys proves collectCSFState reads every csf.conf key
// tri-state: an absent key (AUTO_UPDATES here) must come back nil, never a
// guessed "false".
func TestCSFStateKeys(t *testing.T) {
	withHostRoot(t, t.TempDir())
	withCSFDir(t, t.TempDir())
	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		return nil, errors.New("systemctl unavailable in this test")
	})

	conf := map[string]string{
		"TESTING":            "1",
		"LF_DAEMON":          "1",
		"IPV6":               "0",
		"DENY_IP_LIMIT":      "200",
		"DENY_TEMP_IP_LIMIT": "100",
	}

	state := collectCSFState(context.Background(), conf)

	if state.Testing == nil || *state.Testing != true {
		t.Errorf("Testing = %v, want *true", state.Testing)
	}
	if state.LFDaemon == nil || *state.LFDaemon != true {
		t.Errorf("LFDaemon = %v, want *true", state.LFDaemon)
	}
	if state.IPv6 == nil || *state.IPv6 != false {
		t.Errorf("IPv6 = %v, want *false", state.IPv6)
	}
	if state.DenyIPLimit == nil || *state.DenyIPLimit != 200 {
		t.Errorf("DenyIPLimit = %v, want *200", state.DenyIPLimit)
	}
	if state.DenyTempIPLimit == nil || *state.DenyTempIPLimit != 100 {
		t.Errorf("DenyTempIPLimit = %v, want *100", state.DenyTempIPLimit)
	}
	if state.AutoUpdates != nil {
		t.Errorf("AutoUpdates = %v, want nil (absent key is not false)", *state.AutoUpdates)
	}
}

// COL-02 names AUTO_UPDATES among the facts the agent must read, but the only
// assertion on it was "an absent key yields nil" — the key was never present
// in any test's conf, in any fixture, and there is no LAB_EXPECT_AUTO_UPDATES
// in the lab either. So misspelling the key it reads (AUTOUPDATES, say) kept
// internal/firewall, cmd/defensia-agent and internal/api all green while the
// value silently became nil on every real host: indistinguishable from "this
// CSF has no such setting", which is exactly the state the tri-state
// null/false/true design exists to tell apart.
func TestCSFStateAutoUpdatesValue(t *testing.T) {
	withHostRoot(t, t.TempDir())
	withCSFDir(t, t.TempDir())
	withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
		return nil, errors.New("systemctl unavailable in this test")
	})

	for _, tc := range []struct {
		raw  string
		want bool
	}{
		{"1", true},
		{"0", false},
	} {
		state := collectCSFState(context.Background(), map[string]string{"AUTO_UPDATES": tc.raw})
		if state.AutoUpdates == nil {
			t.Fatalf("AUTO_UPDATES=%q gave nil, want *%v — the key being read does not match the key in csf.conf", tc.raw, tc.want)
		}
		if *state.AutoUpdates != tc.want {
			t.Errorf("AUTO_UPDATES=%q gave *%v, want *%v", tc.raw, *state.AutoUpdates, tc.want)
		}
	}
}

// TestCSFStateFixtures proves collectCSFState against two real Phase 14
// fixtures: cwp-orphan-15.00 (TESTING=1, active configserver.com download
// server) and original-15.00 (TESTING=0, every downloadservers line
// commented out).
func TestCSFStateFixtures(t *testing.T) {
	cases := []struct {
		dir                 string
		wantTesting         bool
		wantHasConfigserver bool
	}{
		{"testdata/cwp-orphan-15.00", true, true},
		{"testdata/original-15.00", false, false},
	}

	for _, tc := range cases {
		t.Run(tc.dir, func(t *testing.T) {
			withCSFDir(t, tc.dir)
			withHostRoot(t, t.TempDir())
			withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
				return []byte("inactive\n"), nil
			})

			conf, _, err := readCSFConf()
			if err != nil {
				t.Fatalf("readCSFConf(): %v", err)
			}

			state := collectCSFState(context.Background(), conf)

			if state.Testing == nil || *state.Testing != tc.wantTesting {
				t.Errorf("Testing = %v, want *%v", state.Testing, tc.wantTesting)
			}

			hasConfigserver := false
			for _, s := range state.DownloadServers {
				if strings.Contains(s, "configserver.com") {
					hasConfigserver = true
				}
			}
			if hasConfigserver != tc.wantHasConfigserver {
				t.Errorf("DownloadServers = %v, configserver.com present = %v, want %v", state.DownloadServers, hasConfigserver, tc.wantHasConfigserver)
			}
		})
	}
}

// TestLFDRunning covers every branch of the tri-state lfd detection: a live
// pid, a stale pid, and the systemctl fallback (active / inactive-with-error
// / timeout), plus the /run/lfd.pid alternate path. Every proc-based case
// asserts zero commands were run.
func TestLFDRunning(t *testing.T) {
	t.Run("var/run/lfd.pid running", func(t *testing.T) {
		tmp := t.TempDir()
		withHostRoot(t, tmp)
		mustWriteFile(t, filepath.Join(tmp, "var/run/lfd.pid"), "1234")
		mustWriteFile(t, filepath.Join(tmp, "proc/1234/cmdline"), "lfd - sleeping")
		ran := false
		withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
			ran = true
			return nil, nil
		})

		got := lfdRunning(context.Background())
		if got == nil || *got != true {
			t.Fatalf("lfdRunning() = %v, want *true", got)
		}
		if ran {
			t.Error("lfdRunning() ran a command despite a readable pid file")
		}
	})

	t.Run("stale pid, proc dir missing", func(t *testing.T) {
		tmp := t.TempDir()
		withHostRoot(t, tmp)
		mustWriteFile(t, filepath.Join(tmp, "var/run/lfd.pid"), "9999")
		ran := false
		withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
			ran = true
			return nil, nil
		})

		got := lfdRunning(context.Background())
		if got == nil || *got != false {
			t.Fatalf("lfdRunning() = %v, want *false", got)
		}
		if ran {
			t.Error("lfdRunning() ran a command despite a (stale) readable pid file")
		}
	})

	t.Run("no pid file, systemctl active", func(t *testing.T) {
		tmp := t.TempDir()
		withHostRoot(t, tmp)
		withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
			if name != "systemctl" || len(args) != 2 || args[0] != "is-active" || args[1] != "lfd" {
				t.Fatalf("unexpected command %q %v", name, args)
			}
			return []byte("active\n"), nil
		})

		got := lfdRunning(context.Background())
		if got == nil || *got != true {
			t.Fatalf("lfdRunning() = %v, want *true", got)
		}
	})

	t.Run("no pid file, systemctl inactive with exit error", func(t *testing.T) {
		tmp := t.TempDir()
		withHostRoot(t, tmp)
		withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
			return []byte("inactive\n"), errors.New("exit status 3")
		})

		got := lfdRunning(context.Background())
		if got == nil || *got != false {
			t.Fatalf("lfdRunning() = %v, want *false", got)
		}
	})

	t.Run("no pid file, systemctl timeout", func(t *testing.T) {
		tmp := t.TempDir()
		withHostRoot(t, tmp)
		withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
			return nil, errors.New("systemctl timed out after 5s: context deadline exceeded")
		})

		got := lfdRunning(context.Background())
		if got != nil {
			t.Fatalf("lfdRunning() = %v, want nil", got)
		}
	})

	t.Run("run/lfd.pid also accepted", func(t *testing.T) {
		tmp := t.TempDir()
		withHostRoot(t, tmp)
		mustWriteFile(t, filepath.Join(tmp, "run/lfd.pid"), "4321")
		mustWriteFile(t, filepath.Join(tmp, "proc/4321/comm"), "lfd\n")
		ran := false
		withRunCmd(t, func(ctx context.Context, d time.Duration, name string, args ...string) ([]byte, error) {
			ran = true
			return nil, nil
		})

		got := lfdRunning(context.Background())
		if got == nil || *got != true {
			t.Fatalf("lfdRunning() = %v, want *true", got)
		}
		if ran {
			t.Error("lfdRunning() ran a command despite a readable /run/lfd.pid")
		}
	})
}

// TestDownloadServers covers the readDownloadServers caps and filtering.
func TestDownloadServers(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		withCSFDir(t, t.TempDir())
		got := readDownloadServers()
		if got == nil {
			t.Fatal("readDownloadServers() = nil, want non-nil empty slice")
		}
		if len(got) != 0 {
			t.Fatalf("readDownloadServers() = %v, want empty", got)
		}
	})

	t.Run("comments and blanks skipped, sentinel-style line kept", func(t *testing.T) {
		dir := t.TempDir()
		withCSFDir(t, dir)
		content := "# comment\n\ndownload.configserver.com\n\nraw.githubusercontent.com/x/sentinelfw/refs/heads/main/\n"
		mustWriteFile(t, filepath.Join(dir, "downloadservers"), content)

		got := readDownloadServers()
		want := []string{"download.configserver.com", "raw.githubusercontent.com/x/sentinelfw/refs/heads/main/"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("readDownloadServers() = %#v, want %#v", got, want)
		}
	})

	t.Run("15 active lines capped at 10", func(t *testing.T) {
		dir := t.TempDir()
		withCSFDir(t, dir)
		var lines []string
		for i := 0; i < 15; i++ {
			lines = append(lines, fmt.Sprintf("server%d.example.com", i))
		}
		mustWriteFile(t, filepath.Join(dir, "downloadservers"), strings.Join(lines, "\n"))

		got := readDownloadServers()
		if len(got) != 10 {
			t.Fatalf("readDownloadServers() len = %d, want 10", len(got))
		}
	})

	t.Run("300-char line truncated to 200", func(t *testing.T) {
		dir := t.TempDir()
		withCSFDir(t, dir)
		mustWriteFile(t, filepath.Join(dir, "downloadservers"), strings.Repeat("a", 300))

		got := readDownloadServers()
		if len(got) != 1 || len(got[0]) != 200 {
			t.Fatalf("readDownloadServers() = %v (entry len %d), want 1 entry of length 200", got, len(got[0]))
		}
	})
}

// TestAutoUpdatesCron covers the cheap stat-only check.
func TestAutoUpdatesCron(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		withHostRoot(t, t.TempDir())
		if autoUpdatesCron() {
			t.Error("autoUpdatesCron() = true, want false")
		}
	})

	t.Run("present", func(t *testing.T) {
		tmp := t.TempDir()
		withHostRoot(t, tmp)
		mustWriteFile(t, filepath.Join(tmp, "etc/cron.d/csf_update"), "0 3 * * * root /usr/sbin/csf -u\n")
		if !autoUpdatesCron() {
			t.Error("autoUpdatesCron() = false, want true")
		}
	})
}
