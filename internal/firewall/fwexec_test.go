package firewall

import (
	"context"
	"strings"
	"sync"
	"testing"
)

type fakeCall struct {
	Name  string
	Args  []string
	Stdin string
}

func (c fakeCall) Argv() string {
	return c.Name + " " + strings.Join(c.Args, " ")
}

type fakeFW struct {
	mu    sync.Mutex
	calls []fakeCall
	bins  map[string]bool
	fn    func(c fakeCall) ([]byte, error)
}

func (f *fakeFW) record(c fakeCall) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, c)
}

func (f *fakeFW) Calls() []fakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]fakeCall, len(f.calls))
	copy(out, f.calls)
	return out
}

// Clear discards every call recorded so far, so a test can isolate the calls
// made by a specific operation from setup noise (e.g. the initial Reselect).
func (f *fakeFW) Clear() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
}

func (f *fakeFW) run(ctx context.Context, stdin, name string, args ...string) ([]byte, error) {
	c := fakeCall{Name: name, Args: args, Stdin: stdin}
	f.record(c)
	if f.fn != nil {
		return f.fn(c)
	}
	return []byte{}, nil
}

func (f *fakeFW) lookPath(name string) (string, error) {
	if f.bins[name] {
		return "/usr/bin/" + name, nil
	}
	return "", &fakeLookPathError{name}
}

type fakeLookPathError struct{ name string }

func (e *fakeLookPathError) Error() string {
	return "exec: \"" + e.name + "\": executable file not found in $PATH"
}

// withFakeFW installs fwRun+fwLookPath, resets backend selection state, and
// restores everything at test cleanup.
func withFakeFW(t *testing.T, bins []string, fn func(c fakeCall) ([]byte, error)) *fakeFW {
	t.Helper()
	f := &fakeFW{bins: map[string]bool{}, fn: fn}
	for _, b := range bins {
		f.bins[b] = true
	}

	origRun := fwRun
	origLookPath := fwLookPath
	fwRun = f.run
	fwLookPath = f.lookPath
	resetBackendState()
	resetNftForTest()

	t.Cleanup(func() {
		fwRun = origRun
		fwLookPath = origLookPath
		resetBackendState()
		resetNftForTest()
	})

	return f
}

func TestFwExecUsesRunner(t *testing.T) {
	f := withFakeFW(t, []string{"ipset"}, nil)

	out, err := fwExec("ipset", "list")
	if err != nil {
		t.Fatalf("fwExec: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("fwExec: expected empty output, got %q", out)
	}

	calls := f.Calls()
	if len(calls) != 1 || calls[0].Argv() != "ipset list" {
		t.Fatalf("expected one recorded call 'ipset list', got %+v", calls)
	}

	_, err = fwExecIn("add x 1.2.3.4 -exist\n", "ipset", "restore")
	if err != nil {
		t.Fatalf("fwExecIn: %v", err)
	}
	calls = f.Calls()
	if len(calls) != 2 || calls[1].Stdin != "add x 1.2.3.4 -exist\n" {
		t.Fatalf("fwExecIn did not pass stdin through: %+v", calls)
	}
}
