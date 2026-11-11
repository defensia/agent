//go:build integration

package firewall

// SetCSFFaultHook lets a real-VM lab/integration test inject a fault at a
// named stage of SafePortChange ("after_write", "after_rollback_write") to
// prove rollback actually restores a live CSF install end to end, not just
// that the code path runs. It exists ONLY in integration builds: this file
// carries the //go:build integration tag above, so `go build ./...` (the
// production build) never compiles it in — there is no runtime flag, no
// environment variable, no code path in the production binary that can
// reach csfFaultHook except nil. `go vet -tags integration ./...` and
// `go test -tags integration` are the only things that ever see this file.
func SetCSFFaultHook(fn func(stage, confPath string) error) (restore func()) {
	prev := csfFaultHook
	csfFaultHook = fn
	return func() { csfFaultHook = prev }
}
