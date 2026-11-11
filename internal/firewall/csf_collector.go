package firewall

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// CSFSnapshot is the full read-only picture of CSF this package collects.
// The heartbeat (iptables.go's FirewallStatus) and Phase 16's health check
// both read this via CurrentCSFSnapshot() — never by running a command
// themselves.
type CSFSnapshot struct {
	Installed    bool
	Version      string
	Fork         string
	ForkEvidence []string

	PortsIn, PortsOut string

	Testing, AutoUpdates, LFDaemon, LFDRunning, IPv6 *bool
	AutoUpdatesCron                                  bool
	DownloadServers                                  []string
	DenyIPLimit, DenyTempIPLimit                     *int

	Deny, Allow CSFList
	ListsHash   string

	CollectedAt time.Time
}

// Package-level collector state. csfSeenMarker/csfPausedMarker are test
// seams (production defaults below); tests reassign them directly to a
// temp path rather than going through hostRoot, since they are agent state
// — not something that lives on the "host" tree a fixture mirrors.
var (
	csfSeenMarker   = "/etc/defensia/csf-seen"
	csfPausedMarker = "/etc/defensia/csf-paused"

	csfSnapshot  atomic.Pointer[CSFSnapshot]
	csfPaused    atomic.Bool
	csfRefreshCh = make(chan struct{}, 1)

	lastLoggedForkVersion string
)

// CollectCSF runs a single synchronous collection pass. It is the only
// function in this package that touches CSF at all, and it is careful to
// do nothing whatsoever (no exec, no file read under csfDir) in the two
// cases where there is nothing to collect:
//   - the integration is paused (SetCSFPaused(true)/kill switch)
//   - CSF is absent and has never been seen on this host
func CollectCSF(ctx context.Context) *CSFSnapshot {
	if CSFPaused() {
		return nil
	}

	bin := csfBinaryPath()
	if bin == "" {
		if seenMarkerExists() {
			return &CSFSnapshot{Installed: false, CollectedAt: time.Now()}
		}
		return nil
	}
	ensureSeenMarker()

	conf, _, err := readCSFConf()
	if err != nil {
		conf = map[string]string{}
	}

	vOut, _ := run(ctx, csfExecTimeout, bin, "-v")
	version := readCSFVersionFile()
	if version == "" {
		version = parseCSFVersion(vOut)
	}

	rpmHasCpanelCSF := false
	if _, err := lookPath("rpm"); err == nil {
		if _, err := run(ctx, csfExecTimeout, "rpm", "-q", "cpanel-csf"); err == nil {
			rpmHasCpanelCSF = true
		}
	}

	state := collectCSFState(ctx, conf)

	fork, evidence := detectFork(forkEnv{
		Version:         version,
		CSFVOutput:      string(vOut),
		Conf:            conf,
		DownloadServers: state.DownloadServers,
		RPMHasCPanelCSF: rpmHasCpanelCSF,
	})

	deny, allow, listsHash := readCSFLists()

	logForkVersionChange(fork, version)

	return &CSFSnapshot{
		Installed:       true,
		Version:         version,
		Fork:            fork,
		ForkEvidence:    evidence,
		PortsIn:         state.PortsIn,
		PortsOut:        state.PortsOut,
		Testing:         state.Testing,
		AutoUpdates:     state.AutoUpdates,
		LFDaemon:        state.LFDaemon,
		LFDRunning:      state.LFDRunning,
		IPv6:            state.IPv6,
		AutoUpdatesCron: state.AutoUpdatesCron,
		DownloadServers: state.DownloadServers,
		DenyIPLimit:     state.DenyIPLimit,
		DenyTempIPLimit: state.DenyTempIPLimit,
		Deny:            deny,
		Allow:           allow,
		ListsHash:       listsHash,
		CollectedAt:     time.Now(),
	}
}

// logForkVersionChange logs once per observed change of fork/version, not
// on every collection pass (the collector runs every few minutes forever).
func logForkVersionChange(fork, version string) {
	key := fork + "@" + version
	if key == lastLoggedForkVersion {
		return
	}
	lastLoggedForkVersion = key
	log.Printf("[csf] detected fork=%s version=%s", fork, version)
}

// StartCSFCollector launches the background collector goroutine and
// returns immediately — including its first pass, which also runs inside
// the goroutine, not before returning. This is what makes it safe to call
// from agent startup: a hung csf/rpm/systemctl on a broken box can never
// delay anything that calls StartCSFCollector.
func StartCSFCollector(ctx context.Context, interval time.Duration) {
	go func() {
		collect := func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[csf] collector panic recovered: %v", r)
				}
			}()
			csfSnapshot.Store(CollectCSF(ctx))
		}

		collect() // immediate first pass

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				collect()
			case <-csfRefreshCh:
				collect()
			}
		}
	}()
}

// CurrentCSFSnapshot returns the most recently collected snapshot — an
// atomic load, nothing else. This is the only function the heartbeat path
// (FirewallStatus) is allowed to call.
func CurrentCSFSnapshot() *CSFSnapshot {
	return csfSnapshot.Load()
}

// RequestCSFRefresh asks the background collector to run a pass as soon as
// possible, without blocking the caller (a full channel means a refresh is
// already pending).
func RequestCSFRefresh() {
	select {
	case csfRefreshCh <- struct{}{}:
	default:
	}
}

// SetCSFPaused implements the kill switch: pausing clears the snapshot
// immediately (so a stale snapshot is never served while paused) and
// persists a marker so the pause survives an agent restart; resuming
// removes the marker and requests an immediate refresh.
func SetCSFPaused(p bool) error {
	csfPaused.Store(p)
	if p {
		csfSnapshot.Store(nil)
		if err := writeMarker(csfPausedMarker); err != nil {
			return err
		}
		log.Printf("[csf] integration paused by panel")
		return nil
	}
	if err := removeMarker(csfPausedMarker); err != nil {
		return err
	}
	log.Printf("[csf] integration resumed")
	RequestCSFRefresh()
	return nil
}

// LoadCSFPaused reads the pause marker at startup, so a restart while
// paused stays paused.
func LoadCSFPaused() {
	_, err := os.Stat(csfPausedMarker)
	csfPaused.Store(err == nil)
}

// CSFPaused reports whether the integration is currently paused.
func CSFPaused() bool {
	return csfPaused.Load()
}

// AckCSFRemovalReported is called once the panel has acknowledged a
// csf_installed:false snapshot (i.e. it has recorded the removal). After
// this, CollectCSF goes back to returning nil — "never seen" — until CSF
// (re)appears.
func AckCSFRemovalReported() {
	_ = removeMarker(csfSeenMarker)
	csfSnapshot.Store(nil)
}

// seenMarkerExists/ensureSeenMarker/writeMarker/removeMarker are the small
// on-disk primitives the seen/paused markers share.
func seenMarkerExists() bool {
	_, err := os.Stat(csfSeenMarker)
	return err == nil
}

func ensureSeenMarker() {
	if seenMarkerExists() {
		return
	}
	if err := writeMarker(csfSeenMarker); err != nil {
		log.Printf("[csf] failed to write seen marker: %v", err)
	}
}

func writeMarker(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte("1\n"), 0o600)
}

func removeMarker(path string) error {
	err := os.Remove(path)
	if err != nil && os.IsNotExist(err) {
		return nil
	}
	return err
}

// csfStatusFromSnapshot adapts a CSFSnapshot to the pre-existing CSFStatus
// shape, used by both the (now snapshot-only) FirewallStatus heartbeat path
// and CSFInfo's synchronous compatibility path. A nil or not-installed
// snapshot yields the zero CSFStatus, exactly like HasCSF()==false used to.
func csfStatusFromSnapshot(s *CSFSnapshot) CSFStatus {
	if s == nil || !s.Installed {
		return CSFStatus{}
	}
	return CSFStatus{
		Installed:  true,
		Version:    s.Version,
		PortsIn:    s.PortsIn,
		PortsOut:   s.PortsOut,
		DenyCount:  s.Deny.Total,
		AllowCount: s.Allow.Total,
	}
}
