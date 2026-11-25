package firewall

import (
	"context"
	"time"
)

// breaker is the read-only safety layer (SYNC-07): unexpected CLI output
// (3 consecutive bad write outcomes, an unrecognised `csf -v`, or a
// malformed csf.tempban line) switches it from "ok" to "degraded" — no more
// writes, existing blocks are left exactly as they are.
//
// No automatic fallback to the Defensia backend (locked decision: avoids
// double blocking) — the ONLY path that moves a ban from CSF back onto the
// Defensia backend is an explicit customer switch or undo, both of which go
// through executor_migrate.go's migrateToDefensia, never through this file.
//
// Recovery requires evidence, not time alone: two consecutive good probes
// (Version OK, csf.tempban parses with zero malformed lines, ListTemp
// classified OK/Benign), spaced csfProbeEvery apart.
type breaker struct {
	state          string // "ok" | "degraded"
	reason         string
	consecutiveBad int
	goodProbes     int
	lastProbeAt    time.Time

	// restartSince tracks how long CSF has looked like it's mid-restart
	// (csf.lock present or DENYIN missing); zero means "not currently
	// restarting". Distinct from state: a restart in progress is reported
	// as a paused read-only pass, not "degraded" or "unavailable", unless
	// it outlasts csfRestartPatience.
	restartSince time.Time
}

func newBreaker() *breaker { return &breaker{state: "ok"} }

// allowWrite reports whether the executor may issue -td/-tr right now.
func (b *breaker) allowWrite() bool { return b.state == "ok" }

// observe records one write outcome. restarting suppresses an
// iptables_error outcome from counting toward degrade — CSF reloading its
// own rules mid-restart is expected noise, not misbehaviour.
func (b *breaker) observe(o CSFOutcome, restarting bool) {
	switch o.Result {
	case ResultOK, ResultBenign, ResultRefused:
		b.consecutiveBad = 0
	case ResultUnexpected:
		if restarting && o.Reason == "iptables_error" {
			return
		}
		b.consecutiveBad++
		if b.state == "ok" && b.consecutiveBad >= csfDegradeAfter {
			b.degradeNow(o.Reason)
		}
	}
}

// degradeNow trips the breaker immediately, regardless of consecutiveBad —
// used for evidence that is unambiguous on its own (an unrecognised
// version banner, a tempban file with unparsable lines).
func (b *breaker) degradeNow(reason string) {
	b.state = "degraded"
	b.reason = reason
	b.consecutiveBad = 0
	b.goodProbes = 0
}

// recovered resets the breaker to "ok" — only ever called after
// csfRecoverAfter consecutive good probes.
func (b *breaker) recovered() {
	b.state = "ok"
	b.reason = ""
	b.consecutiveBad = 0
	b.goodProbes = 0
}

// probe runs the 3-part recovery check and records one good/bad probe,
// returning true only once csfRecoverAfter consecutive good probes have
// been observed (a single good probe after a bad one does not recover —
// goodProbes resets on any bad probe).
func (b *breaker) probe(ctx context.Context, cli *csfCLI) bool {
	if !probeCSFHealthy(ctx, cli) {
		b.goodProbes = 0
		return false
	}
	b.goodProbes++
	return b.goodProbes >= csfRecoverAfter
}

func probeCSFHealthy(ctx context.Context, cli *csfCLI) bool {
	if _, vOut := cli.Version(ctx); vOut.Result != ResultOK {
		return false
	}
	if t, err := readTempBans(); err != nil || t.Malformed > 0 {
		return false
	}
	lOut := cli.ListTemp(ctx)
	return lOut.Result == ResultOK || lOut.Result == ResultBenign
}
