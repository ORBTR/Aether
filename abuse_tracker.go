/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import (
	"fmt"
	"sync/atomic"

	"github.com/ORBTR/aether/abuse"
)

// AbuseTracker is the per-session abuse-scoring wrapper shared by the
// Noise and TCP adapters. It packages the four moving parts of
// per-peer misbehaviour scoring — the abuse.Score registry, the remote
// NodeID, a GoAway emitter, and a session close-with-error hook — into
// one type so the adapter call sites collapse to `tracker.Report(reason)`
// and the threshold-breaker path lives in exactly one place.
//
// Adapters used to inline three near-identical methods each:
//
//   - reportAbuse(reason) — record + maybe GoAway + maybe close
//   - PeerAbuseScore()    — read the current decayed score
//   - SetAbuseScoreRegistry(any) — swap the per-session registry for a
//     cross-session one, validating the concrete type
//
// The tracker owns the Score pointer so SetRegistry on the tracker
// uniformly updates both adapters. Goaway is a closure rather than a
// method on this type so the tracker stays uncoupled from the adapter's
// GoAway implementation (which differs across Noise / TCP / QUIC).
type AbuseTracker struct {
	// AE-P-01: atomic.Pointer so SetRegistry can swap the registry
	// concurrently with Report/PeerScore on the read/deliver hot path
	// without a data race on the pointer field. Load once per call.
	score    atomic.Pointer[abuse.Score[NodeID]]
	remote   NodeID
	goAway   func(reason GoAwayReason, message string) error
	closeErr func(error) error
	// dbgLog is the per-adapter debug printer used to log the
	// threshold-breaker event. nil-safe.
	dbgLog func(format string, args ...any)
}

// NewAbuseTracker builds a tracker bound to the supplied registry +
// remote peer. The goAway closure is invoked when the peer's score
// crosses the threshold (typically a one-line lambda over the
// adapter's session.GoAway). closeErr likewise drives the adapter's
// session.CloseWithError. Either may be nil — the tracker skips that
// step if no closure is supplied. dbgLog is optional.
func NewAbuseTracker(
	registry *abuse.Score[NodeID],
	remote NodeID,
	goAway func(reason GoAwayReason, message string) error,
	closeErr func(error) error,
	dbgLog func(format string, args ...any),
) *AbuseTracker {
	t := &AbuseTracker{
		remote:   remote,
		goAway:   goAway,
		closeErr: closeErr,
		dbgLog:   dbgLog,
	}
	t.score.Store(registry) // AE-P-01: publish registry via atomic store
	return t
}

// Report records a misbehaviour event against the remote peer. When
// the decayed score crosses the abuse-threshold edge (the registry's
// Record reports justExceeded=true) the tracker fires GoAway with
// GoAwayError and closes the session with a descriptive error.
//
// Safe to call at high frequency — the underlying Score uses
// exponential decay, so transient noise does not trip the breaker.
// Returns the current decayed score for adapter-side logging hooks
// that want to track score growth without re-reading via PeerScore.
func (t *AbuseTracker) Report(r abuse.Reason) float64 {
	if t == nil {
		return 0
	}
	score := t.score.Load() // AE-P-01: single atomic load per call
	if score == nil {
		return 0
	}
	current, exceeded := score.Record(t.remote, r)
	if !exceeded {
		return current
	}
	if t.dbgLog != nil {
		t.dbgLog("peer %s blacklisted (abuse score exceeded): reason=%s", t.remote.Short(), r)
	}
	if t.goAway != nil {
		_ = t.goAway(GoAwayError, "abuse threshold")
	}
	if t.closeErr != nil {
		_ = t.closeErr(fmt.Errorf("peer %s exceeded abuse threshold (reason: %s)", t.remote.Short(), r))
	}
	return current
}

// PeerScore returns the remote peer's current decayed score. The bool
// is false when no registry is bound — adapters can use that as the
// signal to return 0 from their public accessor.
func (t *AbuseTracker) PeerScore() (float64, bool) {
	if t == nil {
		return 0, false
	}
	score := t.score.Load() // AE-P-01: single atomic load per call
	if score == nil {
		return 0, false
	}
	return score.Current(t.remote), true
}

// SetRegistry swaps the per-session registry for a shared one — useful
// for cross-session operator dashboards. Returns false when the
// concrete type doesn't match (`*abuse.Score[NodeID]` is the only
// accepted form). Signature takes `interface{}` so the AbuseScoreCapable
// interface can stay package-cycle-free.
func (t *AbuseTracker) SetRegistry(r interface{}) bool {
	registry, ok := r.(*abuse.Score[NodeID])
	if !ok {
		return false
	}
	t.score.Store(registry) // AE-P-01: atomic swap, race-free vs Report/PeerScore
	return true
}

