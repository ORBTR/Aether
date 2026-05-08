package quality

import (
	"sync"
	"sync/atomic"
	"time"
)

// Inputs is the snapshot of measurements used to compute a Score for one
// session at one point in time. All fields are read from existing
// session-level state (health.Monitor, SessionMetrics, FailureTracker)
// — no new per-session bookkeeping is added by this package.
//
// Callers are expected to populate Inputs via NewInputs(session, tracker)
// rather than constructing it by hand; the field list is exposed so
// tests and observability surfaces can produce synthetic Inputs.
type Inputs struct {
	// Class is the route's geographic span. Sets the expected RTT band
	// against which the path's RTT is normalized.
	Class RouteClass

	// SRTT is the smoothed round-trip time (RFC 6298), read from
	// session.Health().SRTT(). Zero indicates no measurement yet.
	SRTT time.Duration

	// RTTVar is the smoothed RTT mean deviation, read from
	// session.Health().RTTVar(). Used for the jitter component.
	RTTVar time.Duration

	// BaselineRTT is the path's own historical SRTT EMA, used for
	// the trend component. If zero, trend is unscored (1.0). Computed
	// by Tracker as a long-window EMA of SRTT samples.
	BaselineRTT time.Duration

	// LossPermille is the recent packet-loss estimate in parts per
	// thousand (0–1000). Read from session.Metrics().LossPercent ×
	// 10. Zero indicates no observed loss.
	LossPermille int

	// FramesRecv is the cumulative inbound frame count. Used to
	// normalize Reorders so a busy path's reorders aren't double-
	// counted.
	FramesRecv int64

	// Reorders is the cumulative out-of-order frame count, summed
	// across streams from session.Metrics().StreamObserve.
	Reorders int64

	// BytesPerSec is the recently-observed throughput. Computed by
	// Tracker as (BytesRecv delta / time delta) over a short window
	// so a session that's been quiet for a while doesn't show its
	// long-ago peak.
	BytesPerSec float64

	// ConsecutiveFailures is the count of consecutive close-with-
	// error events on this (peer, transport) pair. Reset on a
	// successful long-lived session. Read from Tracker.
	ConsecutiveFailures int

	// Reliability is 1 − close-error-rate over a longer window than
	// ConsecutiveFailures. ~0.95 for a stable peer-transport with one
	// odd close in many; ~0.5 for a chronically flap-prone pair.
	Reliability float64

	// Stability is 1 − recent score variance. Computed by Tracker as
	// EMA of |score(t) − score(t-1)|; high variance → low stability.
	Stability float64

	// Age is time since the session was created. Drives the AgeGrace
	// ramp so brand-new sessions don't score low for not having
	// throughput/reliability signals yet.
	Age time.Duration
}

// Score is the result of evaluating Inputs against Weights. It carries
// both the aggregate value (used by callers) and the component
// breakdown (used for observability and for the dispatch layer's
// op-class weighting).
type Score struct {
	// Aggregate is the final [0, 1] score. Read by multipath dispatch,
	// liveness loop, and any other consumer that needs a single number.
	Aggregate float64

	// Components is the per-dimension breakdown. Useful for explaining
	// *why* a score is what it is. The dispatch layer can also re-
	// combine components with op-class-specific weights (e.g.,
	// latency-sensitive dispatch gives RTT extra weight beyond the
	// default).
	Components Components

	// Class is the RouteClass used to compute this score. Surfaced
	// so the dispatch layer can apply region-affinity bonuses
	// without redoing classification.
	Class RouteClass

	// ComputedAt is when this score was computed. Used by callers
	// that cache scores to invalidate after staleness.
	ComputedAt time.Time
}

// IsAlive returns true when the score is high enough to consider the
// session viable for dispatch. Threshold tuned so brand-new sessions
// (in their AgeGrace window) and severely degraded sessions are
// excluded but most working sessions pass.
func (s Score) IsAlive() bool { return s.Aggregate > 0.05 }

// IsHealthy returns true when the score is high enough that the session
// is preferred for new dispatches. Above this threshold, multipath
// treats the session as a first-tier path; below it, the session is
// retained as a fallback only.
func (s Score) IsHealthy() bool { return s.Aggregate > 0.5 }

// Compute evaluates Inputs against Weights and returns a Score. Pure
// function — no side effects, no global state. Safe to call from any
// goroutine, including high-frequency dispatch hot paths.
func Compute(in Inputs, w Weights) Score {
	c := Components{
		RTT:            rttHealth(in.SRTT, in.Class),
		RTTTrend:       rttTrendHealth(in.SRTT, in.BaselineRTT),
		Loss:           lossHealth(in.LossPermille),
		Jitter:         jitterHealth(in.SRTT, in.RTTVar),
		Reorder:        reorderHealth(in.Reorders, in.FramesRecv),
		Throughput:     throughputHealth(in.BytesPerSec, in.Class),
		Reliability:    clamp01(in.Reliability),
		Stability:      clamp01(in.Stability),
		FailurePenalty: failurePenalty(in.ConsecutiveFailures),
		AgeGrace:       ageGrace(in.Age),
	}
	return Score{
		Aggregate:  c.score(w),
		Components: c,
		Class:      in.Class,
		ComputedAt: time.Now(),
	}
}

// DispatchOp tags a dispatch context so the routing layer can weight
// components differently. Latency-sensitive RPCs care more about RTT;
// bulk transfers care more about throughput; gossip is balanced.
type DispatchOp int

const (
	OpDefault DispatchOp = iota
	OpLatencySensitive
	OpBulkTransfer
	OpGossip
)

// DispatchRank computes a composite ranking for choosing between
// multiple alive sessions to a given peer at dispatch time. Combines
// the session's stored Score with op-class-specific weighting and a
// region-affinity bonus.
//
// Rationale for keeping this separate from Compute(): the score is a
// property of the session itself ("how healthy is this connection?")
// and shouldn't depend on what the caller intends to do. The rank
// adjusts the score for the context of a specific dispatch ("for this
// kind of work, is this connection a good fit?") without modifying
// the underlying score.
func DispatchRank(s Score, op DispatchOp) float64 {
	rank := s.Aggregate

	// Region affinity: same-region paths get a small bonus,
	// cross-region get a small discount. The bonus is applied
	// multiplicatively after the score so a high-quality cross-
	// region path still beats a low-quality same-region one.
	switch s.Class {
	case RouteSameRegion:
		rank *= 1.10
	case RouteCrossRegion:
		rank *= 0.95
	case RouteInterContinental:
		rank *= 0.90
	}

	// Op-class adjustments: re-weight a single component without
	// recomputing the whole score, by multiplying the rank by a
	// power of the relevant component value. This is a cheap
	// approximation of "what would this score be if we'd weighted
	// X more heavily?".
	switch op {
	case OpLatencySensitive:
		rank *= 1.0 + 0.5*(s.Components.RTT-0.5)
	case OpBulkTransfer:
		rank *= 1.0 + 0.5*(s.Components.Throughput-0.5)
	case OpGossip:
		// Gossip prefers stable paths over fast ones — a flap-prone
		// path costs gossip more than a slow one.
		rank *= 1.0 + 0.3*(s.Components.Stability-0.5)
	}

	return clamp01(rank)
}

// Tracker keeps the longer-window state that Inputs draws from but
// the session itself doesn't already store: baseline RTT EMA, recent
// throughput, score-variance for stability, and consecutive-failure
// counts per (peer, transport) pair.
//
// Lock-light: each per-key entry is its own struct so concurrent
// scoring of different sessions doesn't contend. The outer map is
// sharded by hash for the same reason — but for the v1 implementation
// a single sync.Map is fine; if profiling shows contention we can
// shard later.
type Tracker struct {
	entries sync.Map // key string → *trackerEntry
}

type trackerEntry struct {
	mu                  sync.Mutex
	baselineRTT         time.Duration // EMA of session SRTT
	lastBytesRecv       uint64
	lastBytesAt         time.Time
	bytesPerSec         float64
	consecutiveFailures atomic.Int64
	reliabilityEMA      float64 // EMA of (1 if clean close, 0 if error)
	stabilityEMA        float64 // EMA of |Δscore|
	lastScore           float64
}

// NewTracker creates an empty tracker. Pass to NewInputs to fill in
// the historical fields each Compute call needs.
func NewTracker() *Tracker { return &Tracker{} }

// Key identifies a (peer, transport) pair within the tracker. Sessions
// for the same peer over different transports track independently —
// noise-udp's failure history shouldn't blacklist WS to the same peer.
func Key(peerID, transport string) string {
	return peerID + "|" + transport
}

// entry returns the trackerEntry for key, creating it if necessary.
func (t *Tracker) entry(key string) *trackerEntry {
	if v, ok := t.entries.Load(key); ok {
		return v.(*trackerEntry)
	}
	e := &trackerEntry{
		reliabilityEMA: 1.0, // start optimistic; failures will drag down
		stabilityEMA:   1.0, // ditto
	}
	v, _ := t.entries.LoadOrStore(key, e)
	return v.(*trackerEntry)
}

// UpdateRTT feeds an SRTT sample into the per-key baseline EMA. Called
// each time a score is computed so the baseline tracks the path's own
// recent history.
func (t *Tracker) UpdateRTT(key string, srtt time.Duration) {
	if srtt <= 0 {
		return
	}
	e := t.entry(key)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.baselineRTT == 0 {
		e.baselineRTT = srtt
		return
	}
	// EMA with α = 0.05 — slow window so single spikes don't move
	// the baseline. About 60 samples worth of memory.
	e.baselineRTT = time.Duration(
		0.05*float64(srtt) + 0.95*float64(e.baselineRTT),
	)
}

// BaselineRTT returns the current baseline for a key, or 0 if no data.
func (t *Tracker) BaselineRTT(key string) time.Duration {
	v, ok := t.entries.Load(key)
	if !ok {
		return 0
	}
	e := v.(*trackerEntry)
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.baselineRTT
}

// UpdateThroughput feeds a cumulative byte count + timestamp into the
// per-key throughput EMA. Computes bytes/sec from the delta against
// the previous sample.
func (t *Tracker) UpdateThroughput(key string, bytesRecv uint64) {
	now := time.Now()
	e := t.entry(key)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.lastBytesAt.IsZero() {
		e.lastBytesRecv = bytesRecv
		e.lastBytesAt = now
		return
	}
	dt := now.Sub(e.lastBytesAt).Seconds()
	if dt < 0.5 {
		// Too short a window — ignore to avoid noise from
		// quiescent periods.
		return
	}
	if bytesRecv < e.lastBytesRecv {
		// Counter rolled — reset baseline.
		e.lastBytesRecv = bytesRecv
		e.lastBytesAt = now
		return
	}
	delta := float64(bytesRecv - e.lastBytesRecv)
	sample := delta / dt
	if e.bytesPerSec == 0 {
		e.bytesPerSec = sample
	} else {
		// EMA with α = 0.3 — quicker than RTT baseline because
		// throughput legitimately varies more.
		e.bytesPerSec = 0.3*sample + 0.7*e.bytesPerSec
	}
	e.lastBytesRecv = bytesRecv
	e.lastBytesAt = now
}

// BytesPerSec returns the current throughput EMA for a key.
func (t *Tracker) BytesPerSec(key string) float64 {
	v, ok := t.entries.Load(key)
	if !ok {
		return 0
	}
	e := v.(*trackerEntry)
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.bytesPerSec
}

// RecordClose feeds a session-close event. cleanClose=true means a
// clean GoAway; cleanClose=false means CloseWithError. Drives both
// the consecutive-failures count and the reliability EMA.
func (t *Tracker) RecordClose(key string, cleanClose bool) {
	e := t.entry(key)
	if cleanClose {
		e.consecutiveFailures.Store(0)
	} else {
		e.consecutiveFailures.Add(1)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	signal := 1.0
	if !cleanClose {
		signal = 0.0
	}
	// EMA with α = 0.1 — about 10 closes' worth of memory.
	e.reliabilityEMA = 0.1*signal + 0.9*e.reliabilityEMA
}

// ConsecutiveFailures returns the current count for a key.
func (t *Tracker) ConsecutiveFailures(key string) int {
	v, ok := t.entries.Load(key)
	if !ok {
		return 0
	}
	return int(v.(*trackerEntry).consecutiveFailures.Load())
}

// Reliability returns the current EMA for a key, or 1.0 if no data.
func (t *Tracker) Reliability(key string) float64 {
	v, ok := t.entries.Load(key)
	if !ok {
		return 1.0
	}
	e := v.(*trackerEntry)
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.reliabilityEMA
}

// RecordScore feeds the latest aggregate score into the stability EMA.
// Stability is 1 − EMA of |Δscore| so a path whose score bounces around
// scores lower in the next compute.
func (t *Tracker) RecordScore(key string, score float64) {
	e := t.entry(key)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.lastScore != 0 {
		delta := score - e.lastScore
		if delta < 0 {
			delta = -delta
		}
		// EMA of |delta| — lower is more stable.
		variance := 0.2*delta + 0.8*(1-e.stabilityEMA)
		e.stabilityEMA = clamp01(1 - variance)
	}
	e.lastScore = score
}

// Stability returns the current stability EMA for a key, or 1.0 if no
// data (new keys start optimistic).
func (t *Tracker) Stability(key string) float64 {
	v, ok := t.entries.Load(key)
	if !ok {
		return 1.0
	}
	e := v.(*trackerEntry)
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stabilityEMA
}

// Forget drops a single (peer, transport) entry from the tracker.
// Called when a peer is permanently removed from the topology
// (pruneStalePeers / unregister) so the tracker doesn't accumulate
// state for nodes that are gone. Cheap — sync.Map.Delete is a no-op
// if the key isn't present.
func (t *Tracker) Forget(key string) {
	t.entries.Delete(key)
}

// ForgetPeer drops every entry whose key matches "<peerID>|...". Used
// when a peer is removed from the topology — every transport tracked
// for that peer becomes stale at once. Walks the sync.Map once;
// O(entries) but only invoked on peer eviction so the cost is bounded.
func (t *Tracker) ForgetPeer(peerID string) {
	prefix := peerID + "|"
	t.entries.Range(func(k, _ any) bool {
		if s, ok := k.(string); ok && len(s) > len(prefix) && s[:len(prefix)] == prefix {
			t.entries.Delete(k)
		}
		return true
	})
}
