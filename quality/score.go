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

	// decayLoopOnce guards lazy startup of the periodic decay
	// goroutine. Started on the first call to UpdateRTT /
	// UpdateThroughput / RecordCloseReason / IsDialSuppressed —
	// whichever fires first. Audit H8: previously decay only ran
	// from UpdateThroughput, so a dormant standby path (no traffic)
	// kept its accumulated failure count forever, suppressing
	// promotion even after the underlying issue cleared.
	decayLoopOnce sync.Once
	decayStop     chan struct{}
}

type trackerEntry struct {
	mu                  sync.Mutex
	baselineRTT         time.Duration // EMA of session SRTT
	lastBytesRecv       uint64
	lastBytesAt         time.Time
	bytesPerSec         float64
	consecutiveFailures atomic.Int64 // session-level close-with-error count
	reliabilityEMA      float64      // EMA of (1 if clean close, 0 if error)
	stabilityEMA           float64 // 1 - stabilitySmoothedDelta — exposed via Stability()
	stabilitySmoothedDelta float64 // EMA of |Δscore| (lower = more stable)
	lastScore           float64

	// Dial-level state. Tracked separately from session-level
	// consecutiveFailures because a dial failure means the handshake
	// never completed — there was no session to score. The dispatcher
	// suppresses dials of paths that have hit a threshold of consecutive
	// dial failures, mirroring the legacy peer.failedProtos cooldown
	// behaviour.
	dialFailureCount    atomic.Int64
	dialCooldownUntilNs atomic.Int64 // unix nanos; 0 = no cooldown

	// dialProbeLastNs is the timestamp of the last "opportunistic
	// probe" attempt — IsDialSuppressed allows one dial through every
	// dialProbeInterval(failureCount) of cooldown so a transient issue
	// that's actually resolved doesn't burn the full 10-minute cap
	// before any retry happens. L1 #6 fix from the routing review.
	dialProbeLastNs atomic.Int64 // unix nanos; 0 = never probed

	// lastFailureDecayAt is the most recent time
	// decayConsecutiveFailuresLocked halved the failure counter.
	// Cascade E / L4 #10 — prevents a long-stale failure penalty
	// from suppressing a path that's actually recovered.
	lastFailureDecayAt time.Time
}

// NewTracker creates an empty tracker. Pass to NewInputs to fill in
// the historical fields each Compute call needs. The periodic decay
// goroutine starts lazily on first touch (see ensureDecayLoop) so
// short-lived tests that never use the tracker don't spawn a
// goroutine.
func NewTracker() *Tracker {
	return &Tracker{decayStop: make(chan struct{})}
}

// ensureDecayLoop starts the periodic ConsecutiveFailures-decay
// goroutine on first call. Idempotent via sync.Once. Audit H8 fix —
// a path that's dormant (no UpdateThroughput firing) needs its
// failure count to age out anyway, otherwise it stays penalised long
// after the underlying network blip cleared.
func (t *Tracker) ensureDecayLoop() {
	t.decayLoopOnce.Do(func() {
		go t.runDecayLoop()
	})
}

// runDecayLoop ticks every consecutiveFailuresDecayInterval and walks
// every entry, halving the failure counter on paths whose
// lastFailureDecayAt is older than the interval. The walk is O(N
// entries) per tick but each entry's work is just an atomic Load +
// time compare + (rarely) one CAS — cheap.
//
// Stops on `Close()`.
func (t *Tracker) runDecayLoop() {
	ticker := time.NewTicker(consecutiveFailuresDecayInterval)
	defer ticker.Stop()
	for {
		select {
		case <-t.decayStop:
			return
		case now := <-ticker.C:
			t.entries.Range(func(_, v interface{}) bool {
				e, ok := v.(*trackerEntry)
				if !ok || e == nil {
					return true
				}
				e.mu.Lock()
				decayConsecutiveFailuresLocked(e, now)
				e.mu.Unlock()
				return true
			})
		}
	}
}

// Close stops the periodic decay goroutine. Safe to call multiple
// times. Trackers created via NewTracker without Close leak the
// goroutine until process exit — fine for the global tracker the
// runtime owns, but tests should defer Close().
func (t *Tracker) Close() {
	if t == nil {
		return
	}
	select {
	case <-t.decayStop:
		// already closed
	default:
		close(t.decayStop)
	}
}

// Key identifies a (peer, transport) pair within the tracker. Sessions
// for the same peer over different transports track independently —
// noise-udp's failure history shouldn't blacklist WS to the same peer.
func Key(peerID, transport string) string {
	return peerID + "|" + transport
}

// entry returns the trackerEntry for key, creating it if necessary.
func (t *Tracker) entry(key string) *trackerEntry {
	// Lazy-start the periodic decay loop on first entry creation —
	// any tracker that has at least one entry needs the decay loop
	// running. Idempotent via sync.Once. Audit H8.
	t.ensureDecayLoop()
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

// decayConsecutiveFailuresLocked applies time-based decay to the
// per-key consecutiveFailures counter. Called from UpdateThroughput
// (which fires on every per-tick stats update) so a path that's
// actually been carrying traffic gets its old failure penalty halved
// every consecutiveFailuresDecayInterval. Without this, a path that
// racked up 8 failures during a week of intermittent issues stays
// penalised hours after recovery — Cascade E / L4 #10 fix.
//
// Caller holds e.mu.
func decayConsecutiveFailuresLocked(e *trackerEntry, now time.Time) {
	cur := e.consecutiveFailures.Load()
	if cur == 0 {
		return
	}
	if e.lastFailureDecayAt.IsZero() {
		e.lastFailureDecayAt = now
		return
	}
	if now.Sub(e.lastFailureDecayAt) < consecutiveFailuresDecayInterval {
		return
	}
	// Halve. CompareAndSwap so concurrent RecordCloseReason can race
	// and still get a consistent result (its Add(1) will simply land
	// on the post-halved value).
	for {
		cur = e.consecutiveFailures.Load()
		if cur == 0 {
			break
		}
		newVal := cur / 2
		if e.consecutiveFailures.CompareAndSwap(cur, newVal) {
			break
		}
	}
	e.lastFailureDecayAt = now
}

// consecutiveFailuresDecayInterval is how often the failure counter
// halves while a path is being actively used (UpdateThroughput fires).
// 60s matches the timescale of the reliability EMA — a path that's
// stable for one minute deserves to be re-considered as a candidate.
const consecutiveFailuresDecayInterval = 60 * time.Second

// UpdateThroughput feeds a cumulative byte count + timestamp into the
// per-key throughput EMA. Computes bytes/sec from the delta against
// the previous sample. Also opportunistically decays the
// consecutiveFailures counter — a path that's actually carrying
// traffic deserves to lose its old failure penalty over time.
func (t *Tracker) UpdateThroughput(key string, bytesRecv uint64) {
	now := time.Now()
	e := t.entry(key)
	e.mu.Lock()
	defer e.mu.Unlock()
	decayConsecutiveFailuresLocked(e, now)
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

// CloseReason categorises a session-close event so the reliability
// scorer can distinguish a peer-rejected dedup-race close (carries no
// signal about path health) from a clean GoAway (positive signal) from
// an actual transport error (negative signal).
//
// L4 #4 fix: the previous (cleanClose bool) signature lumped dedup-race
// closes and transport errors together based on lifetime — a transport
// that died in the first 6s of every attempt LOOKED LIKE a perfect
// clean-close path to the EMA, so chronically-broken paths stayed at
// reliability=1.0 forever.
type CloseReason int

const (
	// CloseClean is a normal GoAway-initiated close. Positive signal.
	CloseClean CloseReason = iota

	// CloseRaceLoser is a dedup-race loss — the peer had a more
	// recent session and rejected ours. No signal about path health.
	// Skip the EMA but DON'T bump consecutiveFailures.
	CloseRaceLoser

	// CloseTransportError is an actual error close — handshake
	// failed, frame parse error, AEAD authentication failure, etc.
	// Negative signal: feeds reliability EMA toward 0 and bumps
	// consecutiveFailures.
	CloseTransportError
)

// RecordCloseReason feeds a session-close event classified by reason.
// Preferred over the legacy RecordClose for new call sites; the
// legacy bool maps to either CloseClean or CloseTransportError so
// existing callers keep working.
func (t *Tracker) RecordCloseReason(key string, reason CloseReason) {
	e := t.entry(key)
	switch reason {
	case CloseClean:
		e.consecutiveFailures.Store(0)
		e.mu.Lock()
		e.reliabilityEMA = 0.1*1.0 + 0.9*e.reliabilityEMA
		e.mu.Unlock()
	case CloseRaceLoser:
		// Neither signal — race-loser closes are routing churn,
		// not path health. Per memory project_dedup_feedback_loop:
		// feeding these to EMA causes scaler→K→dial→reject→close
		// self-amplifying churn loops.
	case CloseTransportError:
		e.consecutiveFailures.Add(1)
		e.mu.Lock()
		e.reliabilityEMA = 0.1*0.0 + 0.9*e.reliabilityEMA
		e.mu.Unlock()
	}
}

// RecordClose is the legacy two-state API. Maintained for existing
// callers. New code should use RecordCloseReason with an explicit
// reason — particularly CloseRaceLoser, which this legacy signature
// cannot express (the cleanClose=true mapping doesn't capture that
// race-loser closes carry no health signal at all).
func (t *Tracker) RecordClose(key string, cleanClose bool) {
	if cleanClose {
		t.RecordCloseReason(key, CloseClean)
	} else {
		t.RecordCloseReason(key, CloseTransportError)
	}
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

// PeerReliability returns the minimum reliability EMA across every
// transport tracked for a peer, or 1.0 if no entries exist for the
// peer. The pessimistic aggregate is correct for the connection
// scaler's purposes: if any one transport keeps failing, the peer
// relationship is unstable enough to warrant extra capacity even when
// the other transports look fine.
func (t *Tracker) PeerReliability(peerID string) float64 {
	prefix := peerID + "|"
	worst := 1.0
	found := false
	t.entries.Range(func(k, v any) bool {
		s, ok := k.(string)
		if !ok || len(s) <= len(prefix) || s[:len(prefix)] != prefix {
			return true
		}
		e := v.(*trackerEntry)
		e.mu.Lock()
		r := e.reliabilityEMA
		e.mu.Unlock()
		if !found || r < worst {
			worst = r
			found = true
		}
		return true
	})
	return worst
}

// RecordScore feeds the latest aggregate score into the stability EMA.
// Stability is 1 − EMA of |Δscore| so a path whose score bounces around
// scores lower in the next compute.
//
// Proper EMA: stability_new = α·current_stability_estimate + (1-α)·prev.
// The previous formula computed `variance = 0.2*delta + 0.8*(1-stab)`
// then `stab = 1 - variance`, whose fixed point at delta=0 sits at
// stab=1.0 ONLY if reached from stab=1.0 — anything below 1.0 oscillated
// around 0.5 (was H-Quality-EMA-Oscillation). The correct EMA-of-|delta|
// formula tracks delta directly and derives stab as `1 - smoothed_delta`,
// with a steady-state of 1.0 at delta=0 reachable from any prior value.
func (t *Tracker) RecordScore(key string, score float64) {
	e := t.entry(key)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.lastScore != 0 {
		delta := score - e.lastScore
		if delta < 0 {
			delta = -delta
		}
		// Smooth |delta| with α=0.2. stabilitySmoothedDelta starts at 0
		// (max stability) so first samples bias toward "stable".
		e.stabilitySmoothedDelta = 0.2*delta + 0.8*e.stabilitySmoothedDelta
		e.stabilityEMA = clamp01(1 - e.stabilitySmoothedDelta)
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

// RecordDialFailure increments the dial-failure counter for a key and
// sets a cooldown that callers consult before re-dialing the same
// (peer, transport) pair. The cooldown grows with consecutive failures:
//
//	1 failure  → baseDialCooldown (30 s)
//	2 failures → 1 min
//	3 failures → 2 min
//	N failures → min(2 min × 2^(N-3), suppressDialCooldown=10 min)
//
// Replaces peer.failedProtos[proto] + peer.dialFailCount[proto] +
// m.cooldownFor(peer, proto) — all that bookkeeping moves into the
// tracker so a single source of truth covers both session-level and
// dial-level failure suppression.
func (t *Tracker) RecordDialFailure(key string) {
	e := t.entry(key)
	n := e.dialFailureCount.Add(1)
	cooldown := dialCooldownDuration(int(n))
	expiry := time.Now().Add(cooldown).UnixNano()
	e.dialCooldownUntilNs.Store(expiry)
}

// RecordDialSuccess clears the dial-failure counter and cooldown for
// a key. Called after a successful dial completes the handshake so a
// path that was failing intermittently can be re-evaluated.
func (t *Tracker) RecordDialSuccess(key string) {
	v, ok := t.entries.Load(key)
	if !ok {
		return
	}
	e := v.(*trackerEntry)
	e.dialFailureCount.Store(0)
	e.dialCooldownUntilNs.Store(0)
}

// RecordCooldown sets a fixed dial cooldown without bumping the failure
// counter. Complementary to RecordDialFailure: the latter is for
// authentic dial failures where "more failures = longer cooldown" makes
// sense (the underlying problem is presumed durable), this is for
// transient events like session stalls where the appropriate response
// is "don't redial for N seconds, then try again from scratch". Setting
// d=0 is a no-op so callers don't need to special-case it.
//
// If a longer cooldown is already in flight (e.g., from a previous
// RecordDialFailure), this preserves whichever expiry is later — a
// short stall cooldown can't shorten a real failure cooldown.
func (t *Tracker) RecordCooldown(key string, d time.Duration) {
	if d <= 0 {
		return
	}
	e := t.entry(key)
	newExpiry := time.Now().Add(d).UnixNano()
	for {
		cur := e.dialCooldownUntilNs.Load()
		if cur >= newExpiry {
			return
		}
		if e.dialCooldownUntilNs.CompareAndSwap(cur, newExpiry) {
			return
		}
	}
}

// IsDialSuppressed returns whether the path is in cooldown right now.
// PURE PREDICATE — does not mutate state; safe to call multiple times
// for observability, dashboards, and dual-checks. Lazy-clears the
// cooldown when its expiry has passed (idempotent), so the first
// poll after the cooldown window naturally returns false. The second
// return value is the cooldown's remaining duration, useful for
// observability and for the EnsureK reconnect loop's backoff.
//
// Audit M12: this used to mutate dialProbeLastNs as a side effect of
// the predicate query, violating command-query separation — a caller
// that read the result twice would have stamped two probes. The
// probe-allowance side effect now lives in TryDialThrough, called
// only by the dialer when it's about to actually attempt a dial.
func (t *Tracker) IsDialSuppressed(key string) (bool, time.Duration) {
	v, ok := t.entries.Load(key)
	if !ok {
		return false, 0
	}
	e := v.(*trackerEntry)
	expiry := e.dialCooldownUntilNs.Load()
	if expiry == 0 {
		return false, 0
	}
	remaining := time.Until(time.Unix(0, expiry))
	if remaining <= 0 {
		// Lazily clear so subsequent reads are fast. CAS so two
		// concurrent observers don't race; whichever wins clears
		// the field, the other reads 0 next time.
		e.dialCooldownUntilNs.CompareAndSwap(expiry, 0)
		return false, 0
	}
	return true, remaining
}

// TryDialThrough returns true if the dialer should be allowed to
// attempt a dial RIGHT NOW for this key, false if the cooldown still
// applies. Distinct from IsDialSuppressed in that this is the
// COMMAND form — calling it stamps an opportunistic-probe timestamp
// when it returns true during a cooldown, so the next call within the
// probe interval will return false.
//
// Use this exactly once at the start of a dial attempt, NOT for
// observability or repeated checks. The intended pattern:
//
//	if !tracker.TryDialThrough(key) {
//	    return ErrDialSuppressed
//	}
//	// actually dial
//
// Audit M12 fix — splits the predicate (IsDialSuppressed, pure)
// from the command (TryDialThrough, allowed to mutate).
//
// L1 #6 opportunistic probe semantics: even during cooldown, this
// returns true once every dialProbeInterval(failureCount) so a
// transient issue that's actually resolved doesn't burn the full
// 10-minute cap before any retry.
func (t *Tracker) TryDialThrough(key string) bool {
	v, ok := t.entries.Load(key)
	if !ok {
		return true // no record → no suppression
	}
	e := v.(*trackerEntry)
	expiry := e.dialCooldownUntilNs.Load()
	if expiry == 0 {
		return true
	}
	remaining := time.Until(time.Unix(0, expiry))
	if remaining <= 0 {
		e.dialCooldownUntilNs.CompareAndSwap(expiry, 0)
		return true
	}
	// In cooldown — check probe allowance.
	now := time.Now().UnixNano()
	failures := e.dialFailureCount.Load()
	probeInterval := dialProbeInterval(failures)
	if probeInterval <= 0 {
		return false
	}
	last := e.dialProbeLastNs.Load()
	if last != 0 && time.Duration(now-last) < probeInterval {
		return false
	}
	// Stamp probe attempt — CAS so concurrent callers can't both
	// be allowed through on the same probe slot.
	if e.dialProbeLastNs.CompareAndSwap(last, now) {
		return true
	}
	// Lost the CAS — another goroutine grabbed the probe slot.
	return false
}

// dialProbeInterval returns how often an opportunistic dial probe is
// allowed during cooldown. Scales with failure count so a rapidly
// flapping path doesn't get probed every few seconds — but a
// long-suppressed path (10-min cap) gets a chance every ~2.5 minutes
// to detect recovery. Returns 0 for low failure counts (the cooldown
// is short enough that probing during it adds little value).
func dialProbeInterval(failures int64) time.Duration {
	if failures < 3 {
		return 0 // base cooldowns ≤ 1 min; just wait them out
	}
	cooldown := dialCooldownDuration(int(failures))
	// One probe per quarter of the cooldown window. Caps at 2.5 min
	// (10-min cap / 4).
	return cooldown / 4
}

// DialFailureCount returns the consecutive dial-failure count for a
// key. Used by callers that want to surface "this path has been
// flapping" in observability or to apply additional logic (e.g.
// preferring transports with fewer recent failures during EnsureK
// reconnect ordering).
func (t *Tracker) DialFailureCount(key string) int {
	v, ok := t.entries.Load(key)
	if !ok {
		return 0
	}
	return int(v.(*trackerEntry).dialFailureCount.Load())
}

// dialCooldownDuration is the cooldown growth schedule. Pulled out so
// callers (and tests) can reason about timing without re-implementing
// the formula.
func dialCooldownDuration(failureCount int) time.Duration {
	const (
		baseCooldown     = 30 * time.Second
		maxCooldown      = 10 * time.Minute
		suppressThresh   = 3 // failures
	)
	if failureCount <= 0 {
		return 0
	}
	if failureCount == 1 {
		return baseCooldown
	}
	if failureCount == 2 {
		return 1 * time.Minute
	}
	// At suppressThresh, we go to long suppression
	exp := failureCount - suppressThresh // 0,1,2,...
	if exp < 0 {
		exp = 0
	}
	d := 2 * time.Minute
	for i := 0; i < exp; i++ {
		d *= 2
		if d > maxCooldown {
			return maxCooldown
		}
	}
	return d
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
