//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

// Package multipath manages multiple transport paths to a single peer.
//
// Level 1 — Active/Standby: one primary path, one standby with periodic probes.
// Instant failover when primary dies, failback after stability period.
//
// Level 2 — Redundant REALTIME: REALTIME class frames sent on BOTH paths.
// Dedup on receive by SeqNo. Data class frames only on primary.
package multipath

import (
	"context"
	"sync"
	"time"

	"github.com/ORBTR/aether"
)

// PathState tracks the health state of a single transport path.
type PathState int

const (
	PathActive   PathState = iota // primary path, carrying all traffic
	PathStandby                    // backup path, periodic probes only
	PathProbing                    // checking if standby is still alive
	PathDead                       // failed probes, not usable
	PathFlapping                   // STALL-DETECT false-positive repeated; demoted for a cooldown window
)

// String returns a human-readable state.
func (s PathState) String() string {
	switch s {
	case PathActive:
		return "active"
	case PathStandby:
		return "standby"
	case PathProbing:
		return "probing"
	case PathDead:
		return "dead"
	case PathFlapping:
		return "flapping"
	default:
		return "unknown"
	}
}

// PathFlapping demote tier — see RecordTLPReset.
//
// The session-level STALL-DETECT false-positive path in the noise
// adapter (see adapter/noise_reliability.go [STALL-DETECT]
// "false-positive") fires when the stall detector declares "no
// progress" but the probe-before-close Ping then succeeds. A single
// false-positive is a transient blip that the inline recovery (cwnd
// reset + TLP reset) handles fine. Repeated false-positives within a
// short window mean the path is not crashing but IS losing tail
// packets often enough that the stall detector keeps firing —
// typical of a flaky cross-region UDP path with bursty NAT /
// conntrack drops. Demoting traffic to a steadier transport (WS,
// TCP) until the path settles is preferable to letting the
// bimodal-latency tail accumulate on the noise path.
//
//   - flappingResetThreshold: tlpReset hits-in-window before demote.
//   - flappingWindowDur: sliding window over which hits are counted.
//   - flappingDemoteDur: how long the path stays in PathFlapping
//     after the most recent qualifying hit before reverting to
//     PathStandby. Re-emitted by every subsequent hit while the
//     path is already PathFlapping, so a sustained burst keeps the
//     path demoted for the full window past the LAST event.
const (
	flappingResetThreshold = 3
	flappingWindowDur      = 5 * time.Minute
	flappingDemoteDur      = 60 * time.Second
)

// Path represents a single transport path to a peer.
type Path struct {
	Session  aether.Session
	Protocol aether.Protocol
	State    PathState
	Quality  int // higher = better (matches connection quality system)
	RTT      time.Duration
	LastProbe time.Time
	LastSuccess time.Time
	ConsecutiveFailures int

	// CreatedAt is the wall-clock at addPathLocked time. Stable across
	// the path's lifetime — written ONCE on path creation and never
	// rewritten by probe success. The quality scorer's sessionAge gate
	// reads CreatedAt (not LastSuccess) so AgeGrace ramps from 0→1
	// monotonically over the path's lifetime instead of resetting on
	// every probe ACK. LastSuccess is rewritten by OnProbeSuccess on
	// every probe, so reading it as a creation-time proxy would re-
	// enter the AgeGrace=0 window on every probe and multiplicatively
	// zero the path's Aggregate score for its entire lifetime.
	CreatedAt time.Time

	// LastFailure timestamp drives the dead→standby resurrection path.
	// OnPrimaryFailure stamps this when marking PathDead; the probe loop
	// (and PickByQuality / PickPath opportunistically) check that
	// `time.Now().Sub(LastFailure) >= deadResurrectCooldown` before
	// re-considering the path as a standby candidate. Cascade A.3 fix
	// (L4 #2+#7) — previously PathDead was terminal with no recovery.
	LastFailure time.Time

	// Level 3 weighted scheduling counters. weight is derived from
	// Quality + RTT + loss; bytesScheduled is what we've sent on this
	// path in the current round. The scheduler picks the path with
	// the largest weight*round - bytesScheduled deficit.
	Loss          float64 // 0.0 (no loss) → 1.0 (total loss)
	weightCache   float64
	bytesScheduled int64

	// PathFlapping bookkeeping. tlpResetEvents is a sliding-window
	// ring of the last `flappingResetThreshold` tlpReset event
	// timestamps; flappingUntil is the absolute time at which the
	// path may transition back from PathFlapping → PathStandby (its
	// pre-demote state was Healthy/Standby/Active — we always restore
	// to Standby and let promotebestStandby + setPrimary re-elect).
	// Events older than flappingWindowDur are ignored on insert.
	tlpResetEvents [flappingResetThreshold]time.Time
	tlpResetIdx    int
	flappingUntil  time.Time
}

// deadResurrectCooldown is the minimum time a path stays in PathDead
// before becoming a probe/promotion candidate again. Without this,
// either every probe attempt would slam a dead path immediately after
// failure (wasteful churn) or PathDead would be permanent (the bug
// Cascade A.3 fixed). 30s matches the probeInterval default so the
// next probe tick is the first chance for resurrection.
const deadResurrectCooldown = 30 * time.Second

// Manager manages multiple paths to a single peer.
type Manager struct {
	mu    sync.Mutex
	paths []*Path
	primary int // index of active path

	// probeTick increments on every probeNonPrimary invocation. Used to
	// decide whether to include the primary path in this tick's probe
	// set (every primaryProbeEvery-th tick). Was H-Multipath-PrimaryProbe.
	probeTick uint64

	// Configuration
	probeInterval    time.Duration
	stabilityPeriod  time.Duration
	maxFailures      int

	// Redundancy level
	redundantRealtime bool // Level 2: send REALTIME on both paths
	weightedLB        bool // Level 3: weighted load balance across paths

	// qstate carries the quality scoring + EnsureK reconnect state.
	// nil for legacy callers that haven't called AddPathQA or
	// EnsureK; populated lazily by either, so existing AddPath +
	// PrimarySession callers continue to work unchanged.
	qstate *qualityState

	// nowFunc is an injectable clock for tests. nil → time.Now. The
	// PathFlapping demote tier checks both the 5-minute sliding
	// window for tlpReset hits AND a 60-second demote-expiry timer,
	// neither of which is practical to exercise under wall-clock in
	// a unit test. now() routes both through nowFunc so the test
	// can advance virtual time deterministically.
	nowFunc func() time.Time
}

// now returns the current time, honouring nowFunc when injected.
// Field is set once at construction (or by a test) and read-only
// afterwards, so no lock needed for the read.
func (m *Manager) now() time.Time {
	if m.nowFunc != nil {
		return m.nowFunc()
	}
	return time.Now()
}

// NewManager creates a multipath manager.
func NewManager() *Manager {
	return &Manager{
		probeInterval:   30 * time.Second,
		stabilityPeriod: 60 * time.Second,
		maxFailures:     3,
	}
}

// SetProbeInterval overrides the cadence at which RunProbeLoop pings
// non-primary paths. Default 30s; callers that need to beat a faster
// underlying-conn idle close (Fly 6PN UDP / cross-region NAT) should
// drop this to 5-8s so the keepalive PING reaches the peer before the
// kernel conntrack / NAT mapping reaps the socket. Call before
// RunProbeLoop — the running ticker captures the value at start.
func (m *Manager) SetProbeInterval(d time.Duration) {
	if d <= 0 {
		return
	}
	m.mu.Lock()
	m.probeInterval = d
	m.mu.Unlock()
}

// EnableRedundantRealtime activates Level 2 — REALTIME frames on both paths.
func (m *Manager) EnableRedundantRealtime() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.redundantRealtime = true
}

// EnableWeightedLoadBalance activates Level 3 — non-REALTIME frames are
// distributed across active+standby paths proportional to each path's
// quality score (function of Quality, RTT, and Loss).
//
// REALTIME traffic continues to use the primary path (or both, if Level 2
// is also enabled) — the weighted distribution is for INTERACTIVE/BULK
// classes where reordering at the receiver is acceptable.
func (m *Manager) EnableWeightedLoadBalance() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.weightedLB = true
}

// RecordPathStats updates RTT and loss for a path. Called from the
// per-session metrics collector. Triggers a weight cache refresh.
func (m *Manager) RecordPathStats(session aether.Session, rtt time.Duration, loss float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.paths {
		if p.Session == session {
			p.RTT = rtt
			if loss < 0 {
				loss = 0
			}
			if loss > 1 {
				loss = 1
			}
			p.Loss = loss
			p.weightCache = computePathWeight(p)
			return
		}
	}
}

// PickPath returns the best path for a non-REALTIME frame of size n bytes
// using weighted-deficit round-robin. Falls back to the primary path when
// Level 3 is disabled or when only one path is available. Returns nil
// only if there are no live paths.
func (m *Manager) PickPath(n int) aether.Session {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Opportunistic resurrection: even without RunProbeLoop running,
	// paths whose cooldown has elapsed get re-considered here.
	m.resurrectExpiredDeadPathsLocked()
	m.resurrectExpiredFlappingPathsLocked()

	if !m.weightedLB || len(m.paths) <= 1 {
		if m.primary < len(m.paths) {
			return m.paths[m.primary].Session
		}
		return nil
	}

	// Weighted Deficit Round-Robin (WDRR) — pick the path whose
	// bytes-sent-per-unit-weight is lowest. The path "owes" itself the
	// most bytes given its weight share, so it should carry the next
	// frame. Formula: cost(p) = bytesScheduled(p) / weight(p); pick
	// argmin(cost). Dead and Flapping paths excluded — same rationale
	// as in promotebestStandby: a flapping path's session is alive but
	// the whole point of the demote is to keep traffic OFF it for
	// flappingDemoteDur.
	//
	// The previous formula `weight - bytesScheduled/weight` inverted the
	// fair-share semantics — a high-weight path earned deficit 10× faster
	// per byte than a low-weight path, which is the opposite of "high
	// weight = bigger share."
	var best *Path
	var bestCost float64
	first := true
	for _, p := range m.paths {
		if p.State == PathDead || p.State == PathFlapping {
			continue
		}
		if p.weightCache <= 0 {
			p.weightCache = computePathWeight(p)
		}
		cost := float64(p.bytesScheduled) / p.weightCache
		if first || cost < bestCost {
			best = p
			bestCost = cost
			first = false
		}
	}
	if best == nil {
		return nil
	}
	best.bytesScheduled += int64(n)
	// Decay all counters periodically to keep deficits bounded — when
	// every path's bytesScheduled exceeds 1 MB, halve them all.
	if best.bytesScheduled > 1024*1024 {
		for _, p := range m.paths {
			p.bytesScheduled /= 2
		}
	}
	return best.Session
}

// computePathWeight derives a single quality score for weighted scheduling.
// Higher = better. Combines Quality (operator-supplied tier), RTT (lower
// is better), and Loss (lower is better). All terms positive; minimum 1.
func computePathWeight(p *Path) float64 {
	w := float64(p.Quality)
	if w <= 0 {
		w = 1
	}
	if p.RTT > 0 {
		// Penalise RTT: 50 ms baseline, halving weight for every 50 ms above.
		ratio := 50.0 / (float64(p.RTT.Milliseconds()) + 1)
		if ratio > 1 {
			ratio = 1
		}
		w *= ratio
	}
	w *= 1 - 0.8*p.Loss // 0% loss → unchanged; 100% loss → 0.2× weight
	if w < 1 {
		w = 1
	}
	return w
}

// AddPath registers a new transport path.
func (m *Manager) AddPath(session aether.Session, proto aether.Protocol, quality int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addPathLocked(session, proto, quality)
}

// addPathLocked is the lock-already-held variant of AddPath. Used by
// AddPathQA so the quality-aware bookkeeping can happen under the same
// lock as the legacy path insertion — eliminates the race window
// where a concurrent AddPath could insert a path between AddPathQA's
// unlock and relock, leaving its meta attached to the wrong Path.
// Audit M11.
func (m *Manager) addPathLocked(session aether.Session, proto aether.Protocol, quality int) *Path {
	// L4 #5: seed bytesScheduled at half the current live minimum so a
	// new path doesn't pin the WDRR scheduler at deficit=0 for the
	// first many sends. Without this, a freshly-added path WINS every
	// PickPath comparison (cost = 0/weight = 0) until it accumulates
	// enough bytes to match existing paths — turning every fresh
	// AddPath into a momentary "newcomer takes all" window.
	var seed int64
	if len(m.paths) > 0 {
		seed = m.paths[0].bytesScheduled
		for _, p := range m.paths {
			if p.bytesScheduled < seed {
				seed = p.bytesScheduled
			}
		}
		seed /= 2
	}

	now := time.Now()
	path := &Path{
		Session:        session,
		Protocol:       proto,
		State:          PathStandby,
		Quality:        quality,
		LastSuccess:    now,
		CreatedAt:      now,
		bytesScheduled: seed,
	}

	m.paths = append(m.paths, path)

	// If this is the first path or has better quality, make it primary
	if len(m.paths) == 1 || quality > m.paths[m.primary].Quality {
		m.setPrimary(len(m.paths) - 1)
	}

	dbgMultipath.Printf("Added path %s (quality=%d, state=%s)", proto, quality, path.State)
	return path
}

// RemovePath removes a transport path (session closed).
func (m *Manager) RemovePath(session aether.Session) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, p := range m.paths {
		if p.Session != session {
			continue
		}
		wasPrimary := i == m.primary
		m.paths = append(m.paths[:i], m.paths[i+1:]...)
		// L4 #6 fix: correctly adjust m.primary on removal. Previously
		// the code only handled "primary index ran off the end"
		// (m.primary >= len after splice → reset to 0, which silently
		// picked paths[0] not the best). Three cases now:
		//   - removed path was primary → promote best standby
		//   - removed path was BEFORE primary → decrement index so it
		//     still points at the same Path pointer post-shift
		//   - removed path was AFTER primary → no change
		switch {
		case wasPrimary:
			if len(m.paths) > 0 {
				m.promotebestStandby()
			} else {
				m.primary = 0
			}
		case i < m.primary:
			m.primary--
		}
		return
	}
}

// PrimarySession returns the current primary path's session.
func (m *Manager) PrimarySession() (aether.Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.paths) == 0 || m.primary >= len(m.paths) {
		return nil, false
	}
	return m.paths[m.primary].Session, true
}

// AllSessions returns all active+standby sessions (for redundant sending).
func (m *Manager) AllSessions() []aether.Session {
	m.mu.Lock()
	defer m.mu.Unlock()

	var sessions []aether.Session
	for _, p := range m.paths {
		if p.State == PathActive || p.State == PathStandby {
			sessions = append(sessions, p.Session)
		}
	}
	return sessions
}

// AllProtocolsRepresented returns the set of transport protocols
// represented in the manager — across active, standby, AND PathDead
// states (but excluding closed sessions). Used by EnsureK to decide
// which protocols still need a fresh dial.
//
// L4 #12 fix: previously EnsureK consulted AllSessions which excludes
// PathDead. A transiently dead path's protocol was missing from the
// "already represented" set, so EnsureK kept re-dialing the same
// broken transport — racing the still-extant Dead-state Path on the
// other side and producing fresh dedup races. Including Dead lets
// EnsureK pick a different protocol instead.
func (m *Manager) AllProtocolsRepresented() []aether.Protocol {
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := make(map[aether.Protocol]struct{}, len(m.paths))
	for _, p := range m.paths {
		if p.Session == nil || p.Session.IsClosed() {
			continue
		}
		seen[p.Protocol] = struct{}{}
	}
	out := make([]aether.Protocol, 0, len(seen))
	for proto := range seen {
		out = append(out, proto)
	}
	return out
}

// ShouldSendRedundant returns true if this frame should be sent on all paths
// (Level 2: REALTIME class redundancy).
func (m *Manager) ShouldSendRedundant(latencyClass aether.LatencyClass) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.redundantRealtime && latencyClass == aether.ClassREALTIME && len(m.paths) > 1
}

// OnPrimaryFailure handles primary path failure — instant failover to standby.
// Marks the failed path PathDead and stamps LastFailure so the probe loop
// (or opportunistic resurrection) can revive it after deadResurrectCooldown.
//
// Dead-on-arrival recovery: if every other path is also PathDead (a
// network blip can kill all transports simultaneously) promotebestStandby
// returns no winner and the primary index would remain pointing at the
// just-killed path. Dispatch then returns it forever from PrimarySession
// until something external triggers a re-probe. The recovery path here
// resurrects all dead standbys (skipping cooldown) and re-runs the
// promotion — at least one path can return to PathStandby and become
// the new primary. Was the H-Multipath-DeadPrimary finding.
func (m *Manager) OnPrimaryFailure() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.paths) <= 1 {
		return // no standby to failover to
	}

	old := m.paths[m.primary]
	old.State = PathDead
	old.LastFailure = time.Now()
	old.ConsecutiveFailures++

	dbgMultipath.Printf("Primary path %s failed, failing over", old.Protocol)
	if m.promotebestStandby() {
		return
	}
	// No live standby — force every Dead/Flapping path with a non-closed
	// session back to Standby (skip cooldown) so we can promote one of
	// them. A flapping path is unambiguously preferable to no primary at
	// all, so the demote tier yields here.
	dbgMultipath.Printf("All standbys also Dead/Flapping — forcing resurrect to break wedge")
	for _, p := range m.paths {
		if (p.State == PathDead || p.State == PathFlapping) && p.Session != nil && !p.Session.IsClosed() {
			p.State = PathStandby
			p.flappingUntil = time.Time{}
		}
	}
	m.promotebestStandby()
}

// resurrectExpiredDeadPathsLocked transitions PathDead paths back to
// PathStandby once they've cooled down past deadResurrectCooldown. Called
// from PickByQuality + PickPath (opportunistic, no extra goroutine) and
// from the probe loop. Caller must hold m.mu.
func (m *Manager) resurrectExpiredDeadPathsLocked() {
	now := time.Now()
	for _, p := range m.paths {
		if p.State != PathDead {
			continue
		}
		// Skip paths whose underlying session has actually closed —
		// resurrection only makes sense for transient failures.
		if p.Session == nil || p.Session.IsClosed() {
			continue
		}
		if !p.LastFailure.IsZero() && now.Sub(p.LastFailure) < deadResurrectCooldown {
			continue
		}
		p.State = PathStandby
		dbgMultipath.Printf("Path %s resurrected from Dead → Standby (cooldown elapsed)", p.Protocol)
	}
}

// resurrectExpiredFlappingPathsLocked transitions PathFlapping paths
// back to PathStandby once flappingDemoteDur has elapsed since the
// most recent qualifying tlpReset. Called from the same opportunistic-
// resurrection sites as resurrectExpiredDeadPathsLocked (PickPath,
// PickByQuality, probeNonPrimary) so the demote auto-recovers without
// a dedicated goroutine. Caller must hold m.mu.
func (m *Manager) resurrectExpiredFlappingPathsLocked() {
	now := m.now()
	for _, p := range m.paths {
		if p.State != PathFlapping {
			continue
		}
		if p.Session == nil || p.Session.IsClosed() {
			continue
		}
		if !p.flappingUntil.IsZero() && now.Before(p.flappingUntil) {
			continue
		}
		p.State = PathStandby
		p.flappingUntil = time.Time{}
		// Don't clear tlpResetEvents — the sliding window still
		// considers events from before the demote in case another
		// burst arrives. They'll naturally fall out of the window
		// when their age exceeds flappingWindowDur.
		dbgMultipath.Printf("Path %s recovered from Flapping → Standby (demote elapsed)", p.Protocol)
	}
}

// RunProbeLoop runs a goroutine that periodically pings non-primary
// paths to detect liveness recovery. Successful probes call
// OnProbeSuccess which transitions PathDead/PathProbing back to
// PathStandby and updates RTT. Failed probes leave the path's State
// alone (so a Dead path stays Dead, a Standby path stays Standby) but
// stamp LastFailure to defer the next probe.
//
// Exits when ctx is cancelled. Safe to call once per manager; calling
// multiple times spawns multiple loops (caller's responsibility).
//
// Cascade A.3 (L4 #2): before this, the manager had probeInterval +
// stabilityPeriod + maxFailures fields and OnProbeSuccess hook, but no
// code ever drove them. Standby paths could not be promoted; dead
// paths could not be resurrected. RunProbeLoop closes that gap.
func (m *Manager) RunProbeLoop(ctx context.Context) {
	interval := m.probeInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Also exit when the manager's Stop() is called — the qstate.stop
	// channel is closed by Stop(), so we listen on both. Without this
	// the probe loop would outlive the manager's qstate teardown and
	// could touch state that's already been GC'd.
	var stopCh <-chan struct{}
	m.mu.Lock()
	if m.qstate != nil {
		stopCh = m.qstate.stop
	}
	m.mu.Unlock()

	for {
		select {
		case <-ctx.Done():
			return
		case <-stopCh:
			return
		case <-ticker.C:
			m.probeNonPrimary(ctx)
		}
	}
}

// primaryProbeEvery is the modulus that determines how often probeNonPrimary
// ALSO probes the primary path. Tied to the global probe counter — every Nth
// probe tick includes the primary. 4 gives a primary-liveness check every
// ~2 minutes at the default 30s tick. Without primary probing, a silently
// wedged primary (cwnd-stuck, app reads block, no explicit error) was
// undetectable until external OnPrimaryFailure was called from dispatch
// (was H-Multipath-PrimaryProbe).
const primaryProbeEvery uint64 = 4

// probeNonPrimary pings every non-primary path (and the primary on every
// primaryProbeEvery-th invocation). Holds m.mu only to snapshot the path
// list — actual Ping calls happen outside the lock so a slow ping doesn't
// block dispatch.
func (m *Manager) probeNonPrimary(ctx context.Context) {
	m.mu.Lock()
	m.resurrectExpiredDeadPathsLocked()
	m.resurrectExpiredFlappingPathsLocked()
	m.probeTick++
	probePrimary := m.probeTick%primaryProbeEvery == 0
	type probeTarget struct {
		idx     int
		session aether.Session
		proto   aether.Protocol
	}
	targets := make([]probeTarget, 0, len(m.paths))
	for i, p := range m.paths {
		if p.Session == nil || p.Session.IsClosed() {
			continue
		}
		if i == m.primary && !probePrimary {
			continue
		}
		if p.State == PathDead {
			// Still cooling down — skip.
			continue
		}
		if p.State == PathFlapping {
			// Demoted — skip probes too so we don't accidentally
			// transition it back to Standby via OnProbeSuccess
			// before the demote-expiry timer elapses.
			continue
		}
		targets = append(targets, probeTarget{idx: i, session: p.Session, proto: p.Protocol})
	}
	m.mu.Unlock()

	for _, t := range targets {
		pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		rtt, err := t.session.Ping(pingCtx)
		cancel()
		if err == nil {
			m.OnProbeSuccess(t.session, rtt)
			continue
		}
		// Failed probe — stamp LastFailure but don't change state
		// (a standby path that's flaky stays standby; it'll be
		// re-probed next tick).
		m.mu.Lock()
		if t.idx < len(m.paths) && m.paths[t.idx].Session == t.session {
			m.paths[t.idx].LastProbe = time.Now()
			m.paths[t.idx].LastFailure = time.Now()
		}
		m.mu.Unlock()
	}
}

// OnProbeSuccess records a successful probe on a standby path.
func (m *Manager) OnProbeSuccess(session aether.Session, rtt time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, p := range m.paths {
		if p.Session == session {
			p.RTT = rtt
			p.LastSuccess = time.Now()
			p.ConsecutiveFailures = 0
			if p.State == PathDead || p.State == PathProbing {
				p.State = PathStandby
			}
			break
		}
	}
}

// PathCount returns the number of registered paths.
func (m *Manager) PathCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.paths)
}

// PathFlappingCount returns the number of paths currently in the
// PathFlapping demote tier. Library surfaces this through
// aether_path_flapping_total so operators can correlate the
// bimodal-latency tail against the demote rate. Cheap; safe to call
// from monitoring goroutines.
//
// Side-effect: runs resurrectExpiredFlappingPathsLocked first so the
// returned count reflects the post-recovery state — callers polling
// this every Nseconds will see paths return to zero promptly without
// needing a separate tick.
func (m *Manager) PathFlappingCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resurrectExpiredFlappingPathsLocked()
	n := 0
	for _, p := range m.paths {
		if p.State == PathFlapping {
			n++
		}
	}
	return n
}

// setPrimary makes path at index i the active primary.
func (m *Manager) setPrimary(i int) {
	if i >= len(m.paths) {
		return
	}
	// Demote old primary to standby — but PRESERVE PathFlapping and
	// PathDead. RecordTLPReset / OnPrimaryFailure both mark the old
	// primary's state BEFORE calling promotebestStandby → setPrimary,
	// and the new primary election must not silently un-mark that
	// state (otherwise promotebestStandby would immediately re-elect
	// the just-demoted path on its next call).
	if m.primary < len(m.paths) {
		old := m.paths[m.primary]
		if old.State != PathFlapping && old.State != PathDead {
			old.State = PathStandby
		}
	}
	m.primary = i
	m.paths[i].State = PathActive
	// L4 #9: reset the new primary's bytesScheduled to the cohort minimum
	// so it gets fair WDRR scheduling from the moment of promotion
	// rather than ranking below its true quality due to the long quiet
	// standby window. Tracker-level throughput EMA recovers naturally
	// once UpdateThroughput starts firing again.
	if len(m.paths) > 1 {
		minSched := m.paths[0].bytesScheduled
		for _, p := range m.paths {
			if p.bytesScheduled < minSched {
				minSched = p.bytesScheduled
			}
		}
		m.paths[i].bytesScheduled = minSched
	}
	dbgMultipath.Printf("Primary path: %s (quality=%d)", m.paths[i].Protocol, m.paths[i].Quality)
}

// promotebestStandby finds the best non-dead, non-flapping path and
// makes it primary. Returns true on success, false when no live
// standby exists (caller can react by resurrecting Dead paths — see
// OnPrimaryFailure).
//
// PathFlapping is excluded the same way PathDead is, but for a
// different reason: a flapping path's session is still alive (its
// Ping succeeded during the false-positive recovery) so it would
// otherwise look like a perfectly good promotion candidate. The
// whole point of the PathFlapping tier is to keep dispatch away from
// it for flappingDemoteDur so a steadier transport (WS, TCP) carries
// traffic while the noise-UDP path settles.
func (m *Manager) promotebestStandby() bool {
	bestIdx := -1
	bestQuality := -1
	for i, p := range m.paths {
		if p.State == PathDead || p.State == PathFlapping {
			continue
		}
		if p.Quality > bestQuality {
			bestIdx = i
			bestQuality = p.Quality
		}
	}
	if bestIdx >= 0 {
		m.setPrimary(bestIdx)
		return true
	}
	return false
}

// RecordTLPReset is invoked by the noise adapter (via the higher-level
// connection manager that owns this multipath Manager) every time
// STALL-DETECT fires its false-positive recovery path on a session
// owned by this Manager. The path identified by `session` accumulates
// the event in a sliding flappingWindowDur (5-minute) window; once
// flappingResetThreshold (3) events have landed in the window, the
// path is demoted to PathFlapping for flappingDemoteDur (60 s) —
// promotebestStandby skips it during the demote so a steadier
// transport carries traffic. After flappingDemoteDur with no further
// hits, the path reverts to PathStandby (cheapest re-entry state;
// setPrimary / WDRR will re-elect it on its next round if its quality
// justifies the role).
//
// Callers that don't track a multipath.Manager (single-path peers,
// tests that don't exercise the demote tier) can safely never call
// this — Manager behaves exactly as before.
//
// Returns true when the call moved the path INTO PathFlapping (so the
// caller can log / surface the demote event); false on every other
// outcome (path not found, hit recorded but threshold not yet
// crossed, path already in PathFlapping).
func (m *Manager) RecordTLPReset(session aether.Session) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	var target *Path
	for _, p := range m.paths {
		if p.Session == session {
			target = p
			break
		}
	}
	if target == nil {
		return false
	}
	now := m.now()

	// Sliding-window ring insert. The ring is sized to exactly
	// flappingResetThreshold so a full ring of in-window timestamps
	// IS the threshold-crossed condition. Re-scan the ring on every
	// insert to count in-window hits — the ring is small (3
	// entries) so the scan is cheap and we don't need a separate
	// decay tick.
	target.tlpResetEvents[target.tlpResetIdx] = now
	target.tlpResetIdx = (target.tlpResetIdx + 1) % len(target.tlpResetEvents)

	if target.State == PathFlapping {
		// Already demoted — extend the recovery deadline so a
		// sustained burst of resets keeps the path demoted for the
		// FULL flappingDemoteDur past the LAST event, not the
		// first one. Without this, a slow drip of resets at, say,
		// 50 s intervals would let the path recover between hits
		// even though it's still misbehaving.
		target.flappingUntil = now.Add(flappingDemoteDur)
		return false
	}

	cutoff := now.Add(-flappingWindowDur)
	hits := 0
	for _, t := range target.tlpResetEvents {
		if !t.IsZero() && !t.Before(cutoff) {
			hits++
		}
	}
	if hits < flappingResetThreshold {
		return false
	}

	// AER-017: never demote a SOLE usable path to Flapping. PickByQuality and
	// AllSessions exclude flapping paths, so demoting the only one leaves them
	// returning nothing for the whole demote window — consumers see "no session
	// to peer" while a perfectly usable session exists and self-inflict a ~60s
	// outage (and the demote events here can be manufactured by healthy
	// idle-resume traffic, AER-002). A flapping-but-only path beats none.
	hasAlt := false
	for _, p := range m.paths {
		if p != target && p.State != PathDead && p.State != PathFlapping {
			hasAlt = true
			break
		}
	}
	if !hasAlt {
		dbgMultipath.Printf("Path %s hit the flapping threshold but is the only usable path — not demoting",
			target.Protocol)
		return false
	}

	// Threshold crossed — demote.
	wasPrimary := false
	for i, p := range m.paths {
		if p == target && i == m.primary {
			wasPrimary = true
			break
		}
	}
	target.State = PathFlapping
	target.flappingUntil = now.Add(flappingDemoteDur)
	dbgMultipath.Printf("Path %s demoted to Flapping (hits=%d in %v, demoteUntil=%v)",
		target.Protocol, hits, flappingWindowDur, target.flappingUntil)
	if wasPrimary && len(m.paths) > 1 {
		// Hand traffic to whichever non-flapping, non-dead standby
		// ranks best — exactly what OnPrimaryFailure would do, minus
		// the PathDead bookkeeping (the flapping path's session is
		// alive, just being shunned).
		m.promotebestStandby()
	}
	return true
}
