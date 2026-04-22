//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
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
	"sync"
	"time"

	"github.com/ORBTR/aether"
)

// PathState tracks the health state of a single transport path.
type PathState int

const (
	PathActive  PathState = iota // primary path, carrying all traffic
	PathStandby                   // backup path, periodic probes only
	PathProbing                   // checking if standby is still alive
	PathDead                      // failed probes, not usable
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
	default:
		return "unknown"
	}
}

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

	// Level 3 weighted scheduling counters. weight is derived from
	// Quality + RTT + loss; bytesScheduled is what we've sent on this
	// path in the current round. The scheduler picks the path with
	// the largest weight*round - bytesScheduled deficit.
	Loss          float64 // 0.0 (no loss) → 1.0 (total loss)
	weightCache   float64
	bytesScheduled int64
}

// Manager manages multiple paths to a single peer.
type Manager struct {
	mu    sync.Mutex
	paths []*Path
	primary int // index of active path

	// Configuration
	probeInterval    time.Duration
	stabilityPeriod  time.Duration
	maxFailures      int

	// Redundancy level
	redundantRealtime bool // Level 2: send REALTIME on both paths
	weightedLB        bool // Level 3: weighted load balance across paths
}

// NewManager creates a multipath manager.
func NewManager() *Manager {
	return &Manager{
		probeInterval:   30 * time.Second,
		stabilityPeriod: 60 * time.Second,
		maxFailures:     3,
	}
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
	// argmin(cost). Dead paths excluded.
	//
	// The previous formula `weight - bytesScheduled/weight` inverted the
	// fair-share semantics — a high-weight path earned deficit 10× faster
	// per byte than a low-weight path, which is the opposite of "high
	// weight = bigger share."
	var best *Path
	var bestCost float64
	first := true
	for _, p := range m.paths {
		if p.State == PathDead {
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

	path := &Path{
		Session:  session,
		Protocol: proto,
		State:    PathStandby,
		Quality:  quality,
		LastSuccess: time.Now(),
	}

	m.paths = append(m.paths, path)

	// If this is the first path or has better quality, make it primary
	if len(m.paths) == 1 || quality > m.paths[m.primary].Quality {
		m.setPrimary(len(m.paths) - 1)
	}

	dbgMultipath.Printf("Added path %s (quality=%d, state=%s)", proto, quality, path.State)
}

// RemovePath removes a transport path (session closed).
func (m *Manager) RemovePath(session aether.Session) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, p := range m.paths {
		if p.Session == session {
			m.paths = append(m.paths[:i], m.paths[i+1:]...)
			if m.primary >= len(m.paths) {
				m.primary = 0
			}
			// If removed path was primary, promote best standby
			if i == m.primary && len(m.paths) > 0 {
				m.promotebestStandby()
			}
			break
		}
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

// ShouldSendRedundant returns true if this frame should be sent on all paths
// (Level 2: REALTIME class redundancy).
func (m *Manager) ShouldSendRedundant(latencyClass aether.LatencyClass) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.redundantRealtime && latencyClass == aether.ClassREALTIME && len(m.paths) > 1
}

// OnPrimaryFailure handles primary path failure — instant failover to standby.
func (m *Manager) OnPrimaryFailure() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.paths) <= 1 {
		return // no standby to failover to
	}

	old := m.paths[m.primary]
	old.State = PathDead
	old.ConsecutiveFailures++

	dbgMultipath.Printf("Primary path %s failed, failing over", old.Protocol)
	m.promotebestStandby()
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

// setPrimary makes path at index i the active primary.
func (m *Manager) setPrimary(i int) {
	if i >= len(m.paths) {
		return
	}
	// Demote old primary to standby
	if m.primary < len(m.paths) {
		m.paths[m.primary].State = PathStandby
	}
	m.primary = i
	m.paths[i].State = PathActive
	dbgMultipath.Printf("Primary path: %s (quality=%d)", m.paths[i].Protocol, m.paths[i].Quality)
}

// promotebestStandby finds the best non-dead path and makes it primary.
func (m *Manager) promotebestStandby() {
	bestIdx := -1
	bestQuality := -1
	for i, p := range m.paths {
		if p.State != PathDead && p.Quality > bestQuality {
			bestIdx = i
			bestQuality = p.Quality
		}
	}
	if bestIdx >= 0 {
		m.setPrimary(bestIdx)
	}
}
