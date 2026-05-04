/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 *
 * HealthMonitor tracks per-session health metrics: activity timestamps,
 * ping/pong RTT, missed pings, and EMA-smoothed latency. Extracted from
 * noiseConn to be reusable by any transport protocol (QUIC, WebSocket, gRPC).
 */
package health

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/ORBTR/aether/rtt"
)

// Monitor tracks the health state of a single transport session.
// Thread-safe: all fields protected by mu (and an embedded RTT
// estimator that has its own internal mutex).
// Composable: embed in any session struct to get health tracking.
//
// RTT tracking is delegated to rtt.Estimator (RFC 6298 SRTT/RTTVar/RTO,
// shared with the per-stream reliability layer). Monitor feeds it samples
// from ping/pong cycles via RecordPongRecv. The estimator surfaces
// SRTT, RTTVar, and RTO — the latter is the canonical "how long should
// we wait before declaring a missing reply lost?" value used by the
// keepalive subsystem to size its per-ping deadline.
type Monitor struct {
	mu             sync.RWMutex
	lastActivity   time.Time
	lastPingSent   time.Time
	lastPongRecv   time.Time
	missedPings    int
	pendingPingSeq uint32
	lastRTT        time.Duration
	rttEst         *rtt.Estimator // SRTT/RTTVar/RTO over ping-RTT samples
	closed         int32          // atomic: 1 = closed
}

// NewMonitor creates a health monitor with the given EMA smoothing
// factor. emaAlpha controls how much weight new RTT samples get
// (0.2 = 20% new, 80% old). Pass 0 to use the RFC 6298 default
// (α = 0.125). Outside (0, 1] also falls back to the RFC default.
func NewMonitor(emaAlpha float64) *Monitor {
	estOpts := rtt.Options{}
	if emaAlpha > 0 && emaAlpha <= 1 {
		estOpts.Alpha = emaAlpha
	}
	now := time.Now()
	return &Monitor{
		lastActivity: now,
		lastPongRecv: now,
		rttEst:       rtt.New(estOpts),
	}
}

// RecordActivity updates the last-received timestamp. Called on every inbound packet.
func (m *Monitor) RecordActivity() {
	m.mu.Lock()
	m.lastActivity = time.Now()
	m.mu.Unlock()
}

// RecordPingSent records that a ping was sent with the given sequence number.
func (m *Monitor) RecordPingSent(seq uint32) {
	m.mu.Lock()
	m.lastPingSent = time.Now()
	m.pendingPingSeq = seq
	m.mu.Unlock()
}

// RecordPongRecv records that a pong was received and feeds the RTT
// sample to the underlying rtt.Estimator (RFC 6298 SRTT/RTTVar/RTO).
// The seq parameter is the sequence number echoed back in the pong
// payload. sentAt is the time the corresponding ping was sent (use
// PingSentAt() if the caller doesn't track it separately). RTT
// samples are only consumed when seq matches the pending ping
// sequence.
func (m *Monitor) RecordPongRecv(seq uint32, sentAt time.Time) {
	m.mu.Lock()
	now := time.Now()
	// Only update RTT if this pong matches the pending ping
	if seq != 0 && seq == m.pendingPingSeq {
		sample := now.Sub(sentAt)
		m.lastRTT = sample
		// Delegate the RFC 6298 math to the shared estimator. Its
		// Update is internally locked, so calling under m.mu is
		// safe.
		m.rttEst.Update(sample)
	}
	m.lastPongRecv = now
	m.missedPings = 0
	m.pendingPingSeq = 0
	m.mu.Unlock()
}

// PingSentAt returns when the last ping was sent. Used by callers to pass
// sentAt to RecordPongRecv when they don't track ping timestamps separately.
func (m *Monitor) PingSentAt() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastPingSent
}

// IncrementMissedPings increments the missed ping counter and returns the new count.
func (m *Monitor) IncrementMissedPings() int {
	m.mu.Lock()
	m.missedPings++
	n := m.missedPings
	m.mu.Unlock()
	return n
}

// --- Read-only accessors (implement aether.HealthReporter) ---

// LastActivity returns when the last packet was received.
func (m *Monitor) LastActivity() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastActivity
}

// RTT returns the last measured RTT sample and the SRTT (smoothed
// EMA-style mean per RFC 6298). Backwards-compatible signature; "avg"
// is sourced from the underlying rtt.Estimator's SRTT.
func (m *Monitor) RTT() (last, avg time.Duration) {
	m.mu.RLock()
	last = m.lastRTT
	m.mu.RUnlock()
	return last, m.rttEst.SRTT()
}

// IsAlive returns true if the session has received data within the timeout.
func (m *Monitor) IsAlive(timeout time.Duration) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return time.Since(m.lastActivity) < timeout
}

// MissedPings returns the consecutive missed ping count.
func (m *Monitor) MissedPings() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.missedPings
}

// LastPongReceived returns when the last pong was received.
func (m *Monitor) LastPongReceived() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastPongRecv
}

// AvgRTT returns the SRTT (RFC 6298 smoothed mean of ping RTT samples).
// Backwards-compatible name; identical to SRTT().
func (m *Monitor) AvgRTT() time.Duration { return m.rttEst.SRTT() }

// SRTT returns the smoothed round-trip time (RFC 6298). Equivalent to
// AvgRTT — provided for naming parity with rtt.Estimator and the
// reliability layer.
func (m *Monitor) SRTT() time.Duration { return m.rttEst.SRTT() }

// RTTVar returns the smoothed RTT mean deviation (RFC 6298) over the
// ping/pong sample stream. Zero before the first pong.
func (m *Monitor) RTTVar() time.Duration { return m.rttEst.RTTVar() }

// RTO returns the canonical Probe Timeout for this session
// (SRTT + max(G, 4*RTTVar), clamped to the estimator's [MinRTO, MaxRTO]).
// Used by the keepalive subsystem to size its per-ping deadline:
// short on stable low-latency paths, long on bursty or high-RTT paths.
func (m *Monitor) RTO() time.Duration { return m.rttEst.RTO() }

// MarkClosed marks the monitor as closed. Called by the owning session on Close().
func (m *Monitor) MarkClosed() {
	atomic.StoreInt32(&m.closed, 1)
}

// IsClosed returns true if the monitor has been marked as closed.
func (m *Monitor) IsClosed() bool {
	return atomic.LoadInt32(&m.closed) == 1
}
