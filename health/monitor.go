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
)

// Monitor tracks the health state of a single transport session.
// Thread-safe: all fields protected by mu.
// Composable: embed in any session struct to get health tracking.
type Monitor struct {
	mu             sync.RWMutex
	lastActivity   time.Time
	lastPingSent   time.Time
	lastPongRecv   time.Time
	missedPings    int
	pendingPingSeq uint32
	lastRTT        time.Duration
	avgRTT         time.Duration
	emaAlpha       float64 // smoothing factor for RTT EMA (default 0.2)
	closed         int32   // atomic: 1 = closed
}

// NewMonitor creates a health monitor with the given EMA smoothing factor.
// emaAlpha controls how much weight new RTT samples get (0.2 = 20% new, 80% old).
func NewMonitor(emaAlpha float64) *Monitor {
	if emaAlpha <= 0 || emaAlpha > 1 {
		emaAlpha = 0.2
	}
	now := time.Now()
	return &Monitor{
		lastActivity: now,
		lastPongRecv: now,
		emaAlpha:     emaAlpha,
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

// RecordPongRecv records that a pong was received, computes RTT, updates EMA.
// The seq parameter is the sequence number echoed back in the pong payload.
// sentAt is the time the corresponding ping was sent (use PingSentAt() if the
// caller doesn't track it separately). RTT is only updated when seq matches
// the pending ping sequence.
func (m *Monitor) RecordPongRecv(seq uint32, sentAt time.Time) {
	m.mu.Lock()
	now := time.Now()
	// Only update RTT if this pong matches the pending ping
	if seq != 0 && seq == m.pendingPingSeq {
		rtt := now.Sub(sentAt)
		m.lastRTT = rtt
		if m.avgRTT == 0 {
			m.avgRTT = rtt
		} else {
			alpha := m.emaAlpha
			m.avgRTT = time.Duration(float64(m.avgRTT)*(1-alpha) + float64(rtt)*alpha)
		}
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

// RTT returns the last measured and EMA-smoothed round-trip times.
func (m *Monitor) RTT() (last, avg time.Duration) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastRTT, m.avgRTT
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

// AvgRTT returns the EMA-smoothed RTT.
func (m *Monitor) AvgRTT() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.avgRTT
}

// MarkClosed marks the monitor as closed. Called by the owning session on Close().
func (m *Monitor) MarkClosed() {
	atomic.StoreInt32(&m.closed, 1)
}

// IsClosed returns true if the monitor has been marked as closed.
func (m *Monitor) IsClosed() bool {
	return atomic.LoadInt32(&m.closed) == 1
}
