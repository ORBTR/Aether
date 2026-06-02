/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

// Package reliability implements per-stream reliability for the Aether wire protocol.
// Used by transports that lack native reliability (Noise-UDP).
// Transports with native reliability (QUIC, TCP, WS) skip this layer entirely.
package reliability

import (
	"time"

	"github.com/ORBTR/aether/rtt"
)

// RTTEstimator implements RFC 6298 SRTT/RTTVar/RTO computation for a
// single per-stream sample stream (data ACKs).
//
// Thin wrapper over rtt.Estimator — the canonical implementation lives
// in github.com/ORBTR/aether/rtt and is shared with health.Monitor
// (control-plane keepalive RTT). This wrapper is preserved at the same
// API surface so existing reliability callers (RetransmitQueue, RACK,
// per-stream state machine) keep compiling unchanged.
//
// Tracks:
//   - SRTT: smoothed round-trip time (exponentially weighted average)
//   - RTTVAR: RTT variance (mean deviation, for jitter detection)
//   - RTO: retransmission timeout (SRTT + 4*RTTVAR, clamped to [minRTO, maxRTO])
type RTTEstimator struct {
	e *rtt.Estimator
}

// NewRTTEstimator creates an estimator with RFC 6298 default parameters
// suitable for per-stream data ACK RTT measurement.
func NewRTTEstimator() *RTTEstimator {
	return &RTTEstimator{e: rtt.NewDefault()}
}

// newRTTEstimatorWithParams creates an estimator with custom MinRTO/
// MaxRTO bounds. Other parameters default. Used by tests.
func newRTTEstimatorWithParams(minRTO, maxRTO time.Duration) *RTTEstimator {
	return &RTTEstimator{e: rtt.New(rtt.Options{MinRTO: minRTO, MaxRTO: maxRTO})}
}

// Update records a new RTT sample and recalculates SRTT, RTTVAR, and RTO.
// The sample should be the measured round-trip time for a single frame's ACK.
// Retransmitted frames should NOT generate RTT samples (Karn's algorithm).
func (e *RTTEstimator) Update(sample time.Duration) { e.e.Update(sample) }

// UpdateWithDelay records an RTT sample with ACK processing delay subtracted.
// rawRTT is the measured wall-clock round-trip. ackDelay is the time the
// receiver held the ACK before sending (from CompositeACK.AckDelay × 8µs).
// The adjusted sample is max(rawRTT - ackDelay, 1µs) to prevent negative RTT.
// Follows QUIC RFC 9002 Section 5.3 approach.
func (e *RTTEstimator) UpdateWithDelay(rawRTT time.Duration, ackDelay time.Duration) {
	e.e.UpdateWithDelay(rawRTT, ackDelay)
}

// RTO returns the current retransmission timeout.
func (e *RTTEstimator) RTO() time.Duration { return e.e.RTO() }

// SRTT returns the smoothed round-trip time.
func (e *RTTEstimator) SRTT() time.Duration { return e.e.SRTT() }

// rttVar returns the RTT variance. Package-private — exposed via
// RTTVar() in the new API; kept lowercase for backwards compatibility
// with existing reliability tests that consult this value.
func (e *RTTEstimator) rttVar() time.Duration { return e.e.RTTVar() }

// RTTVar returns the smoothed RTT mean deviation (RFC 6298). Public
// counterpart to rttVar() — preferred for new callers.
func (e *RTTEstimator) RTTVar() time.Duration { return e.e.RTTVar() }

// BackoffRTO doubles the current RTO (exponential backoff on retransmit timeout).
// Called when a retransmission timer fires without an ACK.
// RFC 6298 Section 5.5: "double the RTO value".
func (e *RTTEstimator) BackoffRTO() time.Duration { return e.e.BackoffRTO() }

// isInitialized returns true if at least one RTT sample has been
// recorded. Package-private; used by reliability internals.
func (e *RTTEstimator) isInitialized() bool { return e.e.IsInitialized() }

// IsInitialized is the public counterpart to isInitialized() — added
// for parity with the new API.
func (e *RTTEstimator) IsInitialized() bool { return e.e.IsInitialized() }

// Percentile returns the p-th percentile RTT from the underlying
// estimator's ring-buffer histogram. See rtt.Estimator.Percentile.
func (e *RTTEstimator) Percentile(p int) time.Duration { return e.e.Percentile(p) }

// PercentileSnapshot returns (p50, p95, p99) RTT from the histogram
// in one ring-buffer copy + sort pass. See rtt.Estimator.PercentileSnapshot.
func (e *RTTEstimator) PercentileSnapshot() (p50, p95, p99 time.Duration) {
	return e.e.PercentileSnapshot()
}
