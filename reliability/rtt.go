/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

// Package reliability implements per-stream reliability for the Aether wire protocol.
// Used by transports that lack native reliability (Noise-UDP).
// Transports with native reliability (QUIC, TCP, WS) skip this layer entirely.
package reliability

import (
	"sync"
	"time"
)

// RTTEstimator implements the Jacobson/Karels algorithm (RFC 6298) for
// smoothed RTT estimation and retransmission timeout (RTO) computation.
//
// The estimator tracks:
//   - SRTT: smoothed round-trip time (exponentially weighted average)
//   - RTTVAR: RTT variance (for jitter detection)
//   - RTO: retransmission timeout (SRTT + 4*RTTVAR, clamped to [minRTO, maxRTO])
type RTTEstimator struct {
	mu          sync.Mutex
	srtt        time.Duration // smoothed RTT
	rttvar      time.Duration // RTT variance
	rto         time.Duration // retransmission timeout
	alpha       float64       // SRTT smoothing factor (default: 0.125)
	beta        float64       // RTTVAR smoothing factor (default: 0.25)
	minRTO      time.Duration // minimum RTO (default: 200ms)
	maxRTO      time.Duration // maximum RTO (default: 60s)
	granularity time.Duration // clock granularity (default: 1ms)
	initialized bool          // false until first sample
}

// NewRTTEstimator creates an estimator with RFC 6298 default parameters.
func NewRTTEstimator() *RTTEstimator {
	return &RTTEstimator{
		alpha:       0.125,
		beta:        0.25,
		minRTO:      200 * time.Millisecond,
		maxRTO:      60 * time.Second,
		granularity: time.Millisecond,
		rto:         time.Second, // initial RTO before first sample
	}
}

// newRTTEstimatorWithParams creates an estimator with custom parameters.
func newRTTEstimatorWithParams(minRTO, maxRTO time.Duration) *RTTEstimator {
	e := NewRTTEstimator()
	e.minRTO = minRTO
	e.maxRTO = maxRTO
	return e
}

// Update records a new RTT sample and recalculates SRTT, RTTVAR, and RTO.
// The sample should be the measured round-trip time for a single frame's ACK.
// Retransmitted frames should NOT generate RTT samples (Karn's algorithm).
func (e *RTTEstimator) Update(sample time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.initialized {
		// First sample: RFC 6298 Section 2.2
		e.srtt = sample
		e.rttvar = sample / 2
		e.initialized = true
	} else {
		// Subsequent samples: RFC 6298 Section 2.3
		// RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R|
		diff := e.srtt - sample
		if diff < 0 {
			diff = -diff
		}
		e.rttvar = time.Duration(float64(e.rttvar)*(1-e.beta) + float64(diff)*e.beta)

		// SRTT = (1 - alpha) * SRTT + alpha * R
		e.srtt = time.Duration(float64(e.srtt)*(1-e.alpha) + float64(sample)*e.alpha)
	}

	// RTO = SRTT + max(G, 4 * RTTVAR)
	k := 4 * e.rttvar
	if k < e.granularity {
		k = e.granularity
	}
	e.rto = e.srtt + k

	// Clamp RTO
	if e.rto < e.minRTO {
		e.rto = e.minRTO
	}
	if e.rto > e.maxRTO {
		e.rto = e.maxRTO
	}
}

// UpdateWithDelay records an RTT sample with ACK processing delay subtracted.
// rawRTT is the measured wall-clock round-trip. ackDelay is the time the
// receiver held the ACK before sending (from CompositeACK.AckDelay × 8µs).
// The adjusted sample is max(rawRTT - ackDelay, 1µs) to prevent negative RTT.
// Follows QUIC RFC 9002 Section 5.3 approach.
func (e *RTTEstimator) UpdateWithDelay(rawRTT time.Duration, ackDelay time.Duration) {
	adjusted := rawRTT - ackDelay
	if adjusted < time.Microsecond {
		adjusted = time.Microsecond
	}
	e.Update(adjusted)
}

// RTO returns the current retransmission timeout.
func (e *RTTEstimator) RTO() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.rto
}

// SRTT returns the smoothed round-trip time.
func (e *RTTEstimator) SRTT() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.srtt
}

// rttVar returns the RTT variance.
func (e *RTTEstimator) rttVar() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.rttvar
}

// BackoffRTO doubles the current RTO (exponential backoff on retransmit timeout).
// Called when a retransmission timer fires without an ACK.
// RFC 6298 Section 5.5: "double the RTO value".
func (e *RTTEstimator) BackoffRTO() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rto *= 2
	if e.rto > e.maxRTO {
		e.rto = e.maxRTO
	}
	return e.rto
}

// isInitialized returns true if at least one RTT sample has been recorded.
func (e *RTTEstimator) isInitialized() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.initialized
}
