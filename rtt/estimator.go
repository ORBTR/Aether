/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

// Package rtt implements the Jacobson/Karels RTT estimator (RFC 6298)
// shared across the Aether stack.
//
// Two subsystems sample round-trip time on every session, against the
// same algorithm but for different purposes:
//
//   - control plane: ping/pong on stream 2 (consumed by the keepalive
//     subsystem to size its per-ping timeout)
//   - data plane: per-stream ACK→data RTT (consumed by RACK loss
//     detection and the per-stream retransmission timer)
//
// Each consumer instantiates its own *Estimator over its own sample
// stream — pings and data ACKs can diverge significantly under load
// (pings are control-priority; data RTT is queued behind congestion
// control). Sharing the math (this package) without sharing the sample
// state preserves both signals while avoiding two copies of RFC 6298.
//
// Replaces the prior in-place implementations in
// reliability.RTTEstimator and the inline EMA in health.Monitor.
// Capabilities preserved from both:
//
//   - Reliability:  MinRTO/MaxRTO bounds, BackoffRTO (RFC 6298 §5.5),
//                   ack-delay-adjusted samples (UpdateWithDelay,
//                   QUIC RFC 9002 §5.3), Karn's-algorithm-friendly
//                   single-sample API (caller decides which samples
//                   to feed it — retransmitted frames omitted).
//   - Health:       configurable smoothing alpha for SRTT EMA, lastRTT
//                   accessor for diagnostic readout.
package rtt

import (
	"sync"
	"time"
)

// Default parameters per RFC 6298. Callers needing different bounds
// (e.g. health.Monitor with looser min/max for ping-RTT vs. data-ACK
// RTT) supply Options to New.
const (
	// DefaultAlpha is the SRTT smoothing factor. RFC 6298 §2.3 specifies
	// α = 1/8 = 0.125 for new-sample weight. Existing code in
	// health.Monitor used 0.2 historically; we standardise on the RFC
	// value here since it produces lower variance in steady state.
	DefaultAlpha = 0.125

	// DefaultBeta is the RTTVar smoothing factor. RFC 6298 §2.3 specifies
	// β = 1/4 = 0.25 for new-sample weight on the deviation EMA.
	DefaultBeta = 0.25

	// DefaultMinRTO is the lower bound on RTO. RFC 6298 §2.4 mandates
	// SHOULD ≥ 1s for TCP — Aether uses 200ms because we run on much
	// lower-latency intra-DC paths and a 1s floor would mask real
	// retransmit-needed conditions on noise-UDP same-region.
	DefaultMinRTO = 200 * time.Millisecond

	// DefaultMaxRTO is the upper bound on RTO. RFC 6298 §2.5 mandates
	// SHOULD ≥ 60s — we use exactly 60s to bound exponential backoff.
	DefaultMaxRTO = 60 * time.Second

	// DefaultGranularity is the clock granularity G in the RTO formula
	// RTO = SRTT + max(G, K*RTTVar). 1ms matches Linux's HZ=1000
	// scheduler tick — finer than this is meaningless on most hosts.
	DefaultGranularity = time.Millisecond

	// rfcK is the multiplier on RTTVar in the RTO formula. RFC 6298
	// §2.3 specifies K = 4. Not configurable — there is no scenario
	// where deviating from K=4 produces better behaviour.
	rfcK = 4
)

// Options configures an Estimator. All fields are optional; zero values
// fall back to the package defaults defined above.
type Options struct {
	// Alpha is the SRTT smoothing factor (new-sample weight on SRTT EMA).
	// Range (0, 1]. Defaults to DefaultAlpha (RFC 6298 = 0.125).
	Alpha float64

	// Beta is the RTTVar smoothing factor (new-sample weight on RTTVar
	// EMA). Range (0, 1]. Defaults to DefaultBeta (RFC 6298 = 0.25).
	Beta float64

	// MinRTO clamps RTO from below — useful to prevent the estimator
	// from declaring loss prematurely on extremely-low-RTT paths
	// (loopback, same-host) where a single scheduler hiccup is larger
	// than 4*RTTVar. Defaults to DefaultMinRTO.
	MinRTO time.Duration

	// MaxRTO clamps RTO from above. Bounds exponential backoff so a
	// black-holed path doesn't accumulate infinite-second timeouts.
	// Defaults to DefaultMaxRTO.
	MaxRTO time.Duration

	// Granularity is the clock granularity used in the RTO formula's
	// max(G, K*RTTVar) term. Lower bound for RTO contribution from
	// jitter even when RTTVar collapses to zero on extremely-stable
	// paths. Defaults to DefaultGranularity.
	Granularity time.Duration

	// InitialRTO is the RTO returned before any sample has been seen.
	// Used by callers that need a non-zero starting timeout. Defaults
	// to 1s.
	InitialRTO time.Duration
}

// withDefaults applies package defaults to any zero fields in opts.
func (o Options) withDefaults() Options {
	if o.Alpha <= 0 || o.Alpha > 1 {
		o.Alpha = DefaultAlpha
	}
	if o.Beta <= 0 || o.Beta > 1 {
		o.Beta = DefaultBeta
	}
	if o.MinRTO <= 0 {
		o.MinRTO = DefaultMinRTO
	}
	if o.MaxRTO <= 0 {
		o.MaxRTO = DefaultMaxRTO
	}
	if o.Granularity <= 0 {
		o.Granularity = DefaultGranularity
	}
	if o.InitialRTO <= 0 {
		o.InitialRTO = time.Second
	}
	return o
}

// Estimator computes SRTT, RTTVar, RTO, MinRTT, and PTO from a stream
// of RTT samples per RFC 6298 (Jacobson/Karels) plus the RFC 9002
// extensions (QUIC). All public methods are safe for concurrent use;
// reads share a single mutex with writes since RTT samples typically
// arrive at < 1 kHz and contention is negligible.
//
// One Estimator per logical RTT signal:
//   - keepalive ping/pong → one Estimator on health.Monitor
//   - per-stream data ACKs → one Estimator on each noiseStream
//
// Beyond the core RFC 6298 outputs, the estimator also tracks:
//   - MinRTT (smallest observed sample, per RFC 9002 §5.2)
//   - LastSampleAt (wall clock of the most recent sample, for caller
//     freshness checks)
//
// Plus computes on demand:
//   - PTO with peer-advertised max_ack_delay (RFC 9002 §6.2)
type Estimator struct {
	mu           sync.Mutex
	opts         Options
	srtt         time.Duration
	rttVar       time.Duration
	rto          time.Duration
	lastSample   time.Duration
	minRTT       time.Duration // smallest observed sample (RFC 9002 §5.2)
	lastSampleAt time.Time     // wall clock of most recent Update
	sampleCount  uint64        // total successful Update calls
	initialized  bool
}

// New constructs an Estimator with the given Options. Zero-valued
// Options fields fall back to package defaults — callers that want
// pure-RFC behaviour can pass Options{}.
func New(opts Options) *Estimator {
	o := opts.withDefaults()
	return &Estimator{
		opts: o,
		rto:  o.InitialRTO,
	}
}

// NewDefault constructs an Estimator with the package-default Options.
// Equivalent to New(Options{}).
func NewDefault() *Estimator { return New(Options{}) }

// Update consumes a new RTT sample and recomputes SRTT, RTTVar, RTO
// per RFC 6298 §2.3 (or §2.2 on the very first sample).
//
// The sample should be a single round-trip measurement that the caller
// is confident isn't from a retransmitted frame (Karn's algorithm —
// retransmitted samples are ambiguous and must be omitted). Aether's
// reliability layer enforces this by checking SendEntry.Retries == 0
// before calling Update.
//
// Negative or zero samples are rejected (no-op). Caller should pre-clamp
// to >= 1µs if they're working from a wall-clock difference that might
// be negative due to clock skew.
func (e *Estimator) Update(sample time.Duration) {
	if sample <= 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	e.lastSample = sample
	e.lastSampleAt = time.Now()
	e.sampleCount++
	if e.minRTT == 0 || sample < e.minRTT {
		e.minRTT = sample
	}

	if !e.initialized {
		// RFC 6298 §2.2 — first sample sets SRTT = R, RTTVar = R/2.
		e.srtt = sample
		e.rttVar = sample / 2
		e.initialized = true
	} else {
		// RFC 6298 §2.3 — subsequent samples.
		// Compute RTTVar BEFORE updating SRTT so the |SRTT-R'|
		// deviation reflects the pre-update mean, per the RFC's
		// pseudocode order.
		diff := e.srtt - sample
		if diff < 0 {
			diff = -diff
		}
		e.rttVar = time.Duration(float64(e.rttVar)*(1-e.opts.Beta) + float64(diff)*e.opts.Beta)
		e.srtt = time.Duration(float64(e.srtt)*(1-e.opts.Alpha) + float64(sample)*e.opts.Alpha)
	}

	// RTO = SRTT + max(G, K*RTTVar), clamped to [MinRTO, MaxRTO].
	k := time.Duration(rfcK) * e.rttVar
	if k < e.opts.Granularity {
		k = e.opts.Granularity
	}
	rto := e.srtt + k
	if rto < e.opts.MinRTO {
		rto = e.opts.MinRTO
	}
	if rto > e.opts.MaxRTO {
		rto = e.opts.MaxRTO
	}
	e.rto = rto
}

// UpdateWithDelay is the QUIC RFC 9002 §5.3 variant: subtract the
// peer-reported ACK-processing delay before feeding the sample to
// Update. Avoids inflating SRTT by time the receiver held the ACK
// before transmitting it.
//
// Adjusted sample is max(rawRTT - ackDelay, 1µs) to prevent the
// inputs from going negative under tiny RTTs or pathological
// peer-reported delays.
func (e *Estimator) UpdateWithDelay(rawRTT, ackDelay time.Duration) {
	adjusted := rawRTT - ackDelay
	if adjusted < time.Microsecond {
		adjusted = time.Microsecond
	}
	e.Update(adjusted)
}

// SRTT returns the smoothed round-trip time. Zero before the first
// sample.
func (e *Estimator) SRTT() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.srtt
}

// RTTVar returns the smoothed RTT mean deviation (RFC 6298). Zero
// before the first sample.
func (e *Estimator) RTTVar() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.rttVar
}

// RTO returns the current retransmission timeout (Probe Timeout in
// QUIC parlance). Returns Options.InitialRTO before the first sample.
// Always within [MinRTO, MaxRTO] after Update has been called at
// least once.
func (e *Estimator) RTO() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.rto
}

// LastSample returns the most recent raw RTT sample fed to Update.
// Useful for diagnostic readout; not used in any decision path. Zero
// before the first sample.
func (e *Estimator) LastSample() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lastSample
}

// LastSampleAt returns the wall-clock time the most recent sample was
// recorded. Zero before the first sample. Used by callers that need
// to know whether the estimator's outputs are fresh — e.g. a
// keepalive subsystem might fall back to static defaults if the
// last sample is older than some threshold.
func (e *Estimator) LastSampleAt() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lastSampleAt
}

// MinRTT returns the smallest RTT sample observed since the estimator
// was constructed. Per RFC 9002 §5.2, MinRTT is a more stable signal
// than SRTT for the path's irreducible latency floor — useful for BBR-
// style bandwidth estimation, RACK reorder window sizing, and
// distinguishing genuine load from network reordering.
//
// Zero before the first sample. Monotonically non-increasing (only
// decreases or stays the same) — call ResetMinRTT explicitly to
// trigger re-measurement (e.g. after a path migration).
func (e *Estimator) MinRTT() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.minRTT
}

// ResetMinRTT clears the MinRTT tracker. Caller invokes when the
// physical path is known to have changed (multipath migration, NAT
// rebinding, etc.) so a stale minimum from the old path doesn't
// pollute decisions on the new one.
func (e *Estimator) ResetMinRTT() {
	e.mu.Lock()
	e.minRTT = 0
	e.mu.Unlock()
}

// SampleCount returns the total number of successful Update calls.
// Useful for confidence checks: callers can require N samples before
// trusting SRTT/RTO for a decision (e.g. don't suppress a peer's
// proto until we have ≥ 5 samples).
func (e *Estimator) SampleCount() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.sampleCount
}

// PTO computes the QUIC RFC 9002 §6.2 Probe Timeout:
//
//	PTO = SRTT + max(G, K*RTTVar) + max_ack_delay
//
// Differs from RTO in that it includes the peer-advertised
// max_ack_delay term — the maximum time the peer might sit on an ACK
// before transmitting it. Used by TLP (Tail Loss Probe) to size its
// fire window: a probe should only fire after the peer has had every
// reasonable opportunity to ACK on its own.
//
// Pass maxAckDelay = 0 if the peer hasn't advertised one, which makes
// PTO equivalent to RTO. Callers that want both can hold a single
// max_ack_delay value and call PTO(d) and RTO() side by side.
func (e *Estimator) PTO(maxAckDelay time.Duration) time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	if maxAckDelay < 0 {
		maxAckDelay = 0
	}
	pto := e.rto + maxAckDelay
	if pto > e.opts.MaxRTO {
		pto = e.opts.MaxRTO
	}
	return pto
}

// Snapshot is a point-in-time view of the estimator's state. All
// values are captured under a single lock acquisition so reads are
// consistent with each other (e.g. SRTT and RTTVar agree).
type Snapshot struct {
	SRTT         time.Duration
	RTTVar       time.Duration
	RTO          time.Duration
	MinRTT       time.Duration
	LastSample   time.Duration
	LastSampleAt time.Time
	SampleCount  uint64
	Initialized  bool
}

// Snapshot captures the current state in one consistent atomic read.
// Useful for diagnostic dumps where multiple values need to be
// reported together.
func (e *Estimator) Snapshot() Snapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	return Snapshot{
		SRTT:         e.srtt,
		RTTVar:       e.rttVar,
		RTO:          e.rto,
		MinRTT:       e.minRTT,
		LastSample:   e.lastSample,
		LastSampleAt: e.lastSampleAt,
		SampleCount:  e.sampleCount,
		Initialized:  e.initialized,
	}
}

// BackoffRTO doubles the current RTO and returns the new value. Used
// by the retransmission timer when a frame's RTO fires without an
// ACK — RFC 6298 §5.5 "double the RTO value". Bounded above by MaxRTO
// so a black-holed path doesn't accumulate infinite timeouts.
//
// Backoff state persists until the next successful Update (sample
// from a non-retransmitted frame's ACK), which recomputes RTO from
// SRTT and RTTVar afresh.
func (e *Estimator) BackoffRTO() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rto *= 2
	if e.rto > e.opts.MaxRTO {
		e.rto = e.opts.MaxRTO
	}
	return e.rto
}

// IsInitialized reports whether at least one sample has been recorded.
// Callers checking whether SRTT/RTTVar/RTO are meaningful (vs. the
// initial defaults) should consult this first.
func (e *Estimator) IsInitialized() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.initialized
}
