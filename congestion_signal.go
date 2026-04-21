/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

package aether

import (
	"sync"
	"sync/atomic"
	"time"
)

// CongestionThrottle is the sender-side state for an explicit CONGESTION
// signal received from a peer. Sessions instantiate one per peer and
// consult it from their send path.
//
// Usage:
//
//	var throttle CongestionThrottle
//	// On CONGESTION frame receipt:
//	throttle.Apply(DecodeCongestion(frame.Payload))
//	// Before a large send:
//	if throttle.ShouldStall() { time.Sleep(throttle.RemainingBackoff()) }
//	// Or, for proportional rate shaping, check throttle.RateFactor() ∈ [0,1].
//
// Zero value is valid: no throttle applied ⇒ ShouldStall() false,
// RateFactor() == 1.0.
type CongestionThrottle struct {
	mu        sync.Mutex
	expiresAt time.Time        // end of current backoff window (zero = no active hint)
	severity  uint8            // 0-100, from the most recent CONGESTION hint
	reason    CongestionReason // most recent reason, for metrics
	hits      atomic.Uint64    // counter — how many hints applied overall
}

// Apply processes an incoming CONGESTION payload and updates the throttle.
// A severity==0 hint clears the throttle ("all clear"). Otherwise the hint
// is valid for BackoffMs milliseconds from now; subsequent hints extend
// or replace the window depending on severity.
func (t *CongestionThrottle) Apply(p CongestionPayload) {
	t.hits.Add(1)
	t.mu.Lock()
	defer t.mu.Unlock()

	// Explicit "all clear" — drop the throttle.
	if p.Severity == 0 {
		t.expiresAt = time.Time{}
		t.severity = 0
		t.reason = p.Reason
		return
	}

	t.reason = p.Reason
	t.severity = p.Severity

	// Default backoff if peer didn't specify one: scale from severity so higher
	// severity yields longer windows (10 ms per percent of severity).
	backoff := time.Duration(p.BackoffMs) * time.Millisecond
	if backoff <= 0 {
		backoff = time.Duration(p.Severity) * 10 * time.Millisecond
	}
	newExpiry := time.Now().Add(backoff)
	// Never shorten a longer active backoff (peer should be telling us to
	// back off MORE, never less, across overlapping hints).
	if newExpiry.After(t.expiresAt) {
		t.expiresAt = newExpiry
	}
}

// ShouldStall returns true if severity 100 is active — sender should hold
// sends until RemainingBackoff() elapses. For intermediate severities, use
// RateFactor() instead.
func (t *CongestionThrottle) ShouldStall() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.severity >= 100 && time.Now().Before(t.expiresAt)
}

// RateFactor returns the current permitted send-rate multiplier in [0, 1].
// 1.0 means unrestricted; 0.0 means fully stalled. Computed from severity
// (linear: factor = (100-severity)/100) while the backoff window is active,
// and 1.0 otherwise. Callers shaping send rate — e.g. a token-bucket pacer —
// can multiply their target rate by this factor.
func (t *CongestionThrottle) RateFactor() float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.expiresAt.IsZero() || time.Now().After(t.expiresAt) {
		return 1.0
	}
	return float64(100-int(t.severity)) / 100.0
}

// TotalHits returns the cumulative number of CONGESTION hints applied
// since construction. Lock-free — safe to call from metric sampling paths
// without contending with Apply. Surfaces the counter that Snapshot()
// already exposes, for consumers that only need the hit count and don't
// want to materialise a full state struct on every sample.
func (t *CongestionThrottle) TotalHits() uint64 {
	return t.hits.Load()
}

// RemainingBackoff returns the remaining duration of the active backoff
// window, or zero if no hint is active.
func (t *CongestionThrottle) RemainingBackoff() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.expiresAt.IsZero() {
		return 0
	}
	remaining := time.Until(t.expiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// Snapshot returns the current throttle state. Cheap; for metrics.
func (t *CongestionThrottle) Snapshot() CongestionThrottleState {
	t.mu.Lock()
	defer t.mu.Unlock()
	return CongestionThrottleState{
		Active:           !t.expiresAt.IsZero() && time.Now().Before(t.expiresAt),
		Severity:         t.severity,
		Reason:           t.reason,
		RemainingBackoff: time.Until(t.expiresAt),
		TotalHits:        t.hits.Load(),
	}
}

// CongestionThrottleState is a point-in-time view for metrics/observability.
type CongestionThrottleState struct {
	Active           bool
	Severity         uint8
	Reason           CongestionReason
	RemainingBackoff time.Duration
	TotalHits        uint64
}
