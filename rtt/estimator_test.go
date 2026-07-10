/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

package rtt

import (
	"testing"
	"time"
)

// TestFirstSampleSetsSRTTAndHalfRTTVar — RFC 6298 §2.2.
func TestFirstSampleSetsSRTTAndHalfRTTVar(t *testing.T) {
	e := NewDefault()
	e.Update(100 * time.Millisecond)
	if e.SRTT() != 100*time.Millisecond {
		t.Errorf("SRTT: got %v want 100ms", e.SRTT())
	}
	if e.RTTVar() != 50*time.Millisecond {
		t.Errorf("RTTVar: got %v want 50ms", e.RTTVar())
	}
}

// TestSubsequentSamplesConverge — RFC 6298 §2.3 with stable input.
func TestSubsequentSamplesConverge(t *testing.T) {
	e := NewDefault()
	for i := 0; i < 100; i++ {
		e.Update(50 * time.Millisecond)
	}
	// SRTT should converge to the sample value
	if delta := e.SRTT() - 50*time.Millisecond; abs(delta) > time.Microsecond {
		t.Errorf("SRTT didn't converge to 50ms: got %v", e.SRTT())
	}
	// RTTVar should converge toward zero with stable input
	if e.RTTVar() > 100*time.Microsecond {
		t.Errorf("RTTVar should be tiny on stable input: got %v", e.RTTVar())
	}
}

// TestRTOBoundsClamp — RTO clamped to [MinRTO, MaxRTO].
func TestRTOBoundsClamp(t *testing.T) {
	e := New(Options{MinRTO: 10 * time.Millisecond, MaxRTO: 200 * time.Millisecond})
	// Tiny sample → would compute below MinRTO
	e.Update(time.Microsecond)
	if e.RTO() < 10*time.Millisecond {
		t.Errorf("RTO below MinRTO: got %v", e.RTO())
	}
	// Huge sample → RTO computation would exceed MaxRTO without clamp
	e2 := New(Options{MinRTO: 10 * time.Millisecond, MaxRTO: 200 * time.Millisecond})
	e2.Update(10 * time.Second)
	if e2.RTO() > 200*time.Millisecond {
		t.Errorf("RTO above MaxRTO: got %v", e2.RTO())
	}
}

// TestBackoffRTODoubles — RFC 6298 §5.5 doubling on retransmit timeout.
func TestBackoffRTODoubles(t *testing.T) {
	e := NewDefault()
	e.Update(50 * time.Millisecond)
	r1 := e.RTO()
	r2 := e.BackoffRTO()
	if r2 != r1*2 {
		t.Errorf("BackoffRTO: got %v want %v (2x %v)", r2, r1*2, r1)
	}
}

// TestBackoffCappedAtMaxRTO — exponential backoff bounded.
func TestBackoffCappedAtMaxRTO(t *testing.T) {
	e := New(Options{MaxRTO: 500 * time.Millisecond})
	e.Update(100 * time.Millisecond)
	for i := 0; i < 20; i++ {
		e.BackoffRTO()
	}
	if e.RTO() > 500*time.Millisecond {
		t.Errorf("BackoffRTO exceeded MaxRTO: got %v", e.RTO())
	}
}

// TestUpdateWithDelaySubtractsACK — RFC 9002 §5.3 ack-delay handling.
func TestUpdateWithDelaySubtractsACK(t *testing.T) {
	e := NewDefault()
	e.UpdateWithDelay(100*time.Millisecond, 30*time.Millisecond)
	if e.SRTT() != 70*time.Millisecond {
		t.Errorf("SRTT: got %v want 70ms (100-30)", e.SRTT())
	}
}

// TestUpdateWithDelayClampsToMicrosecond — negative-RTT prevention.
func TestUpdateWithDelayClampsToMicrosecond(t *testing.T) {
	e := NewDefault()
	// ackDelay > rawRTT would produce negative — should clamp to 1µs
	e.UpdateWithDelay(10*time.Millisecond, 50*time.Millisecond)
	if e.SRTT() != time.Microsecond {
		t.Errorf("SRTT: got %v want 1µs (clamped)", e.SRTT())
	}
}

// TestRejectsZeroAndNegative — defensive against bad inputs.
func TestRejectsZeroAndNegative(t *testing.T) {
	e := NewDefault()
	e.Update(0)
	e.Update(-1 * time.Millisecond)
	if e.IsInitialized() {
		t.Error("estimator initialised by invalid samples")
	}
}

// TestPreInitInitialRTO — InitialRTO returned before any sample.
func TestPreInitInitialRTO(t *testing.T) {
	e := New(Options{InitialRTO: 2 * time.Second})
	if e.RTO() != 2*time.Second {
		t.Errorf("pre-init RTO: got %v want 2s", e.RTO())
	}
	if e.IsInitialized() {
		t.Error("IsInitialized true before any sample")
	}
}

// TestRTTVarRespondsToJitter — bursty samples inflate RTTVar.
func TestRTTVarRespondsToJitter(t *testing.T) {
	e := NewDefault()
	// Stable baseline
	for i := 0; i < 50; i++ {
		e.Update(100 * time.Millisecond)
	}
	stableVar := e.RTTVar()
	// Now feed jitter
	for i := 0; i < 10; i++ {
		if i%2 == 0 {
			e.Update(50 * time.Millisecond)
		} else {
			e.Update(150 * time.Millisecond)
		}
	}
	burstyVar := e.RTTVar()
	if burstyVar <= stableVar {
		t.Errorf("RTTVar didn't increase under jitter: stable=%v bursty=%v", stableVar, burstyVar)
	}
}

// TestLastSampleTracksMostRecent — diagnostic accessor.
func TestLastSampleTracksMostRecent(t *testing.T) {
	e := NewDefault()
	e.Update(50 * time.Millisecond)
	e.Update(75 * time.Millisecond)
	if e.LastSample() != 75*time.Millisecond {
		t.Errorf("LastSample: got %v want 75ms", e.LastSample())
	}
}

func abs(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
