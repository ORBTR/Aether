/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

package congestion

import (
	"testing"
	"time"
)

// TestTLPBasicArm — armed scheduler fires after PTO has elapsed.
func TestTLPBasicArm(t *testing.T) {
	tlp := NewTLP(20 * time.Millisecond)
	t0 := time.Now()
	tlp.Arm(t0)

	// Right after Arm, ShouldProbe is false (PTO hasn't elapsed).
	if tlp.ShouldProbe(t0.Add(10 * time.Millisecond)) {
		t.Error("ShouldProbe true before PTO elapsed")
	}
	// After PTO (default ~65ms with 20ms SRTT + 25ms maxAckDelay = 65ms).
	pto := tlp.Snapshot().PTO
	if !tlp.ShouldProbe(t0.Add(pto + time.Millisecond)) {
		t.Error("ShouldProbe false after PTO elapsed")
	}
}

// TestTLPDisarm — Disarm clears the schedule.
func TestTLPDisarm(t *testing.T) {
	tlp := NewTLP(20 * time.Millisecond)
	t0 := time.Now()
	tlp.Arm(t0)
	tlp.Disarm()
	pto := tlp.Snapshot().PTO
	if tlp.ShouldProbe(t0.Add(pto + time.Second)) {
		t.Error("ShouldProbe true after Disarm")
	}
}

// TestTLPPendingProbe — pending state suppresses re-firing.
func TestTLPPendingProbe(t *testing.T) {
	tlp := NewTLP(20 * time.Millisecond)
	t0 := time.Now()
	tlp.Arm(t0)
	pto := tlp.Snapshot().PTO
	// First probe at PTO.
	tlp.MarkProbeSent(99)
	// While pending, ShouldProbe returns false even past 2× PTO.
	if tlp.ShouldProbe(t0.Add(2*pto + time.Millisecond)) {
		t.Error("ShouldProbe true while probe is pending")
	}
	// On ACK, pending clears.
	tlp.MarkProbeAcked()
	tlp.Arm(t0.Add(2 * pto)) // re-arm with fresher inFlight time
	// Now should fire again at the new schedule.
	if !tlp.ShouldProbe(t0.Add(3*pto + time.Millisecond)) {
		t.Error("ShouldProbe false after MarkProbeAcked + Arm")
	}
}

// TestTLPMaxConsecutiveProbes — capped at maxConsecutiveProbes.
func TestTLPMaxConsecutiveProbes(t *testing.T) {
	tlp := NewTLP(20 * time.Millisecond)
	t0 := time.Now()
	tlp.Arm(t0)
	pto := tlp.Snapshot().PTO

	for i := 0; i < maxConsecutiveProbes; i++ {
		tlp.MarkProbeSent(uint32(i))
		// Without an Ack, Disarm/MarkAcked, the consecutive counter grows.
		tlp.MarkProbeAcked()  // Clear pending so next ShouldProbe can fire.
		tlp.consecutiveProbes = i + 1 // simulate not resetting via internal access
		tlp.Arm(t0.Add(time.Duration(i+1) * pto))
	}
	// Once at the cap, ShouldProbe must return false even past PTO.
	if tlp.ShouldProbe(t0.Add(time.Duration(maxConsecutiveProbes+5) * pto)) {
		t.Error("ShouldProbe true after maxConsecutiveProbes")
	}
}

// TestTLPAnyAckResetsCounter — receiving real ACKs unsticks the counter.
func TestTLPAnyAckResetsCounter(t *testing.T) {
	tlp := NewTLP(20 * time.Millisecond)
	tlp.consecutiveProbes = maxConsecutiveProbes
	tlp.AnyAckReceived()
	if tlp.consecutiveProbes != 0 {
		t.Errorf("AnyAckReceived didn't reset consecutiveProbes: %d", tlp.consecutiveProbes)
	}
}

// TestTLPPTOFloor — PTO doesn't collapse below the floor on tiny SRTT.
func TestTLPPTOFloor(t *testing.T) {
	tlp := NewTLP(0) // unknown SRTT
	pto := tlp.Snapshot().PTO
	if pto < tlpPTOFloor {
		t.Errorf("PTO below floor: %v < %v", pto, tlpPTOFloor)
	}
}

// TestTLPPTOCeiling — PTO is bounded above by ceiling.
func TestTLPPTOCeiling(t *testing.T) {
	tlp := NewTLP(10 * time.Second) // pathologically large SRTT
	pto := tlp.Snapshot().PTO
	if pto > tlpPTOCeiling {
		t.Errorf("PTO above ceiling: %v > %v", pto, tlpPTOCeiling)
	}
}
