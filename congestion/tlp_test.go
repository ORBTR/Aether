/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
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

// TestTLPPendingProbe — RFC 8985 §7.5 / RFC 9002 §6.2.4: a pending probe
// does NOT block subsequent probes. The previous behaviour (probePending
// gates ShouldProbe) caused stream wedges when the first probe was
// dropped on the wire — the connection stayed in "waiting for probe ACK"
// forever and never fired the 2nd/3rd probe that would either elicit an
// ACK or exhaust the consecutiveProbes counter and let the session-level
// stall detector close the path. Probes are gated by scheduledAt
// (re-armed each tick) + consecutiveProbes only.
func TestTLPPendingProbe(t *testing.T) {
	tlp := NewTLP(20 * time.Millisecond)
	t0 := time.Now()
	tlp.Arm(t0)
	pto := tlp.Snapshot().PTO
	// First probe at PTO.
	tlp.MarkProbeSent(99)
	// Even with probePending=true, ShouldProbe must fire again once the
	// next scheduled time has elapsed (adapter Arms with the fresh
	// XmitTime after each MarkProbeSent).
	tlp.Arm(t0.Add(pto)) // re-arm with the probe's XmitTime
	if !tlp.ShouldProbe(t0.Add(2*pto + time.Millisecond)) {
		t.Error("ShouldProbe must fire again after re-Arm even with probePending=true")
	}
	// On ACK, consecutiveProbes resets and we can probe afresh.
	tlp.MarkProbeAcked()
	tlp.Arm(t0.Add(2 * pto))
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
