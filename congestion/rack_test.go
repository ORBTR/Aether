/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

package congestion

import (
	"testing"
	"time"
)

// TestRACKBasicLossDetection — a packet sent before fack with xmit time
// older than reoWnd is declared lost.
func TestRACKBasicLossDetection(t *testing.T) {
	r := NewRACK(20 * time.Millisecond) // SRTT 20ms → reoWnd = 5ms
	t0 := time.Now()
	// Frame 1 sent at t0, frame 2 sent at t0+10ms.
	// ACK arrives at t0+30ms acknowledging frame 2 → fack = t0+10ms.
	r.Ack(2, t0.Add(10*time.Millisecond), t0.Add(30*time.Millisecond))

	// Frame 1's xmit time (t0) is 10ms older than fack (t0+10ms),
	// well past reoWnd (5ms). Should be declared lost.
	snap := []SendEntrySnapshot{
		{Seq: 1, XmitTime: t0},
	}
	lost, _ := r.DetectLost(snap, t0.Add(30*time.Millisecond))
	if len(lost) != 1 || lost[0] != 1 {
		t.Errorf("expected seq 1 to be declared lost, got %v", lost)
	}
}

// TestRACKReorderTolerance — a packet within reoWnd of fack is NOT lost.
func TestRACKReorderTolerance(t *testing.T) {
	r := NewRACK(100 * time.Millisecond) // SRTT 100ms → reoWnd = 25ms
	t0 := time.Now()
	r.Ack(2, t0.Add(20*time.Millisecond), t0.Add(50*time.Millisecond))

	// Frame 1 sent 10ms before fack (well within 25ms reoWnd).
	// Run DetectLost soon after the ACK so the wake time
	// (XmitTime + reoWnd = t0 + 35ms) is in the future.
	snap := []SendEntrySnapshot{
		{Seq: 1, XmitTime: t0.Add(10 * time.Millisecond)},
	}
	lost, wakeup := r.DetectLost(snap, t0.Add(20*time.Millisecond))
	if len(lost) != 0 {
		t.Errorf("expected no losses (within reoWnd), got %v", lost)
	}
	if wakeup.IsZero() {
		t.Error("expected non-zero wakeup time for re-check (XmitTime+reoWnd should be in future)")
	}
}

// TestRACKIdempotence — the same seq isn't re-marked on subsequent ticks.
func TestRACKIdempotence(t *testing.T) {
	r := NewRACK(20 * time.Millisecond)
	t0 := time.Now()
	r.Ack(2, t0.Add(10*time.Millisecond), t0.Add(30*time.Millisecond))

	snap := []SendEntrySnapshot{
		{Seq: 1, XmitTime: t0},
	}
	lost1, _ := r.DetectLost(snap, t0.Add(30*time.Millisecond))
	lost2, _ := r.DetectLost(snap, t0.Add(40*time.Millisecond))

	if len(lost1) != 1 {
		t.Fatalf("first DetectLost: expected 1 loss, got %v", lost1)
	}
	if len(lost2) != 0 {
		t.Errorf("second DetectLost: expected 0 (already marked), got %v", lost2)
	}
}

// TestRACKDSACKInflatesReoWnd — observing reordering grows reoWnd.
func TestRACKDSACKInflatesReoWnd(t *testing.T) {
	r := NewRACK(80 * time.Millisecond)
	initialReoWnd := r.Snapshot().ReoWnd
	r.OnDSACK()
	r.OnDSACK()
	after := r.Snapshot().ReoWnd
	if after <= initialReoWnd {
		t.Errorf("expected reoWnd to grow after DSACKs, %v -> %v", initialReoWnd, after)
	}
}

// TestRACKNoFackNoLossDecision — can't decide losses without any deliveries.
func TestRACKNoFackNoLossDecision(t *testing.T) {
	r := NewRACK(20 * time.Millisecond)
	snap := []SendEntrySnapshot{
		{Seq: 1, XmitTime: time.Now().Add(-10 * time.Second)},
	}
	lost, wakeup := r.DetectLost(snap, time.Now())
	if len(lost) != 0 {
		t.Errorf("no fack established yet — expected 0 losses, got %v", lost)
	}
	if !wakeup.IsZero() {
		t.Error("expected zero wakeup when no fack established")
	}
}

// TestRACKFackOnlyAdvances — Ack on an older xmit time doesn't move fack
// backward.
func TestRACKFackOnlyAdvances(t *testing.T) {
	r := NewRACK(20 * time.Millisecond)
	t0 := time.Now()
	// First, an ACK on a packet with XmitTime t0+50ms.
	r.Ack(5, t0.Add(50*time.Millisecond), t0.Add(70*time.Millisecond))
	st1 := r.Snapshot()
	// Then, a (later-arriving) ACK on a packet with XmitTime t0+10ms.
	r.Ack(2, t0.Add(10*time.Millisecond), t0.Add(80*time.Millisecond))
	st2 := r.Snapshot()
	if !st2.Fack.Equal(st1.Fack) {
		t.Errorf("fack moved backward: %v -> %v", st1.Fack, st2.Fack)
	}
}
