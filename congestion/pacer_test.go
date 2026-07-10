/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package congestion

import (
	"testing"
)

// TestPacer_ZeroRateDisablesPacing is the AE-H-04 regression: for a default
// (CUBIC) session the token-bucket Pacer's rate is never set, so once the
// initial burst drains, TimeUntilSend must treat rate <= 0 as "pacing
// disabled" and return 0 — not park the writeLoop for maxPacerWait (an hour)
// per frame, which deadlocked throughput on any >64KB send.
func TestPacer_ZeroRateDisablesPacing(t *testing.T) {
	// (1) Zero rate, burst drained: TimeUntilSend must return 0 (was time.Hour).
	p := NewPacer(0, 64*1024)
	p.OnSend(64 * 1024) // drain the entire initial burst
	if got := p.TimeUntilSend(1400); got != 0 {
		t.Fatalf("zero-rate drained pacer: TimeUntilSend(1400) = %v, want 0 "+
			"(AE-H-04 regression: previously returned maxPacerWait)", got)
	}

	// (2) Over-correction guard: with a positive rate and an empty bucket,
	// pacing must still delay — the fix only flips the rate<=0 disabled case.
	q := NewPacer(1000, 1400)
	if !q.Consume(1400) {
		t.Fatal("setup: Consume(1400) on a full 1400-byte bucket should succeed")
	}
	if got := q.TimeUntilSend(1400); got <= 0 {
		t.Fatalf("positive-rate empty pacer: TimeUntilSend(1400) = %v, want > 0 "+
			"(pacing must still delay when a real rate is configured)", got)
	}
}

// TestPacer_ZeroRateMatchesSendTimePacer pins the AE-H-04 intent: the
// token-bucket Pacer with no configured rate now agrees with SendTimePacer,
// which already returns 0 for the rate<=0 "pacing disabled" sentinel.
func TestPacer_ZeroRateMatchesSendTimePacer(t *testing.T) {
	p := NewPacer(0, 64*1024)
	p.OnSend(64 * 1024) // drain the burst so the rate<=0 branch is exercised
	tokenWait := p.TimeUntilSend(1400)

	s := NewSendTimePacer(0)
	sendTimeWait := s.TimeUntilSend(1400)

	if tokenWait != 0 || sendTimeWait != 0 {
		t.Fatalf("disabled-pacing mismatch: Pacer=%v SendTimePacer=%v, both want 0",
			tokenWait, sendTimeWait)
	}
}
