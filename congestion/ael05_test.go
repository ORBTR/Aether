/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

package congestion

import (
	"testing"
	"time"
)

// TestAEL05_AckOnMarkedLostInflatesReoWnd — AE-L-05: acking a seq RACK already
// declared lost (DSACK evidence of reordering) must inflate reoWnd via the
// production rack.Ack wiring, not only the explicit OnDSACK API. Pre-fix,
// Ack unconditionally deleted the markedLost entry and reoWnd stayed pinned at
// computeReoWnd(); post-fix, the in-Ack DSACK detection revives the RFC 8985
// §7.2 inflation path so genuinely-reordering flows widen their tolerance.
func TestAEL05_AckOnMarkedLostInflatesReoWnd(t *testing.T) {
	r := NewRACK(80 * time.Millisecond) // reoWnd base = minRTT/4 = 20ms
	t0 := time.Now()
	// Establish fack at t0+40ms by acking a later packet.
	r.Ack(3, t0.Add(40*time.Millisecond), t0.Add(60*time.Millisecond))
	// Seq 1 (sent at t0) is well past reoWnd (cutoff=t0+20ms) → declared lost
	// and recorded in markedLost.
	snap := []SendEntrySnapshot{{Seq: 1, XmitTime: t0}}
	lost, _ := r.DetectLost(snap, t0.Add(60*time.Millisecond))
	if len(lost) != 1 || lost[0] != 1 {
		t.Fatalf("setup: expected seq 1 declared lost, got %v", lost)
	}
	before := r.Snapshot().ReoWnd
	// The reordered original for seq 1 finally arrives and is acked.
	r.Ack(1, t0, t0.Add(70*time.Millisecond))
	after := r.Snapshot()
	if after.ReoWnd <= before { // expect 20ms -> 30ms (step = minRTT/8 = 10ms)
		t.Errorf("expected reoWnd to inflate on re-ack of marked-lost seq, %v -> %v", before, after.ReoWnd)
	}
	if after.MarkedLost != 0 {
		t.Errorf("expected markedLost cleared after ack, got %d entries", after.MarkedLost)
	}
}
