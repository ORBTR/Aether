/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package reliability

import (
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// AE-P-23 regression coverage. Engine.ProcessACK previously removed
// retransmit entries with `for seq := block.Start; seq <= block.End; seq++`,
// where block.Start/block.End are peer-controlled uint32 from the wire. An
// End of 0xFFFFFFFF made seq wrap to 0 and stay <= End forever (infinite loop
// under e.sendMu), and End<Start ran ~4B Remove() calls. The fix bounds the
// scan by maxAckRangeSpan exactly as SendWindow.AckRange already does. These
// tests use finding-ID-unique symbol names to avoid cross-agent collisions in
// package reliability.

func aep23NewEngine() *Engine {
	return NewEngine(EngineConfig{
		StreamID:    1,
		Reliability: aether.ReliableOrdered,
		WindowSize:  64,
	})
}

// aep23EnqueueAt injects a retransmit entry keyed at an explicit SeqNo,
// bypassing the sequential Send() allocator so boundary spans (e.g. seq
// 65536) can be exercised without enqueuing millions of frames.
func aep23EnqueueAt(e *Engine, seqNo uint32) {
	f := &aether.Frame{StreamID: 1, Type: aether.TypeDATA, SeqNo: seqNo, Payload: []byte("x"), Length: 1}
	e.RetransmitQ.Enqueue(f)
}

// aep23RunWithTimeout runs fn and fails the test if it does not return within
// d — the direct detector for the infinite-loop / ~4B-iteration DoS.
func aep23RunWithTimeout(t *testing.T, d time.Duration, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s: ProcessACK did not return within %v (unbounded SACK scan)", what, d)
	}
}

// TestAEP23_ProcessACK_SACKWrapGuard drives the classic wrap input
// {Start:0, End:0xFFFFFFFF}. Pre-fix this never terminates.
func TestAEP23_ProcessACK_SACKWrapGuard(t *testing.T) {
	eng := aep23NewEngine()
	for i := 0; i < 4; i++ {
		eng.Send(&aether.Frame{StreamID: 1, Type: aether.TypeDATA, Payload: []byte("d"), Length: 1})
	}
	before := eng.RetransmitQ.Len()

	aep23RunWithTimeout(t, 2*time.Second, "wrap-span", func() {
		eng.ProcessACK(0xDEADBEEF, []aether.SACKBlock{{Start: 0, End: 0xFFFFFFFF}})
	})

	// Oversize span is skipped entirely: no retransmit entry is removed by
	// the SACK path (cumulative ackNo 0xDEADBEEF is absent, so it removes
	// nothing either).
	if got := eng.RetransmitQ.Len(); got != before {
		t.Fatalf("wrap span should remove nothing: len before=%d after=%d", before, got)
	}
}

// TestAEP23_ProcessACK_SACKReversedBlock drives End<Start, whose wrap-safe
// uint32 subtraction yields a huge span that must be skipped, not spun over.
func TestAEP23_ProcessACK_SACKReversedBlock(t *testing.T) {
	eng := aep23NewEngine()
	for i := 0; i < 4; i++ {
		eng.Send(&aether.Frame{StreamID: 1, Type: aether.TypeDATA, Payload: []byte("d"), Length: 1})
	}
	before := eng.RetransmitQ.Len()

	aep23RunWithTimeout(t, 2*time.Second, "reversed-block", func() {
		eng.ProcessACK(0xDEADBEEF, []aether.SACKBlock{{Start: 100, End: 5}})
	})

	if got := eng.RetransmitQ.Len(); got != before {
		t.Fatalf("reversed block should remove nothing: len before=%d after=%d", before, got)
	}
}

// TestAEP23_ProcessACK_SACKValidRangeRemoves is the capability-preserving
// regression: a legitimate in-window SACK block still removes exactly its
// covered seqs from the retransmit queue.
func TestAEP23_ProcessACK_SACKValidRangeRemoves(t *testing.T) {
	eng := aep23NewEngine()
	// Sequential seqs 0..5.
	for i := 0; i < 6; i++ {
		eng.Send(&aether.Frame{StreamID: 1, Type: aether.TypeDATA, Payload: []byte("d"), Length: 1})
	}
	if got := eng.RetransmitQ.Len(); got != 6 {
		t.Fatalf("setup: expected 6 queued entries, got %d", got)
	}

	// Cumulative ackNo absent from the window (no-op), so only the SACK
	// block [2,4] removes entries: seqs 2,3,4 → 3 removed, 0/1/5 remain.
	eng.ProcessACK(0xDEADBEEF, []aether.SACKBlock{{Start: 2, End: 4}})

	if got := eng.RetransmitQ.Len(); got != 3 {
		t.Fatalf("valid SACK block [2,4] should remove exactly 3 entries: len=%d, want 3", got)
	}
}

// TestAEP23_ProcessACK_SACKBoundarySpan pins the guard boundary: a span of
// exactly maxAckRangeSpan is processed (entries removed), while span+1 is
// skipped (entries retained).
func TestAEP23_ProcessACK_SACKBoundarySpan(t *testing.T) {
	// span == maxAckRangeSpan: processed. Block [0, maxAckRangeSpan].
	engOK := aep23NewEngine()
	aep23EnqueueAt(engOK, 0)
	aep23EnqueueAt(engOK, uint32(maxAckRangeSpan))
	if got := engOK.RetransmitQ.Len(); got != 2 {
		t.Fatalf("setup(ok): expected 2 entries, got %d", got)
	}
	aep23RunWithTimeout(t, 2*time.Second, "boundary-span", func() {
		engOK.ProcessACK(0xDEADBEEF, []aether.SACKBlock{{Start: 0, End: uint32(maxAckRangeSpan)}})
	})
	if got := engOK.RetransmitQ.Len(); got != 0 {
		t.Fatalf("span==maxAckRangeSpan must be processed and remove both entries: len=%d, want 0", got)
	}

	// span == maxAckRangeSpan+1: skipped. Block [0, maxAckRangeSpan+1].
	engSkip := aep23NewEngine()
	aep23EnqueueAt(engSkip, 0)
	aep23EnqueueAt(engSkip, uint32(maxAckRangeSpan)+1)
	if got := engSkip.RetransmitQ.Len(); got != 2 {
		t.Fatalf("setup(skip): expected 2 entries, got %d", got)
	}
	aep23RunWithTimeout(t, 2*time.Second, "over-boundary-span", func() {
		engSkip.ProcessACK(0xDEADBEEF, []aether.SACKBlock{{Start: 0, End: uint32(maxAckRangeSpan) + 1}})
	})
	if got := engSkip.RetransmitQ.Len(); got != 2 {
		t.Fatalf("span>maxAckRangeSpan must be skipped and retain both entries: len=%d, want 2", got)
	}
}
