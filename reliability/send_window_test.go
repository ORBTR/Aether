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

func TestSendWindow_AddAndAck(t *testing.T) {
	w := NewSendWindow(10)

	f1 := &aether.Frame{Type: aether.TypeDATA, Payload: []byte("a")}
	f2 := &aether.Frame{Type: aether.TypeDATA, Payload: []byte("b")}

	seq1 := w.Add(f1)
	seq2 := w.Add(f2)

	if seq1 != 0 {
		t.Errorf("first SeqNo: got %d, want 0", seq1)
	}
	if seq2 != 1 {
		t.Errorf("second SeqNo: got %d, want 1", seq2)
	}
	if w.InFlight() != 2 {
		t.Errorf("InFlight: got %d, want 2", w.InFlight())
	}

	entry := w.Ack(0)
	if entry == nil {
		t.Fatal("Ack(0) returned nil")
	}
	if w.InFlight() != 1 {
		t.Errorf("InFlight after ack: got %d, want 1", w.InFlight())
	}
	if w.Base() != 1 {
		t.Errorf("Base after ack: got %d, want 1", w.Base())
	}
}

func TestSendWindow_AckRange(t *testing.T) {
	w := NewSendWindow(10)

	for i := 0; i < 5; i++ {
		w.Add(&aether.Frame{Type: aether.TypeDATA})
	}

	count := w.AckRange(1, 3) // ack SeqNos 1, 2, 3
	if count != 3 {
		t.Errorf("AckRange count: got %d, want 3", count)
	}
	if w.InFlight() != 2 { // 0 and 4 still in flight
		t.Errorf("InFlight: got %d, want 2", w.InFlight())
	}
}

func TestSendWindow_IsFull(t *testing.T) {
	w := NewSendWindow(3)

	w.Add(&aether.Frame{Type: aether.TypeDATA})
	w.Add(&aether.Frame{Type: aether.TypeDATA})
	if w.IsFull() {
		t.Error("should not be full with 2/3")
	}

	w.Add(&aether.Frame{Type: aether.TypeDATA})
	if !w.IsFull() {
		t.Error("should be full with 3/3")
	}

	w.Ack(0)
	if w.IsFull() {
		t.Error("should not be full after ack")
	}
}

func TestSendWindow_Expired(t *testing.T) {
	w := NewSendWindow(10)
	w.Add(&aether.Frame{Type: aether.TypeDATA})

	// Immediately check — should not be expired
	expired := w.Expired(100 * time.Millisecond)
	if len(expired) != 0 {
		t.Errorf("should not be expired immediately, got %d", len(expired))
	}

	// Wait and check
	time.Sleep(150 * time.Millisecond)
	expired = w.Expired(100 * time.Millisecond)
	if len(expired) != 1 {
		t.Errorf("should have 1 expired, got %d", len(expired))
	}
}

func TestSendWindow_GetEntry(t *testing.T) {
	w := NewSendWindow(10)
	w.Add(&aether.Frame{Type: aether.TypeDATA, Payload: []byte("hello")})

	entry := w.GetEntry(0)
	if entry == nil {
		t.Fatal("GetEntry(0) returned nil")
	}
	if string(entry.Frame.Payload) != "hello" {
		t.Errorf("payload: got %q, want %q", entry.Frame.Payload, "hello")
	}

	// Non-existent SeqNo
	if w.GetEntry(99) != nil {
		t.Error("GetEntry(99) should return nil")
	}
}

// fillWindow adds n frames (seq 0..n-1) to a fresh window sized maxSize.
func fillWindow(t *testing.T, maxSize, n int) *SendWindow {
	t.Helper()
	w := NewSendWindow(maxSize)
	for i := 0; i < n; i++ {
		w.Add(&aether.Frame{Type: aether.TypeDATA})
	}
	if got := w.InFlight(); got != n {
		t.Fatalf("setup: InFlight()=%d, want %d", got, n)
	}
	return w
}

// bitmap4 returns a 4-byte bitmap with the given bit indices set. Bit i
// corresponds to seq BaseACK+1+i (matching ProcessCompositeACK's scan).
func bitmap4(bits ...int) []byte {
	b := make([]byte, 4)
	for _, i := range bits {
		b[i/8] |= 1 << (uint(i) % 8)
	}
	return b
}

// TestProcessCompositeACK_NoSpuriousNACKAboveLargestAcked is the AE-H-09
// regression: an in-flight seq ABOVE the highest SACKed seq must not be
// implicitly NACKed. Pre-fix, int(largestAcked-seqNo) underflowed uint32
// to ~4e9 and spuriously NACKed the whole in-flight tail on every gapped ACK.
func TestProcessCompositeACK_NoSpuriousNACKAboveLargestAcked(t *testing.T) {
	w := fillWindow(t, 64, 20) // seq 0..19 in flight, next=20

	// BaseACK=10, bitmap marks seq12 (bit 1) and seq13 (bit 2) received.
	// largestAcked becomes 13; seq14..19 are still legitimately in flight.
	ack := &aether.CompositeACK{BaseACK: 10, Bitmap: bitmap4(1, 2)}
	acked, nacks := w.ProcessCompositeACK(ack, ReorderThreshold)

	if len(nacks) != 0 {
		t.Fatalf("nacks=%v, want empty (seq14..19 above largestAcked must NOT be NACKed)", nacks)
	}
	if len(acked) == 0 {
		t.Fatalf("acked is empty, want the cumulative + bitmap acks")
	}

	// seq12,13 acked and removed; seq11 still present (gap distance 2 < 3).
	if w.GetEntry(12) != nil {
		t.Errorf("seq12 should be acked+removed")
	}
	if w.GetEntry(13) != nil {
		t.Errorf("seq13 should be acked+removed")
	}
	if w.GetEntry(11) == nil {
		t.Errorf("seq11 should still be in flight (below reorder threshold)")
	}
	// Remaining in flight: seq 11,14,15,16,17,18,19 == 7.
	if got := w.InFlight(); got != 7 {
		t.Errorf("InFlight()=%d, want 7", got)
	}
	if got := w.Base(); got != 11 {
		t.Errorf("Base()=%d, want 11", got)
	}
}

// TestProcessCompositeACK_HighBitDoesNotInflateLargestAcked exercises the
// first-pass bound: a peer setting a bit at/beyond largestSent must not push
// largestAcked past w.next and thereby widen the NACK range.
func TestProcessCompositeACK_HighBitDoesNotInflateLargestAcked(t *testing.T) {
	w := fillWindow(t, 64, 20) // seq 0..19 in flight, next=20

	// 32-byte bitmap with only bit 250 set (seqNo 261, far beyond next=20).
	bm := make([]byte, 32)
	bm[250/8] |= 1 << (uint(250) % 8)
	ack := &aether.CompositeACK{BaseACK: 10, Bitmap: bm}

	_, nacks := w.ProcessCompositeACK(ack, ReorderThreshold)
	if len(nacks) != 0 {
		t.Fatalf("nacks=%v, want empty (high bit must not inflate largestAcked)", nacks)
	}
}

// TestProcessCompositeACK_GenuineReorderStillNACKs proves the guard narrows
// only spurious wrap NACKs — a real gap below largestAcked still NACKs.
func TestProcessCompositeACK_GenuineReorderStillNACKs(t *testing.T) {
	w := fillWindow(t, 64, 20) // seq 0..19 in flight, next=20

	// BaseACK=10, seq15 received (bit 4). largestAcked=15.
	// seq11 (dist 4) and seq12 (dist 3) exceed ReorderThreshold(3) -> NACK.
	// seq13 (dist 2), seq14 (dist 1) below threshold; seq16..19 above
	// largestAcked -> not NACKed.
	ack := &aether.CompositeACK{BaseACK: 10, Bitmap: bitmap4(4)}
	_, nacks := w.ProcessCompositeACK(ack, ReorderThreshold)

	want := []uint32{11, 12}
	if len(nacks) != len(want) {
		t.Fatalf("nacks=%v, want %v", nacks, want)
	}
	for i, seq := range want {
		if nacks[i] != seq {
			t.Fatalf("nacks=%v, want %v", nacks, want)
		}
	}
}

// TestProcessCompositeACK_StaleBaseACKStillAppliesSACK is the fleet-wide
// noise-udp stall regression. During a mid-stream gap the receiver's
// `expected` equals the sender's `base`, so every SACK-bearing duplicate ACK
// carries BaseACK == base-1 (i.e. BaseACK < base). The stale-BaseACK branch
// must NOT discard such an ACK wholesale — its cumulative point is stale but
// its SACK bitmap is fresh and is the ONLY signal that clears the received
// tail from flight and fast-retransmits the hole.
//
// Pre-fix, ProcessCompositeACK returned nil,nil in that branch BEFORE the
// bitmap scan, so: inFlight never drained, base never advanced, the receiver
// re-ACKed the buffered tail forever (millions of aether_ack_emit_duplicate),
// TLP tail-probes elicited only more discarded dup-ACKs, and the consumer
// keepalive reaped the still-grade-A session at ~62s. Measured on every
// noise-udp pair, including the latest deployed aether — the sawtooth churn.
func TestProcessCompositeACK_StaleBaseACKStillAppliesSACK(t *testing.T) {
	w := fillWindow(t, 64, 20) // seq 0..19 in flight, next=20, base=0

	// Advance the send base to 11 — models a receiver that delivered 0..10
	// in order. seq 11 is then the lost head of the stream.
	w.ProcessCompositeACK(&aether.CompositeACK{BaseACK: 10}, ReorderThreshold)
	if got := w.Base(); got != 11 {
		t.Fatalf("setup: Base()=%d, want 11", got)
	}
	if got := w.InFlight(); got != 9 { // 11..19
		t.Fatalf("setup: InFlight()=%d, want 9", got)
	}

	// The receiver lost seq 11 but holds 12..15, so it keeps emitting a
	// duplicate ACK whose cumulative point is expected-1 = 10 (== base-1),
	// carrying a SACK bitmap marking seq11 missing and seq12..15 received.
	// bit i -> seq BaseACK+1+i = 11+i, so bits 1..4 mark seq12..15.
	ack := &aether.CompositeACK{BaseACK: 10, Bitmap: bitmap4(1, 2, 3, 4)}
	acked, nacks := w.ProcessCompositeACK(ack, ReorderThreshold)

	// The SACK bitmap must still be applied: clear seq12..15 from flight and
	// fast-retransmit the hole at seq11. Pre-fix this returns nil,nil and the
	// stream never recovers.
	if len(acked) != 4 {
		t.Fatalf("acked=%d entries, want 4 (seq12..15 SACKed) — the stale-BaseACK path is discarding the SACK bitmap and breaking gap recovery", len(acked))
	}
	for _, seq := range []uint32{12, 13, 14, 15} {
		if w.GetEntry(seq) != nil {
			t.Errorf("seq%d should be SACK-acked and removed", seq)
		}
	}
	if got := w.InFlight(); got != 5 { // 11,16,17,18,19 remain
		t.Errorf("InFlight()=%d, want 5", got)
	}
	if got := w.Base(); got != 11 {
		t.Errorf("Base()=%d, want 11 (the hole at seq11 pins base until it is retransmitted+acked)", got)
	}
	if len(nacks) != 1 || nacks[0] != 11 {
		t.Fatalf("nacks=%v, want [11] (the missing head must be fast-retransmitted)", nacks)
	}
}
