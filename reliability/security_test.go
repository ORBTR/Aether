/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package reliability

import (
	"testing"

	"github.com/ORBTR/aether"
)

// ─── S1 — Composite ACK unbounded-scan protection ─────────────────────
// Addresses _SECURITY.md §3.2. Crafted ACKs must not be able to force
// CPU-exhausting loops in ProcessCompositeACK.

func TestS1_CumulativeJumpRejected(t *testing.T) {
	w := NewSendWindow(64)
	// Put one real frame in so base=0, next=1
	w.Add(&aether.Frame{StreamID: 1})

	// Craft an ACK claiming BaseACK = 4 billion (uint32 max).
	// Without the cap, ProcessCompositeACK would loop 4B times.
	malicious := &aether.CompositeACK{BaseACK: ^uint32(0)}
	acked, nacks := w.ProcessCompositeACK(malicious, 3)

	if len(acked) != 0 || len(nacks) != 0 {
		t.Fatalf("malicious ACK returned acked=%d nacks=%d; want 0/0", len(acked), len(nacks))
	}
	if got := w.SuspiciousACKsCount(); got != 1 {
		t.Errorf("SuspiciousACKsCount = %d, want 1", got)
	}
}

func TestS1_BitmapLengthValidation(t *testing.T) {
	w := NewSendWindow(64)
	w.Add(&aether.Frame{StreamID: 1})

	// 255-byte bitmap — attacker trying to force a 2040-bit scan.
	bogus := &aether.CompositeACK{BaseACK: 0, Bitmap: make([]byte, 255)}
	acked, _ := w.ProcessCompositeACK(bogus, 3)

	if len(acked) != 0 {
		t.Fatalf("bogus bitmap ACK was processed")
	}
	if got := w.SuspiciousACKsCount(); got != 1 {
		t.Errorf("SuspiciousACKsCount = %d, want 1", got)
	}
}

func TestS1_ValidBitmapLengthAccepted(t *testing.T) {
	w := NewSendWindow(64)
	// Add a few frames so bitmap bits have something to ack.
	for i := 0; i < 4; i++ {
		w.Add(&aether.Frame{StreamID: 1})
	}
	// 8-byte bitmap is a valid length. BaseACK stays small.
	good := &aether.CompositeACK{BaseACK: 0, Bitmap: make([]byte, 8)}
	_, _ = w.ProcessCompositeACK(good, 3)
	if got := w.SuspiciousACKsCount(); got != 0 {
		t.Errorf("valid bitmap length flagged as suspicious (count=%d)", got)
	}
}

func TestS1_OversizedExtRangeRejected(t *testing.T) {
	w := NewSendWindow(64)
	// Base=0, next will advance with each Add; we need enough to anchor ExtRange.
	for i := 0; i < 8; i++ {
		w.Add(&aether.Frame{StreamID: 1})
	}
	// Craft an ExtRange of 2B entries — forces unbounded scan without cap.
	// The block must live above the bitmap window (empty here, so >0 is enough).
	ack := &aether.CompositeACK{
		BaseACK: 0,
		Flags:   aether.CACKHasExtRanges,
		ExtRanges: []aether.SACKBlock{
			{Start: 100, End: 100 + MaxACKRangeSize + 1},
		},
	}
	_, _ = w.ProcessCompositeACK(ack, 3)
	if got := w.SuspiciousACKsCount(); got != 1 {
		t.Errorf("oversized ExtRange not flagged (count=%d)", got)
	}
}

// ─── S8 — SeqNo wraparound rejection ──────────────────────────────────
// Addresses _SECURITY.md §3.3. An attacker observing topSeq near uint32 max
// must not be able to reset the window by claiming a "forward" jump that
// is actually a wraparound.

func TestS8_WraparoundRejected(t *testing.T) {
	w := NewReplayWindow()
	// Top starts low so the malicious seqNo can appear as a "forward" jump.
	if !w.Check(100) {
		t.Fatal("first check rejected unexpectedly")
	}
	// Attacker claims seqNo = 0xFFFFFFFE — a forward jump of ~4B, well
	// past SeqNoWrapThreshold (2^31). Real traffic never jumps this far.
	if w.Check(0xFFFFFFFE) {
		t.Fatal("wrap-attack seqNo was accepted")
	}
	if got := w.WrapsDetectedCount(); got != 1 {
		t.Errorf("WrapsDetectedCount = %d, want 1", got)
	}
}

func TestS8_LegitimateForwardStepAccepted(t *testing.T) {
	w := NewReplayWindow()
	if !w.Check(100) {
		t.Fatal("first check rejected")
	}
	// A normal forward step of +10 must still succeed.
	if !w.Check(110) {
		t.Fatal("normal forward step rejected")
	}
	if got := w.WrapsDetectedCount(); got != 0 {
		t.Errorf("legitimate step flagged as wrap (count=%d)", got)
	}
}

// ─── S2 — FEC decoder eviction ────────────────────────────────────────
// Addresses _SECURITY.md §3.5. The decoder must evict old groups so an
// attacker cannot fill memory with unique GroupIDs.

func TestS2_PruneEvictsOldest(t *testing.T) {
	d := NewFECDecoder()
	// Insert 300 incomplete groups. Total=3 means "2 data + 1 repair",
	// so receiving only the repair leaves the group stuck (can't recover
	// with 2 frames missing) — no auto-deletion by tryRecover.
	for i := uint32(0); i < 300; i++ {
		d.AddRepair(aether.FECHeader{GroupID: i, Index: 2, Total: 3}, []byte("x"))
	}
	d.Prune(256)
	if len(d.groups) != 256 {
		t.Fatalf("Prune: got %d groups, want 256", len(d.groups))
	}
	// Oldest IDs (0..43) should be gone.
	for i := uint32(0); i < 44; i++ {
		if _, ok := d.groups[i]; ok {
			t.Errorf("oldest group %d not evicted", i)
		}
	}
	if got := d.EvictedCount(); got != 44 {
		t.Errorf("EvictedCount = %d, want 44", got)
	}
}

func TestS2_PruneOlderThan(t *testing.T) {
	d := NewFECDecoder()
	// Use Total=3 so repair alone won't trigger auto-recovery.
	d.AddRepair(aether.FECHeader{GroupID: 1, Index: 2, Total: 3}, []byte("x"))
	// Force the group's firstSeen into the past.
	if g, ok := d.groups[1]; ok {
		g.firstSeen = g.firstSeen.Add(-10 * 1e9) // -10 seconds
	}
	d.PruneOlderThan(5 * 1e9) // drop anything older than 5s
	if _, ok := d.groups[1]; ok {
		t.Fatal("aged group was not evicted")
	}
	if got := d.EvictedCount(); got != 1 {
		t.Errorf("EvictedCount = %d, want 1", got)
	}
}
