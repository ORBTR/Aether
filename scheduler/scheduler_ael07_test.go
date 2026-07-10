/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

package scheduler

import (
	"testing"

	"github.com/ORBTR/aether"
)

// TestAEL07_WFQDeficitChargesRetransmitCost verifies that dequeueFromClass
// advances the persistent WFQ virtual time (ss.deficit) by the SAME cost used
// for selection — i.e. the 2x retransmit penalty — rather than the raw frame
// size (AE-L-07). Pre-fix the advance used frameSize/weight, so the retransmit
// multiplier only tilted the one-shot tie-break and was erased on the next
// comparison, letting a continually-retransmitting stream accrue identical
// accumulated deficit to a clean stream sending equal bytes.
func TestAEL07_WFQDeficitChargesRetransmitCost(t *testing.T) {
	s := NewScheduler()
	const ael07StreamID uint64 = 1

	s.RegisterWithClass(ael07StreamID, DefaultWeight, 0, aether.ClassINTERACTIVE)
	s.MarkRetransmit(ael07StreamID)
	s.Enqueue(ael07StreamID, &aether.Frame{Length: 100})

	frame, _ := s.Dequeue()
	if frame == nil {
		t.Fatal("AE-L-07: expected a frame from Dequeue, got nil")
	}

	frameSize := float64(aether.HeaderSize) + 100
	want := (frameSize * 2.0) / float64(DefaultWeight)

	ss, ok := s.streams[ael07StreamID]
	if !ok {
		t.Fatalf("AE-L-07: stream %d missing from scheduler after Dequeue", ael07StreamID)
	}
	if got := ss.deficit; got != want {
		t.Fatalf("AE-L-07: retransmit cost not charged to accumulated deficit: got %v, want %v (2x retransmit penalty must persist, not just tilt the one-shot selection)", got, want)
	}
}

// TestAEL07_WFQDeficitCreditsFECRepair verifies that a FEC repair frame credits
// the persistent deficit with the 0.5x bonus that the selection metric applies,
// so FEC repair is genuinely encouraged over retransmit in accumulated virtual
// time — not merely in a transient tie-break.
func TestAEL07_WFQDeficitCreditsFECRepair(t *testing.T) {
	s := NewScheduler()
	const ael07StreamID uint64 = 2

	s.RegisterWithClass(ael07StreamID, DefaultWeight, 0, aether.ClassINTERACTIVE)
	s.Enqueue(ael07StreamID, &aether.Frame{Length: 100, Type: aether.TypeFEC_REPAIR})

	frame, _ := s.Dequeue()
	if frame == nil {
		t.Fatal("AE-L-07: expected a frame from Dequeue, got nil")
	}

	frameSize := float64(aether.HeaderSize) + 100
	want := (frameSize * 0.5) / float64(DefaultWeight)

	ss, ok := s.streams[ael07StreamID]
	if !ok {
		t.Fatalf("AE-L-07: stream %d missing from scheduler after Dequeue", ael07StreamID)
	}
	if got := ss.deficit; got != want {
		t.Fatalf("AE-L-07: FEC repair bonus not credited to accumulated deficit: got %v, want %v (0.5x FEC bonus must persist in virtual time)", got, want)
	}
}
