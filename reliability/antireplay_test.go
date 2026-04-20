/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package reliability

import "testing"

func TestReplayWindow_Sequential(t *testing.T) {
	w := NewReplayWindow()

	for i := uint32(0); i < 100; i++ {
		if !w.Check(i) {
			t.Fatalf("sequential %d should be accepted", i)
		}
	}
	if w.top() != 99 {
		t.Errorf("Top: got %d, want 99", w.top())
	}
}

func TestReplayWindow_Duplicate(t *testing.T) {
	w := NewReplayWindow()

	w.Check(10)
	if w.Check(10) {
		t.Error("duplicate should be rejected")
	}
}

func TestReplayWindow_OutOfOrder(t *testing.T) {
	w := NewReplayWindow()

	w.Check(10)
	w.Check(12) // skip 11

	// 11 is within window — should be accepted
	if !w.Check(11) {
		t.Error("out-of-order within window should be accepted")
	}

	// 11 again — should be rejected
	if w.Check(11) {
		t.Error("duplicate out-of-order should be rejected")
	}
}

func TestReplayWindow_TooOld(t *testing.T) {
	w := NewReplayWindow()

	// Set top to 100
	w.Check(100)

	// SeqNo 36 is within window (100 - 36 = 64 = boundary, but >= 64 means outside)
	if w.Check(36) {
		t.Error("SeqNo 36 with top=100 is outside 64-packet window, should be rejected")
	}

	// SeqNo 37 is at boundary (100 - 37 = 63, within window)
	if !w.Check(37) {
		t.Error("SeqNo 37 with top=100 is at window boundary, should be accepted")
	}
}

func TestReplayWindow_LargeJump(t *testing.T) {
	w := NewReplayWindow()

	w.Check(0)
	w.Check(1)
	w.Check(2)

	// Large jump — should accept and reset bitmap
	if !w.Check(1000) {
		t.Error("large jump should be accepted")
	}
	if w.top() != 1000 {
		t.Errorf("Top after jump: got %d, want 1000", w.top())
	}

	// Old SeqNos should be rejected (outside window after jump)
	if w.Check(0) {
		t.Error("old SeqNo after large jump should be rejected")
	}
}

func TestReplayWindow_WindowBoundary(t *testing.T) {
	w := NewReplayWindow()

	// Fill window with 0..63
	for i := uint32(0); i < 64; i++ {
		w.Check(i)
	}

	// All within window should be rejected (duplicates)
	for i := uint32(0); i < 64; i++ {
		if w.Check(i) {
			t.Errorf("duplicate %d should be rejected", i)
		}
	}

	// 64 should advance window
	if !w.Check(64) {
		t.Error("64 should advance window")
	}

	// 0 is now outside window (64 - 0 = 64 >= ReplayWindowSize)
	if w.Check(0) {
		t.Error("0 should be outside window after advance to 64")
	}
}

func TestReplayWindow_Reset(t *testing.T) {
	w := NewReplayWindow()
	w.Check(50)
	w.reset()

	// After reset, same SeqNo should be accepted
	if !w.Check(50) {
		t.Error("after reset, previously seen SeqNo should be accepted")
	}
}
