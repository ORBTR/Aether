/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package reliability

import "testing"

func TestPacketReplay_Sequential(t *testing.T) {
	w := NewPacketReplayWindow()
	for i := uint64(0); i < 200; i++ {
		if !w.Check(i) {
			t.Fatalf("sequential packet %d rejected", i)
		}
	}
}

func TestPacketReplay_Duplicate(t *testing.T) {
	w := NewPacketReplayWindow()
	if !w.Check(10) {
		t.Fatal("first occurrence should be accepted")
	}
	if w.Check(10) {
		t.Fatal("duplicate should be rejected")
	}
}

func TestPacketReplay_OutOfOrder(t *testing.T) {
	w := NewPacketReplayWindow()
	// Accept in scrambled order
	w.Check(5)
	w.Check(3)
	w.Check(7)
	w.Check(1)

	// Duplicates should be rejected
	if w.Check(5) {
		t.Fatal("duplicate 5 should be rejected")
	}
	if w.Check(3) {
		t.Fatal("duplicate 3 should be rejected")
	}

	// New packets should be accepted
	if !w.Check(10) {
		t.Fatal("new packet 10 should be accepted")
	}
}

func TestPacketReplay_TooOld(t *testing.T) {
	w := NewPacketReplayWindow()

	// Advance to 200
	w.Check(200)

	// Packet 200 - 128 = 72 should still be in window
	if !w.Check(73) {
		t.Fatal("packet 73 should be within 128-window of 200")
	}

	// Packet way behind the window should be rejected
	if w.Check(10) {
		t.Fatal("packet 10 should be too old (>128 behind top=200)")
	}
}

func TestPacketReplay_LargeJump(t *testing.T) {
	w := NewPacketReplayWindow()

	w.Check(0)
	w.Check(1)

	// Large jump forward
	if !w.Check(1000) {
		t.Fatal("large jump should be accepted")
	}

	// Old packets now far behind should be rejected
	if w.Check(0) {
		t.Fatal("packet 0 should be too old after jump to 1000")
	}
	if w.Check(1) {
		t.Fatal("packet 1 should be too old after jump to 1000")
	}
}

func TestPacketReplay_WindowBoundary(t *testing.T) {
	w := NewPacketReplayWindow()

	// Set top to exactly PacketReplayWindowSize
	w.Check(PacketReplayWindowSize)

	// Packet at bottom edge of window (top - 127) should be accepted
	bottomEdge := uint64(PacketReplayWindowSize) - uint64(PacketReplayWindowSize-1)
	if !w.Check(bottomEdge) {
		t.Fatalf("bottom edge packet %d should be accepted", bottomEdge)
	}

	// One below bottom edge should be rejected
	if w.Check(0) {
		t.Fatal("packet 0 should be below window bottom")
	}
}

func TestPacketReplay_128BitWidth(t *testing.T) {
	w := NewPacketReplayWindow()

	// Fill 128 consecutive packets
	for i := uint64(0); i < 128; i++ {
		if !w.Check(i) {
			t.Fatalf("packet %d should be accepted in 128-bit window", i)
		}
	}

	// All should now be duplicates
	for i := uint64(0); i < 128; i++ {
		if w.Check(i) {
			t.Fatalf("packet %d should be duplicate", i)
		}
	}
}
