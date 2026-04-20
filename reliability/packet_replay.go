/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package reliability

import "sync"

// PacketReplayWindowSize is the packet-level replay window (128 packets).
// Larger than the per-stream window (64) since packets span all streams.
const PacketReplayWindowSize = 128

// PacketReplayWindow implements packet-level anti-replay protection.
// Keyed by ConnectionID + PacketSeq — operates BEFORE stream demultiplexing.
// This catches replayed encrypted UDP packets at the transport layer,
// separate from the per-stream SeqNo replay window which operates at
// the application layer.
//
// Design matches the per-stream ReplayWindow but with a larger window
// and scoped to the entire connection (all streams combined).
type PacketReplayWindow struct {
	mu     sync.Mutex
	bitmap [2]uint64 // 128-bit bitmap of received packet sequences
	topSeq uint64    // highest accepted packet sequence
	inited bool
}

// NewPacketReplayWindow creates a packet-level replay window.
func NewPacketReplayWindow() *PacketReplayWindow {
	return &PacketReplayWindow{}
}

// Check returns true if the packet sequence is acceptable (not replayed).
// If acceptable, marks the sequence as seen. Thread-safe.
//
// Rules:
//   - seq > top: advance window, accept
//   - top - 127 <= seq <= top: check bitmap, accept if not seen
//   - seq < top - 127: reject (too old)
func (w *PacketReplayWindow) Check(seq uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.inited {
		w.topSeq = seq
		w.setBit(0)
		w.inited = true
		return true
	}

	if seq > w.topSeq {
		diff := seq - w.topSeq
		if diff >= PacketReplayWindowSize {
			// Jump beyond window — reset
			w.bitmap = [2]uint64{}
			w.setBit(0)
		} else {
			// Shift bitmap
			w.shiftLeft(diff)
			w.setBit(0)
		}
		w.topSeq = seq
		return true
	}

	// seq <= top
	diff := w.topSeq - seq
	if diff >= PacketReplayWindowSize {
		return false // too old
	}

	// Check if already seen
	if w.getBit(diff) {
		return false // duplicate
	}

	w.setBit(diff)
	return true
}

// top returns the highest accepted packet sequence.
func (w *PacketReplayWindow) top() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.topSeq
}

// reset clears the window.
func (w *PacketReplayWindow) reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.bitmap = [2]uint64{}
	w.topSeq = 0
	w.inited = false
}

// setBit sets the bit at position pos (0 = MSB of top).
func (w *PacketReplayWindow) setBit(pos uint64) {
	if pos < 64 {
		w.bitmap[0] |= 1 << pos
	} else if pos < 128 {
		w.bitmap[1] |= 1 << (pos - 64)
	}
}

// getBit returns true if the bit at position pos is set.
func (w *PacketReplayWindow) getBit(pos uint64) bool {
	if pos < 64 {
		return w.bitmap[0]&(1<<pos) != 0
	} else if pos < 128 {
		return w.bitmap[1]&(1<<(pos-64)) != 0
	}
	return false
}

// shiftLeft shifts the 128-bit bitmap left by n positions.
func (w *PacketReplayWindow) shiftLeft(n uint64) {
	if n >= 128 {
		w.bitmap = [2]uint64{}
		return
	}
	if n >= 64 {
		w.bitmap[1] = w.bitmap[0] << (n - 64)
		w.bitmap[0] = 0
		return
	}
	w.bitmap[1] = (w.bitmap[1] << n) | (w.bitmap[0] >> (64 - n))
	w.bitmap[0] <<= n
}
