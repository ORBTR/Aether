/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package reliability

import (
	"sync"
	"sync/atomic"
)

// ReplayWindowSize is the number of sequence numbers tracked in the sliding window.
const ReplayWindowSize = 64

// SeqNoWrapThreshold is the maximum legitimate forward jump in one step.
// Per-stream rekey happens long before this (RekeyAfterBytes = 1 GiB ≈ 1M
// frames), so any jump past ~2B SeqNos is a wraparound attack — the uint32
// space is 4B, half of that is definitely forged.
// See _SECURITY.md §3.3 / plan item S8.
const SeqNoWrapThreshold uint32 = 1 << 31

// ReplayWindow implements a sliding window for anti-replay protection.
// Tracks which SeqNos have been seen and rejects duplicates or out-of-window frames.
// Per-stream scope — each stream has its own replay window.
//
// Design matches Noise transport's nonceWindow for consistency.
type ReplayWindow struct {
	mu             sync.Mutex
	bitmap         uint64 // 64-bit bitmap of received SeqNos relative to bottom
	topSeq         uint32 // highest accepted SeqNo
	inited         bool   // false until first frame
	wrapsDetected  uint64 // atomic: jumps > SeqNoWrapThreshold rejected as wrap attack
}

// NewReplayWindow creates an anti-replay window.
func NewReplayWindow() *ReplayWindow {
	return &ReplayWindow{}
}

// WrapsDetectedCount returns the number of suspiciously large forward jumps
// rejected as potential SeqNo-wraparound replay attacks.
func (w *ReplayWindow) WrapsDetectedCount() uint64 {
	return atomic.LoadUint64(&w.wrapsDetected)
}

// Check returns true if the SeqNo is acceptable (not a replay).
// If acceptable, marks the SeqNo as seen. If rejected (duplicate or too old),
// returns false. Thread-safe.
//
// Rules:
//   - SeqNo > top: advance window, accept
//   - top - 63 <= SeqNo <= top: check bitmap, accept if not seen, mark as seen
//   - SeqNo < top - 63: reject (too old)
func (w *ReplayWindow) Check(seqNo uint32) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.inited {
		w.topSeq = seqNo
		w.bitmap = 1 // mark seqNo as seen (bit 0)
		w.inited = true
		return true
	}

	if seqNo > w.topSeq {
		// Advance window
		diff := seqNo - w.topSeq
		// Reject jumps past half the SeqNo space — likely a uint32
		// wraparound attack rather than a legitimate forward step.
		// (S8 — see _SECURITY.md §3.3.)
		if diff > SeqNoWrapThreshold {
			atomic.AddUint64(&w.wrapsDetected, 1)
			return false
		}
		if diff >= ReplayWindowSize {
			// Jump beyond window — reset bitmap
			w.bitmap = 1
		} else {
			// Shift bitmap left by diff, set bit 0 for new seqNo
			w.bitmap <<= diff
			w.bitmap |= 1
		}
		w.topSeq = seqNo
		return true
	}

	// seqNo <= top — check if within window
	diff := w.topSeq - seqNo
	if diff >= ReplayWindowSize {
		return false // too old — outside window
	}

	// Check if already seen
	bit := uint64(1) << diff
	if w.bitmap&bit != 0 {
		return false // duplicate — already seen
	}

	// Mark as seen
	w.bitmap |= bit
	return true
}

// top returns the highest accepted SeqNo.
func (w *ReplayWindow) top() uint32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.topSeq
}

// reset clears the window state.
func (w *ReplayWindow) reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.bitmap = 0
	w.topSeq = 0
	w.inited = false
}
