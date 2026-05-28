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
// See _SECURITY.md §3.3.
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

// CheckResult classifies the outcome of a SeqNo replay check so the
// caller can distinguish a legitimate retransmit (drop silently, no
// abuse) from a genuinely anomalous event (drop AND feed the abuse
// tracker). Three reject reasons are kept separate because they have
// fundamentally different security implications.
type CheckResult int

const (
	// ResultNew — this SeqNo has not been seen. Accept + advance window.
	// Caller should deliver the frame to the reliability layer.
	ResultNew CheckResult = iota

	// ResultDuplicate — SeqNo is within the recent window AND already
	// marked as seen. This is what happens when the sender's reliability
	// layer retransmits a frame whose original copy already arrived (a
	// completely normal occurrence under any non-zero packet loss). The
	// caller MUST drop the frame silently but MUST NOT feed the abuse
	// score — retransmissions are protocol-correct, not adversarial.
	//
	// Conflating this with the genuine-replay cases was the churn root
	// cause: on every lossy path, the reliability layer's natural
	// retransmits accumulated `replay-detected` abuse points until the
	// abuse threshold tripped and the session was closed (typically
	// ~28 s in observation). Sessions short-lived under retransmission
	// produced the rising-churn pattern we tracked through v0.0.308 →
	// v0.0.310.
	ResultDuplicate

	// ResultAncient — SeqNo is below the bottom of the sliding window
	// (`top - ReplayWindowSize` or older). A legitimate retransmit
	// cannot land this far behind — the reliability layer doesn't keep
	// frames around long enough. Either a buggy/malicious peer is
	// replaying an old frame or the window has been deliberately
	// skipped past. Drop AND report abuse.
	ResultAncient

	// ResultWrapAttack — SeqNo jumped past half the uint32 SeqNo space,
	// which a legitimate sender never does inside one rekey window
	// (RekeyAfterBytes ≈ 1 M frames < 2 B SeqNos). Drop AND report
	// abuse. See _SECURITY.md §3.3.
	ResultWrapAttack
)

// String returns a short label suitable for logs / metrics.
func (r CheckResult) String() string {
	switch r {
	case ResultNew:
		return "new"
	case ResultDuplicate:
		return "duplicate"
	case ResultAncient:
		return "ancient"
	case ResultWrapAttack:
		return "wrap-attack"
	default:
		return "unknown"
	}
}

// IsAccept reports whether the caller should treat the frame as
// acceptable (deliver to reliability layer). True only for ResultNew.
func (r CheckResult) IsAccept() bool {
	return r == ResultNew
}

// IsAbuse reports whether the caller should feed the abuse tracker.
// True for ResultAncient and ResultWrapAttack; false for ResultDuplicate
// (legitimate retransmit, not adversarial).
func (r CheckResult) IsAbuse() bool {
	return r == ResultAncient || r == ResultWrapAttack
}

// CheckV2 classifies a SeqNo for delivery + abuse decisions. Marks the
// SeqNo as seen on ResultNew (advancing the window). On all other
// results the window state is unchanged. Thread-safe.
//
// Replaces Check() — old callers that only need a bool can use
// `Check(seq)` which is preserved as a thin wrapper that conflates
// reject reasons (kept for back-compat in tests; production hot path
// should switch to CheckV2 so abuse scoring stays accurate under
// normal retransmission).
//
// Rules:
//   - SeqNo > top by more than SeqNoWrapThreshold → ResultWrapAttack
//   - SeqNo > top, within wrap threshold → advance, ResultNew
//   - top - 63 <= SeqNo <= top, bitmap-bit clear → mark seen, ResultNew
//   - top - 63 <= SeqNo <= top, bitmap-bit set → ResultDuplicate
//   - SeqNo < top - 63 → ResultAncient
func (w *ReplayWindow) CheckV2(seqNo uint32) CheckResult {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.inited {
		w.topSeq = seqNo
		w.bitmap = 1 // mark seqNo as seen (bit 0)
		w.inited = true
		return ResultNew
	}

	if seqNo > w.topSeq {
		// Advance window
		diff := seqNo - w.topSeq
		// Reject jumps past half the SeqNo space — likely a uint32
		// wraparound attack rather than a legitimate forward step.
		// (S8 — see _SECURITY.md §3.3.)
		if diff > SeqNoWrapThreshold {
			atomic.AddUint64(&w.wrapsDetected, 1)
			return ResultWrapAttack
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
		return ResultNew
	}

	// seqNo <= top — check if within window
	diff := w.topSeq - seqNo
	if diff >= ReplayWindowSize {
		return ResultAncient // too old — outside window, cannot be a legitimate retransmit
	}

	// Check if already seen
	bit := uint64(1) << diff
	if w.bitmap&bit != 0 {
		return ResultDuplicate // already seen — almost always a legitimate retransmit
	}

	// Mark as seen
	w.bitmap |= bit
	return ResultNew
}

// Check returns true if the SeqNo is acceptable (not a replay).
// Thin wrapper around CheckV2 that conflates ResultDuplicate /
// ResultAncient / ResultWrapAttack into a single false. Kept for
// callers that don't need the result classification. Production code
// that drives abuse scoring should call CheckV2 directly so legitimate
// retransmits don't get charged as adversarial replays.
func (w *ReplayWindow) Check(seqNo uint32) bool {
	return w.CheckV2(seqNo) == ResultNew
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
