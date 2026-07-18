/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
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
	duplicates     uint64 // atomic: total ResultDuplicate observations (legitimate retransmits)
	ancientDrops   uint64 // atomic: total ResultAncient observations (out-of-window)
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

// DuplicateCount returns the total number of ResultDuplicate observations
// since this window was created. Duplicates are SeqNos already seen
// within the recent sliding window — almost always legitimate
// retransmits from the sender's reliability layer when an ACK was lost
// or late. A high count signals a lossy reverse path (data → ACK
// direction) and is the most useful per-stream signal for distinguishing
// "path works but loses ACKs" from "path loses data". Operators reading
// dashboards / quality scorers consuming path signals should treat this
// as informational; it is NOT an abuse signal (see CheckResult).
func (w *ReplayWindow) DuplicateCount() uint64 {
	return atomic.LoadUint64(&w.duplicates)
}

// AncientDropCount returns the total number of ResultAncient observations
// since this window was created. SeqNos below the window bottom that a
// legitimate sender's reliability layer cannot produce. Distinguished
// from DuplicateCount because Ancient COULD indicate an attack (or a
// peer with broken send-window bookkeeping) while Duplicate does not.
// Surfaced separately so dashboards / abuse reviews can isolate the
// security-relevant signal.
func (w *ReplayWindow) AncientDropCount() uint64 {
	return atomic.LoadUint64(&w.ancientDrops)
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

// classifyLocked returns the CheckResult for seqNo WITHOUT mutating window
// state. Caller must hold w.mu.
//
// Rules:
//   - SeqNo > top by more than SeqNoWrapThreshold → ResultWrapAttack
//   - SeqNo > top, within wrap threshold → ResultNew
//   - top - 63 <= SeqNo <= top, bitmap-bit clear → ResultNew
//   - top - 63 <= SeqNo <= top, bitmap-bit set → ResultDuplicate
//   - SeqNo < top - 63 → ResultAncient
func (w *ReplayWindow) classifyLocked(seqNo uint32) CheckResult {
	if !w.inited {
		return ResultNew
	}
	if seqNo > w.topSeq {
		diff := seqNo - w.topSeq
		// Reject jumps past half the SeqNo space — likely a uint32
		// wraparound attack rather than a legitimate forward step.
		// (S8 — see _SECURITY.md §3.3.)
		if diff > SeqNoWrapThreshold {
			return ResultWrapAttack
		}
		return ResultNew
	}
	diff := w.topSeq - seqNo
	if diff >= ReplayWindowSize {
		return ResultAncient // too old — outside window, cannot be a legitimate retransmit
	}
	bit := uint64(1) << diff
	if w.bitmap&bit != 0 {
		return ResultDuplicate // already seen — almost always a legitimate retransmit
	}
	return ResultNew
}

// commitLocked marks seqNo as seen (advancing the window / setting the
// bitmap bit). Idempotent. Caller must hold w.mu. A wrap-attack seqNo is
// never committed.
func (w *ReplayWindow) commitLocked(seqNo uint32) {
	if !w.inited {
		w.topSeq = seqNo
		w.bitmap = 1 // mark seqNo as seen (bit 0)
		w.inited = true
		return
	}
	if seqNo > w.topSeq {
		diff := seqNo - w.topSeq
		if diff > SeqNoWrapThreshold {
			return // wrap-attack seq — do not advance the window
		}
		if diff >= ReplayWindowSize {
			w.bitmap = 1 // jump beyond window — reset bitmap
		} else {
			w.bitmap <<= diff
			w.bitmap |= 1
		}
		w.topSeq = seqNo
		return
	}
	diff := w.topSeq - seqNo
	if diff >= ReplayWindowSize {
		return // ancient — nothing to mark
	}
	w.bitmap |= (uint64(1) << diff)
}

// Classify returns the CheckResult for a SeqNo WITHOUT marking it seen.
// Bumps the observational counters for the observed condition. The caller
// commits acceptance via Commit only after the frame is durably buffered,
// so a frame dropped by a full reorder buffer is not marked seen — which
// would make every retransmit of it classify ResultDuplicate and be
// discarded forever (AER-061). Thread-safe.
func (w *ReplayWindow) Classify(seqNo uint32) CheckResult {
	w.mu.Lock()
	defer w.mu.Unlock()
	res := w.classifyLocked(seqNo)
	switch res {
	case ResultWrapAttack:
		atomic.AddUint64(&w.wrapsDetected, 1)
	case ResultAncient:
		atomic.AddUint64(&w.ancientDrops, 1)
	case ResultDuplicate:
		atomic.AddUint64(&w.duplicates, 1)
	}
	return res
}

// Commit marks seqNo as seen (advancing the window). Idempotent — a seq
// already inside the window and set is left unchanged. Thread-safe.
func (w *ReplayWindow) Commit(seqNo uint32) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.commitLocked(seqNo)
}

// Check returns true if the SeqNo is acceptable (not a replay), marking it
// seen when it is. Convenience for callers that always accept a new SeqNo
// and don't need to gate the mark on a downstream buffer insert. Production
// hot paths that can drop a frame after acceptance should Classify then
// Commit-on-success instead (AER-061).
func (w *ReplayWindow) Check(seqNo uint32) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	res := w.classifyLocked(seqNo)
	switch res {
	case ResultWrapAttack:
		atomic.AddUint64(&w.wrapsDetected, 1)
	case ResultAncient:
		atomic.AddUint64(&w.ancientDrops, 1)
	case ResultDuplicate:
		atomic.AddUint64(&w.duplicates, 1)
	case ResultNew:
		w.commitLocked(seqNo)
	}
	return res == ResultNew
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
