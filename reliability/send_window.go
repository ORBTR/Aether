/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package reliability

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/congestion"
)

// Caps preventing CPU exhaustion from malicious Composite ACK frames.
// An attacker post-authentication could otherwise craft an ACK that pins
// the send CPU for seconds by claiming a huge cumulative jump or range.
// See _SECURITY.md §3.2.
const (
	// MaxACKCumulativeJump caps the distance between the current send-window
	// base and ack.BaseACK. A normal peer's BaseACK advances by small numbers
	// per ACK; jumps larger than this are rejected.
	//
	// Sized so a peer recovering from a stall (catching up after a
	// multi-second wedge) can send a cumulative ACK covering thousands
	// of seq numbers without tripping the validator. Set at
	// sendWindow.maxSize × 2 — still well below the 2^31 attack
	// threshold but big enough to absorb realistic recovery backlogs.
	// At too-tight ceilings, every recovery ACK is rejected as
	// "suspicious" and the sender's window stays stuck forever.
	MaxACKCumulativeJump uint32 = 65536

	// MaxACKRangeSize caps the size of any ExtRange / DroppedRange block.
	MaxACKRangeSize uint32 = 1024
)

// Allowed bitmap byte lengths for Composite ACK payloads.
// Any other length is a protocol violation.
var validBitmapLens = map[int]bool{0: true, 4: true, 8: true, 16: true, 32: true}

// SendEntry tracks an in-flight frame waiting for acknowledgment.
type SendEntry struct {
	Frame   *aether.Frame
	SentAt  time.Time
	Retries int
	Acked   bool

	// XmitTime is the wall-clock time of the most recent transmission of
	// this entry. Equal to SentAt at first send; updated to time.Now() by
	// BumpXmitTime when the adapter retransmits. RACK loss detection
	// (RFC 8985) consults XmitTime — not SentAt — to decide whether a
	// frame is older than the receiver's most recent delivery and thus
	// presumed lost. Without this distinction RACK would mark every
	// retransmitted frame as lost again on the very first tick.
	XmitTime time.Time

	// BBRv2 per-packet delivery-rate sample. Stamped at send time by the
	// adapter via congestion.BBRController.OnSend, read back by the
	// adapter when the matching ACK arrives so it can call OnAckSampled
	// instead of the degraded OnAck path. Pointer (rather than value)
	// so a nil read distinguishes "no sample stamped" (CUBIC active,
	// not BBR) from "zero-value sample" without a type assertion.
	BBRSample *congestion.DeliveryRateSample
}

// SendWindow tracks unacknowledged frames on the sender side.
// Frames are added with sequential SeqNos and removed when ACKed.
type SendWindow struct {
	mu      sync.Mutex
	entries map[uint32]*SendEntry // SeqNo → entry
	base    uint32                // oldest unacked SeqNo
	next    uint32                // next SeqNo to assign
	maxSize int                   // max unacked frames

	// Atomic counter of Composite ACKs rejected due to validation failures
	// (out-of-range BaseACK jump, oversized range, invalid bitmap length).
	// See _SECURITY.md §3.2.
	suspiciousACKs uint64

	// Atomic counter of ACKs silently no-op'd because BaseACK < base
	// (stale / reordered ACK against an already-advanced send window).
	// Surfaced via StaleBaseACKsCount() so a high stale-ACK rate after
	// reorder doesn't manifest as silent ACK starvation with no signal.
	staleBaseACKs uint64

	// sessionInFlight, if non-nil, is updated on every Add/remove so a
	// session-level atomic counter reflects the total in-flight bytes
	// across all of the session's SendWindows. Lets the writeLoop's
	// CanSend check be a single atomic.Load instead of an O(streams)
	// lock walk per send.
	//
	// Consistency model: every mutation of w.entries happens under w.mu,
	// and the counter update happens under the same lock — readers via
	// atomic.Load may see a slightly stale value when concurrent
	// modifications race, but the absolute total is eventually correct
	// and never under-reports (the CanSend gate is conservative anyway).
	sessionInFlight *atomic.Int64
}

// SetSessionInFlightCounter wires this SendWindow into a session-level
// atomic that aggregates in-flight bytes across all of the session's
// streams. Subsequent Add/Ack operations update this counter as a
// side effect. Pass nil to disable (default).
//
// Must be called BEFORE any Add — otherwise the counter will under-
// report by the size of the pre-wired frames. Adapter call sites wire
// this in createStream right after NewSendWindow.
func (w *SendWindow) SetSessionInFlightCounter(c *atomic.Int64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.sessionInFlight = c
}

// addInFlightLocked / subInFlightLocked update the optional session
// counter. Both must be called under w.mu (the SendWindow lock) so the
// counter update is sequenced with the corresponding entries-map
// mutation. The session-level reader is a lock-free atomic.Load so
// these can use a non-blocking Add even without holding w.mu — but
// keeping the call inside the lock keeps the consistency invariant
// "counter == sum of entries[*].on-wire-size" trivially provable for
// any moment where w.mu is held.
func (w *SendWindow) addInFlightLocked(frame *aether.Frame) {
	if w.sessionInFlight == nil || frame == nil {
		return
	}
	w.sessionInFlight.Add(int64(aether.HeaderSize) + int64(frame.Length))
}

func (w *SendWindow) subInFlightLocked(entry *SendEntry) {
	if w.sessionInFlight == nil || entry == nil || entry.Frame == nil {
		return
	}
	w.sessionInFlight.Add(-(int64(aether.HeaderSize) + int64(entry.Frame.Length)))
}

// removeEntryLocked deletes seq from w.entries, decrementing the
// optional session inflight counter by the entry's on-wire size before
// the delete. No-op if seq isn't present. Centralises the
// counter+delete invariant so future removal call sites stay
// consistent.
func (w *SendWindow) removeEntryLocked(seq uint32) (*SendEntry, bool) {
	entry, ok := w.entries[seq]
	if !ok {
		return nil, false
	}
	w.subInFlightLocked(entry)
	delete(w.entries, seq)
	return entry, true
}

// SuspiciousACKsCount returns the number of Composite ACKs rejected
// because they failed sanity checks (ACK CPU-exhaustion defence).
func (w *SendWindow) SuspiciousACKsCount() uint64 {
	return atomic.LoadUint64(&w.suspiciousACKs)
}

// StaleBaseACKsCount returns the number of Composite ACKs silently
// no-op'd because BaseACK < base (stale / reordered).
func (w *SendWindow) StaleBaseACKsCount() uint64 {
	return atomic.LoadUint64(&w.staleBaseACKs)
}

// NewSendWindow creates a send window with the given maximum size.
func NewSendWindow(maxSize int) *SendWindow {
	return &SendWindow{
		entries: make(map[uint32]*SendEntry),
		maxSize: maxSize,
	}
}

// Add stores a frame in the window and assigns the next SeqNo.
// Returns the assigned SeqNo. The frame's SeqNo field is updated in-place.
func (w *SendWindow) Add(frame *aether.Frame) uint32 {
	seq, _ := w.AddEntry(frame)
	return seq
}

// AddEntry is like Add but also returns the live *SendEntry so callers
// (e.g. RetransmitQueue.EnqueueFromSend) can share the allocation
// instead of building a parallel record with the same frame pointer.
// The returned entry remains owned by the SendWindow; ACK paths may
// clear it and callers must not retain the pointer past an Ack/Drop.
func (w *SendWindow) AddEntry(frame *aether.Frame) (uint32, *SendEntry) {
	w.mu.Lock()
	defer w.mu.Unlock()

	seq := w.next
	frame.SeqNo = seq
	now := time.Now()
	entry := &SendEntry{
		Frame:    frame,
		SentAt:   now,
		XmitTime: now,
	}
	w.entries[seq] = entry
	w.addInFlightLocked(frame)
	w.next++
	return seq, entry
}

// BumpXmitTime updates XmitTime on the entry for seq to t. Called by the
// adapter immediately before re-enqueuing a retransmit so RACK's loss
// detector (RFC 8985 §6.2) sees the freshest transmission timestamp and
// doesn't repeatedly mark a just-retransmitted frame as lost.
//
// No-op if seq is no longer in the window (already ACKed). Safe to call
// from the reliability tick — single-mutex acquisition.
func (w *SendWindow) BumpXmitTime(seq uint32, t time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if entry, ok := w.entries[seq]; ok {
		entry.XmitTime = t
		entry.Retries++
	}
}

// SnapshotEntries returns a copy of all in-flight (seq, XmitTime) pairs
// for RACK iteration. The caller iterates without holding any locks
// (RACK only needs xmit times, not the underlying frames). Allocates a
// fresh slice each call — RACK is invoked once per reliability tick on
// streams with InFlight > 0, so allocation overhead is bounded.
func (w *SendWindow) SnapshotEntries() []SnapshotEntry {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]SnapshotEntry, 0, len(w.entries))
	for seq, e := range w.entries {
		out = append(out, SnapshotEntry{Seq: seq, XmitTime: e.XmitTime, Retries: e.Retries})
	}
	return out
}

// SnapshotEntry is a lock-free view of an in-flight frame's metadata
// for RACK loss detection. Holds no live pointers into the SendWindow
// so the caller can iterate without contending with handleACK or Add.
type SnapshotEntry struct {
	Seq      uint32
	XmitTime time.Time
	Retries  int
}

// Ack marks a single SeqNo as acknowledged and returns the entry (for RTT calculation).
// Returns nil if the SeqNo is not in the window.
func (w *SendWindow) Ack(seqNo uint32) *SendEntry {
	w.mu.Lock()
	defer w.mu.Unlock()

	entry, ok := w.entries[seqNo]
	if !ok {
		return nil
	}
	entry.Acked = true
	w.subInFlightLocked(entry)
	delete(w.entries, seqNo)

	// Advance base past all acked entries
	for {
		if _, exists := w.entries[w.base]; !exists && w.base < w.next {
			w.base++
		} else {
			break
		}
	}

	return entry
}

// AckRange marks all SeqNos in [start, end] inclusive as acknowledged.
// Returns the count of newly acknowledged entries.
//
// Wrap-attack defence: end may be ^uint32(0) (0xFFFFFFFF) from a
// malicious or buggy peer; the naive `for seq := start; seq <= end; seq++`
// then never terminates because seq wraps to 0 and continues to satisfy
// `seq <= end` forever (was M-AckRange-Wrap-Loop). Cap the iteration
// at maxAckRangeSpan entries — a real cumulative ACK never covers
// that many seqs in one frame; anything larger is corruption or attack.
func (w *SendWindow) AckRange(start, end uint32) int {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Compute span using wrap-safe arithmetic. uint32 subtraction handles
	// the wrap naturally; we then bound the result.
	span := uint64(end - start)
	if span > maxAckRangeSpan {
		return 0
	}
	count := 0
	seq := start
	for i := uint64(0); i <= span; i++ {
		if entry, ok := w.entries[seq]; ok {
			entry.Acked = true
			w.subInFlightLocked(entry)
			delete(w.entries, seq)
			count++
		}
		seq++
	}

	// Advance base
	for {
		if _, exists := w.entries[w.base]; !exists && w.base < w.next {
			w.base++
		} else {
			break
		}
	}

	return count
}

// maxAckRangeSpan caps the number of seq numbers a single AckRange call
// may iterate. A real cumulative ACK covers at most "all in-flight"
// which is bounded by SendWindow.maxSize (typically 4096); 65536 gives
// 16x headroom for adapter-specific oversizing while still rejecting
// the 4-billion-entry wrap-attack input.
const maxAckRangeSpan uint64 = 65536

// GetEntry returns the entry for a specific SeqNo (for retransmission by Composite ACK implicit NACK).
// Returns nil if the SeqNo is not in the window.
func (w *SendWindow) GetEntry(seqNo uint32) *SendEntry {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.entries[seqNo]
}

// ProcessCompositeACK processes a Composite ACK frame.
// Returns: (newlyAckedEntries, implicitNacks).
// - acked: entries that were just acknowledged (for RTT sampling).
// - nacks: SeqNos where bitmap bit=0 AND (largestAcked - seqNo) >= reorderThreshold.
//
// Steps:
// 1. Cumulative ACK: remove all entries with SeqNo <= baseACK.
// 2. Bitmap: for each bit position, ACK or mark as implicit NACK.
// 3. Extended ranges: ACK all entries in each range.
// 4. Dropped ranges: permanently remove entries (no retransmit).
func (w *SendWindow) ProcessCompositeACK(ack *aether.CompositeACK, reorderThreshold int) (acked []*SendEntry, nacks []uint32) {
	// Validate bitmap length per spec: must be one of {0, 4, 8, 16, 32}
	// bytes (i.e. {0, 32, 64, 128, 256} bits). Reject otherwise to prevent
	// attacker-controlled scan loops. See _SECURITY.md §3.2.
	if !validBitmapLens[len(ack.Bitmap)] {
		atomic.AddUint64(&w.suspiciousACKs, 1)
		return nil, nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	// Reject BaseACK that's more than MaxACKCumulativeJump beyond the
	// current base. A well-behaved peer never jumps this far in one ACK.
	// Attacker use: BaseACK = base + 2^31 would force a ~2B-iteration loop.
	// Use uint32 subtraction to detect both forward overshoot and any
	// negative jump (which would wrap to a huge value).
	if ack.BaseACK >= w.base {
		if ack.BaseACK-w.base > MaxACKCumulativeJump {
			atomic.AddUint64(&w.suspiciousACKs, 1)
			return nil, nil
		}
	} else {
		// BaseACK before our base — stale or bogus, ignore but don't flag
		// as suspicious (can legitimately happen with reordered ACKs).
		// Count separately for observability — bursts of stale ACKs
		// during a wedge are diagnostic.
		atomic.AddUint64(&w.staleBaseACKs, 1)
		return nil, nil
	}

	// 1. Cumulative ACK (bounded by MaxACKCumulativeJump)
	for seq := w.base; seq <= ack.BaseACK; seq++ {
		if entry, ok := w.entries[seq]; ok {
			entry.Acked = true
			acked = append(acked, entry)
			w.subInFlightLocked(entry)
			delete(w.entries, seq)
		}
	}
	// Advance base
	for {
		if _, exists := w.entries[w.base]; !exists && w.base < w.next {
			w.base++
		} else {
			break
		}
	}

	// 2. Bitmap scan
	if len(ack.Bitmap) > 0 {
		windowBits := len(ack.Bitmap) * 8
		var largestAcked uint32 = ack.BaseACK

		// First pass: find largestAcked for reorder threshold
		for i := 0; i < windowBits; i++ {
			seqNo := ack.BaseACK + 1 + uint32(i)
			// AE-H-09: bits at/beyond largestSent must not inflate largestAcked;
			// a peer setting a high bit could otherwise widen the NACK range.
			if seqNo >= w.next {
				break
			}
			if ack.Bitmap[i/8]&(1<<(uint(i)%8)) != 0 {
				if seqNo > largestAcked {
					largestAcked = seqNo
				}
			}
		}

		// Second pass: ACK received, detect implicit NACKs
		for i := 0; i < windowBits; i++ {
			seqNo := ack.BaseACK + 1 + uint32(i)
			if seqNo >= w.next {
				break // beyond what we've sent
			}

			if ack.Bitmap[i/8]&(1<<(uint(i)%8)) != 0 {
				// bit=1: received
				if entry, ok := w.entries[seqNo]; ok {
					entry.Acked = true
					acked = append(acked, entry)
					w.subInFlightLocked(entry)
					delete(w.entries, seqNo)
				}
			} else {
				// bit=0: missing — implicit NACK if reorder threshold met.
				// AE-H-09: require seqNo strictly below largestAcked. Without
				// this guard an in-flight seq above the highest SACKed seq makes
				// largestAcked-seqNo underflow uint32 to ~4e9, which widens to a
				// large positive int (>= reorderThreshold) and spuriously NACKs
				// the whole in-flight tail — a fast-retransmit storm plus a false
				// congestion loss signal on every gapped ACK.
				if _, ok := w.entries[seqNo]; ok {
					if seqNo < largestAcked && int(largestAcked-seqNo) >= reorderThreshold {
						nacks = append(nacks, seqNo)
					}
				}
			}
		}
	}

	// 3. Extended ranges — must NOT overlap bitmap window. Each range is
	// also capped at MaxACKRangeSize to prevent CPU exhaustion from a
	// crafted block with Start=0, End=0xFFFFFFFF. (§3.2 / S1)
	bitmapEnd := ack.BaseACK + uint32(len(ack.Bitmap)*8)
	for _, block := range ack.ExtRanges {
		if block.Start <= bitmapEnd {
			continue // overlaps bitmap window — ignore (spec violation by receiver)
		}
		if block.End >= w.next {
			// End at/beyond largestSent is meaningless (we hold no entries
			// there) and, critically, unbounded: End=0xFFFFFFFF makes the
			// `seq <= block.End` loop below non-terminating because seq++
			// wraps 0xFFFFFFFF→0 and stays <= End forever, spinning at 100%
			// CPU while holding w.mu — one crafted frame wedges the session.
			// This is the same upper-bound scope guard the DroppedRanges loop
			// applies (block.End >= w.next). (§3.2 / S1 — AE-C-02)
			atomic.AddUint64(&w.suspiciousACKs, 1)
			continue
		}
		if block.End < block.Start {
			atomic.AddUint64(&w.suspiciousACKs, 1)
			continue
		}
		if block.End-block.Start > MaxACKRangeSize {
			atomic.AddUint64(&w.suspiciousACKs, 1)
			continue
		}
		for seq := block.Start; seq <= block.End; seq++ {
			if entry, ok := w.entries[seq]; ok {
				entry.Acked = true
				acked = append(acked, entry)
				w.subInFlightLocked(entry)
				delete(w.entries, seq)
			}
		}
	}

	// 4. Dropped ranges — permanently remove (never retransmit)
	// Scope validation: must fall within (BaseACK, largestSent] AND be
	// bounded in size to prevent mass-drop amplification. (§3.2 / S1)
	for _, block := range ack.DroppedRanges {
		if block.Start <= ack.BaseACK || block.End >= w.next {
			continue // out of scope — ignore (prevents malicious mass-drop)
		}
		if block.End < block.Start {
			atomic.AddUint64(&w.suspiciousACKs, 1)
			continue
		}
		if block.End-block.Start > MaxACKRangeSize {
			atomic.AddUint64(&w.suspiciousACKs, 1)
			continue
		}
		for seq := block.Start; seq <= block.End; seq++ {
			w.removeEntryLocked(seq)
		}
	}

	// Advance base again after all removals
	for {
		if _, exists := w.entries[w.base]; !exists && w.base < w.next {
			w.base++
		} else {
			break
		}
	}

	return acked, nacks
}

// Expired returns all entries that have been in-flight longer than the
// given RTO. These are candidates for retransmission.
//
// Uses XmitTime (most-recent-send) not SentAt (original-send) so a
// frame that's already been retransmitted doesn't re-trip Expired the
// next tick before the new attempt has had a chance to ACK. SentAt
// stays the original timestamp for diagnostics; XmitTime is the value
// the dedicated BumpXmitTime path was added to maintain (was the
// H-Reliability-Expired finding — Expired against SentAt produced a
// retransmit storm under sustained loss).
func (w *SendWindow) Expired(rto time.Duration) []*SendEntry {
	w.mu.Lock()
	defer w.mu.Unlock()

	now := time.Now()
	var expired []*SendEntry
	for _, entry := range w.entries {
		if entry.Acked {
			continue
		}
		ref := entry.XmitTime
		if ref.IsZero() {
			ref = entry.SentAt
		}
		if now.Sub(ref) > rto {
			expired = append(expired, entry)
		}
	}
	return expired
}

// IsFull returns true if the window has reached its maximum size.
func (w *SendWindow) IsFull() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.entries) >= w.maxSize
}

// InFlight returns the number of unacknowledged frames.
func (w *SendWindow) InFlight() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.entries)
}

// InFlightBytes returns the on-wire size of all unacknowledged frames in
// this window (sum of HeaderSize + Frame.Length per entry).
//
// Callers MUST sum InFlightBytes() across the session's live streams and
// pass that plus the prospective frameSize into CUBIC.CanSend — CUBIC's
// contract is `inFlight < cwnd`, so a per-frame call with frameSize
// alone would return true unconditionally and bypass congestion control.
// Preferred fast path is the session's sessionInFlight atomic counter
// (wired via SetSessionInFlightCounter); this method exists for callers
// that need the precise per-window total.
//
// O(entries) per call under the SendWindow lock — entries count is
// bounded by maxSize (typically a few hundred).
func (w *SendWindow) InFlightBytes() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	var total int64
	for _, e := range w.entries {
		if e.Frame == nil {
			continue
		}
		total += int64(aether.HeaderSize) + int64(e.Frame.Length)
	}
	return total
}

// Base returns the oldest unacked SeqNo.
func (w *SendWindow) Base() uint32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.base
}

// Next returns the next SeqNo that will be assigned.
func (w *SendWindow) Next() uint32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.next
}
