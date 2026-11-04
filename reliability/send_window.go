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
// ProcessCompositeACK rejects an ACK past either cap and counts it in
// suspiciousACKs.
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
//
// The fields after Frame and PayloadBytes change only under the window's lock,
// and an ACK path reads them from an entry the window has already removed, so
// handleACK reads them without a lock while the write loop may still hold the
// entry's Frame. Frame.SeqNo is the one Frame field that holds still; the write
// boundary rewrites Payload, Length and Flags.
type SendEntry struct {
	Frame *aether.Frame

	// SentAt is when the frame's first write began (MarkWritten); it is zero
	// while Written is false. handleACK takes an RTT sample only from a written
	// entry with no retransmit, so the interval a sample closes starts at a
	// transmission of that sequence.
	SentAt  time.Time
	Retries int
	Acked   bool

	// XmitTime is the wall-clock time of the most recent transmission of
	// this entry. MarkWritten sets it at each write; BumpXmitTime also sets it
	// when the adapter queues a retransmit, so the RACK tick does not declare
	// the same frame lost again while the retransmit waits for the write loop.
	// RACK loss detection (RFC 8985) consults XmitTime — not SentAt — to decide
	// whether a frame is older than the receiver's most recent delivery and thus
	// presumed lost. Without this distinction RACK would mark every
	// retransmitted frame as lost again on the very first tick.
	XmitTime time.Time

	// BBRv2 per-packet delivery-rate sample. Stamped by MarkWritten at the
	// frame's first write from the sample the adapter passes
	// (congestion.BBRController.StampSample), read back by the adapter when the
	// matching ACK arrives so it can call OnAckSampled instead of the degraded
	// OnAck path. Pointer (rather than value) so a nil read distinguishes "no
	// sample stamped" (CUBIC active, not BBR) from "zero-value sample" without
	// a type assertion.
	BBRSample *congestion.DeliveryRateSample

	// PayloadBytes is Frame.Length as AddEntry found it, the plaintext the
	// sender handed over. The adapter passes it to RetransmitQueue.EnqueueSized
	// at the first write, by which time Frame.Length holds the committed form.
	PayloadBytes int64

	// Written reports that MarkWritten ran for this entry. RACK, TLP, a peer's
	// NACK and the RTT sample consider only written entries: a frame still in
	// the scheduler has no transmission for any of them to reason about.
	Written bool

	// InFlightBytes is the frame's wire length at its first write, the bytes
	// conn.Write took, and the count the session's in-flight counter
	// (sessionInFlight) was charged. It is 0 until then, so an entry that leaves
	// the window unwritten gives back nothing. Every removal subtracts this
	// field; the congestion controller's acked bytes read it; and a retransmit
	// presents it again whatever header form that write took, because the
	// controller was told this number once and removal gives back this number.
	InFlightBytes int64
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
	// Read through SuspiciousACKsCount(); the noise adapter's handleACK
	// charges abuse (ReasonACKValidation) when it rises across one ACK.
	suspiciousACKs uint64

	// Atomic counter of ACKs silently no-op'd because BaseACK < base
	// (stale / reordered ACK against an already-advanced send window).
	// Surfaced via StaleBaseACKsCount() so a high stale-ACK rate after
	// reorder doesn't manifest as silent ACK starvation with no signal.
	staleBaseACKs uint64

	// sessionInFlight, if non-nil, is the session's count of wire bytes in
	// flight: the sum over every entry of every SendWindow wired to it of
	// SendEntry.InFlightBytes. MarkWritten adds that count at the frame's first
	// write and every removal (Ack, AckRange, ProcessCompositeACK,
	// ReleaseInFlight) subtracts the same count, so the counter reads 0 whenever
	// no written entry remains, and a frame still queued behind the write loop's
	// gate holds none of it. The adapter's write loop reads it through one
	// atomic.Load for its CanSend gate, and handleACK and the RACK tick pass it
	// to the controller as the pipe; none walks the streams' windows under their
	// locks per send.
	//
	// Consistency model: every mutation of w.entries and of an entry's
	// Written and InFlightBytes happens under w.mu, and the counter update
	// happens under the same lock, so with no MarkWritten or removal
	// running the counter equals the sum of InFlightBytes over the entries
	// of the wired windows. Each window has its own lock, so several such
	// calls can run at once, and a reader's lock-free atomic.Load can read a
	// value that differs from that sum by the charges those calls are
	// completing.
	sessionInFlight *atomic.Int64

	// released is set by ReleaseInFlight and read by AddEntry, both under
	// w.mu: once the stream that owns this window has left its session's
	// stream map, no ACK path reaches the window again, so an entry added
	// after the release would be held for the session's life. The adapter's
	// noiseStream.Send checks the stream state before it calls Add and holds no
	// lock the Reset path shares, so a Send that passed that check before
	// Reset's state transition can reach Add after Reset's releaseInFlight; the
	// flag makes that Add store nothing, so its write charges nothing.
	released bool
}

// SetSessionInFlightCounter wires this SendWindow into a session-level
// atomic that aggregates in-flight bytes across all of the session's
// streams. Subsequent Add/Ack operations update this counter as a
// side effect. Pass nil to disable (default).
//
// Must be called BEFORE any MarkWritten — otherwise the counter will under-
// report by the size of the pre-wired frames. Adapter call sites wire
// this in createStream right after NewSendWindow.
func (w *SendWindow) SetSessionInFlightCounter(c *atomic.Int64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.sessionInFlight = c
}

// addInFlightLocked / subInFlightLocked charge and release the optional
// session counter by the entry's own InFlightBytes, the one count both
// sides of the entry's life use. Both must be called under w.mu (the
// SendWindow lock) so the counter update is sequenced with the
// corresponding entries-map mutation. The session-level reader is a
// lock-free atomic.Load so these can use a non-blocking Add even without
// holding w.mu — but keeping the call inside the lock keeps the
// consistency invariant "counter == sum of entries[*].InFlightBytes over
// the wired windows" trivially provable for any moment where w.mu is held.
func (w *SendWindow) addInFlightLocked(entry *SendEntry) {
	if w.sessionInFlight == nil || entry == nil {
		return
	}
	w.sessionInFlight.Add(entry.InFlightBytes)
}

func (w *SendWindow) subInFlightLocked(entry *SendEntry) {
	if w.sessionInFlight == nil || entry == nil {
		return
	}
	w.sessionInFlight.Add(-entry.InFlightBytes)
}

// removeEntryLocked deletes seq from w.entries, decrementing the
// optional session inflight counter by the entry's InFlightBytes before
// the delete. No-op if seq isn't present. A removal that calls it keeps
// the counter and the map in step without repeating the pair.
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
// After ReleaseInFlight the window stores nothing and the entry is nil.
func (w *SendWindow) AddEntry(frame *aether.Frame) (uint32, *SendEntry) {
	w.mu.Lock()
	defer w.mu.Unlock()

	seq := w.next
	frame.SeqNo = seq
	w.next++
	if w.released {
		// The window's stream has left its session (ReleaseInFlight ran):
		// no ACK path reaches this window again, so the frame is neither
		// stored nor charged to the session counter, and there is no entry
		// to return, as GetEntry would also find none for this seq. The
		// SeqNo is still assigned so the caller's frame stays well formed.
		// Engine.Send passes the entry on to RetransmitQueue.EnqueueFromSend,
		// which returns on nil; the adapter's sendSingleFrame reads the entry
		// back through GetEntry under a nil check.
		return seq, nil
	}
	entry := &SendEntry{
		Frame: frame,
		// Read here, before the write loop can commit the frame.
		PayloadBytes: int64(frame.Length),
	}
	w.entries[seq] = entry
	return seq, entry
}

// MarkWritten records that frame is going to conn.Write as wireBytes. The first
// call for an entry stamps SentAt, XmitTime and BBRSample and charges wireBytes to
// the session counter; a later call, a retransmit, moves XmitTime only, so the
// charge and the number the controller sees stay the first ones.
//
// It returns the entry's recorded wire count, its PayloadBytes, and whether this
// was the first write. A frame the window holds no entry for (acknowledged while
// queued, its stream gone, or a frame that was never Added) returns zeros and
// charges nothing. The entry is matched by pointer, not by SeqNo alone, because a
// frame beside the window (an FEC repair) can carry any SeqNo.
//
// The adapter's write loop calls it under writeMu before conn.Write, so an ACK
// that follows the write finds the charge already made.
func (w *SendWindow) MarkWritten(frame *aether.Frame, wireBytes int64, now time.Time, sample *congestion.DeliveryRateSample) (recorded, payload int64, first bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	entry, ok := w.entries[frame.SeqNo]
	if !ok || entry.Frame != frame {
		return 0, 0, false
	}
	entry.XmitTime = now
	if entry.Written {
		return entry.InFlightBytes, entry.PayloadBytes, false
	}
	entry.Written = true
	entry.SentAt = now
	entry.BBRSample = sample
	entry.InFlightBytes = wireBytes
	w.addInFlightLocked(entry)
	return wireBytes, entry.PayloadBytes, true
}

// RecordedWireBytes returns the wire count MarkWritten recorded for frame, or 0 if
// the frame has not been written or has left the window.
func (w *SendWindow) RecordedWireBytes(frame *aether.Frame) int64 {
	wire, _ := w.RecordedBytes(frame)
	return wire
}

// RecordedBytes returns the wire count MarkWritten recorded for frame, 0 before
// its first write, and the entry's PayloadBytes, or zeros if the frame has left
// the window. The write loop reads it to tell a retransmit from a first write
// before it reaches the CanSend gate, and counts a retransmit's payload from it,
// since the frame's Length by then is its committed (compressed) length.
func (w *SendWindow) RecordedBytes(frame *aether.Frame) (wire, payload int64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	entry, ok := w.entries[frame.SeqNo]
	if !ok || entry.Frame != frame {
		return 0, 0
	}
	return entry.InFlightBytes, entry.PayloadBytes
}

// WrittenFrame returns seq's frame if the entry has been written and nil otherwise.
// The retransmit paths (a peer's NACK, RACK) use it: a frame not yet written is
// already in the scheduler's queue and has no transmission to repeat, and the lock
// orders this read after the write loop's commit of the frame.
func (w *SendWindow) WrittenFrame(seq uint32) *aether.Frame {
	w.mu.Lock()
	defer w.mu.Unlock()
	if entry, ok := w.entries[seq]; ok && entry.Written {
		return entry.Frame
	}
	return nil
}

// HighestWritten returns the highest-sequence written frame still in the window,
// the frame a TLP probe repeats (RFC 8985 §7.4), or nil when none is written.
func (w *SendWindow) HighestWritten() (*aether.Frame, uint32) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.next == w.base {
		return nil, 0
	}
	for seq := w.next - 1; ; seq-- {
		if entry, ok := w.entries[seq]; ok && entry.Written {
			return entry.Frame, seq
		}
		if seq == w.base {
			return nil, 0
		}
	}
}

// ReleaseInFlight takes every entry out of the window and gives its
// InFlightBytes back to the session counter, returning the total released.
// The adapter calls it where a RESET takes a stream out of its session's stream
// map (noiseStream.Reset, NoiseSession.handleReset): from then
// on the session's handleACK finds no stream for the peer's ACKs, so no
// ACK path would ever remove these entries, and without this call their
// charge would stay in the counter for the session's life, holding that
// much of the congestion window against every later send the write loop's
// CanSend gate admits. Clearing the map makes the release exact
// and idempotent: a goroutine that still holds the stream (reliabilityTick
// over its snapshot, a handleACK that looked the stream up before the
// removal) finds no entry afterwards and subtracts nothing twice. It also
// marks the window released, so an AddEntry that arrives after it (a Send
// that passed the stream's state check before the Reset) charges nothing.
func (w *SendWindow) ReleaseInFlight() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.released = true
	var released int64
	for seq, entry := range w.entries {
		released += entry.InFlightBytes
		w.subInFlightLocked(entry)
		delete(w.entries, seq)
	}
	return released
}

// BumpXmitTime updates XmitTime on the entry for seq to t. Called by the
// adapter immediately before re-enqueuing a retransmit so RACK's loss
// detector (RFC 8985 §6.2) doesn't repeatedly mark a frame as lost while
// its retransmit waits in the scheduler; MarkWritten sets the time of the
// write itself.
//
// No-op if seq has left the window (already ACKed). Safe to call
// from the reliability tick — single-mutex acquisition.
func (w *SendWindow) BumpXmitTime(seq uint32, t time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if entry, ok := w.entries[seq]; ok {
		entry.XmitTime = t
		entry.Retries++
	}
}

// SnapshotEntries returns a copy of the (seq, XmitTime) pairs of every written
// entry for RACK iteration and TLP's arm time; an unwritten entry has no
// transmission for either to time. The caller iterates without holding any locks
// (RACK only needs xmit times, not the underlying frames). Allocates a
// fresh slice each call — RACK is invoked once per reliability tick on
// streams with InFlight > 0, so allocation overhead is bounded.
func (w *SendWindow) SnapshotEntries() []SnapshotEntry {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]SnapshotEntry, 0, len(w.entries))
	for seq, e := range w.entries {
		if !e.Written {
			continue
		}
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
// `seq <= end` forever. Cap the iteration
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
	// attacker-controlled scan loops (each bit is one map lookup below).
	if !validBitmapLens[len(ack.Bitmap)] {
		atomic.AddUint64(&w.suspiciousACKs, 1)
		return nil, nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	// CACKNoCumulative means the receiver has delivered nothing
	// in-order yet, so BaseACK is the wrapped sentinel expected-1
	// (0xFFFFFFFF) carried only to keep the bitmap aligned. Skip the
	// cumulative loop and its jump check entirely — reading the sentinel as
	// a ~4-billion forward jump is exactly what made this ACK look abusive.
	// The SACK bitmap scan below still runs and fast-retransmits seq 0.
	if ack.Flags&aether.CACKNoCumulative == 0 {
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
		} else {
			// BaseACK before our base — the cumulative point is stale (we've
			// already advanced past it), but do NOT discard the ACK: this is
			// the STEADY STATE of a mid-stream gap. When the receiver is
			// missing seq G it sets expected=G and emits BaseACK=expected-1=G-1
			// on EVERY subsequent duplicate ACK, while our base is pinned at G,
			// so BaseACK==base-1 < base holds for the whole life of the gap.
			// The SACK bitmap on those ACKs is FRESH and is the only signal
			// that clears the received tail from flight and fast-retransmits G,
			// so the ACK is not discarded: only the (empty) cumulative removal
			// is skipped, and the bitmap / ExtRange scan below, which is
			// indexed off BaseACK and therefore evaluates exactly base..
			// correctly, still runs. Counted for observability — a burst of
			// stale-BaseACKs marks an active gap, not an attack, so it is
			// deliberately NOT flagged as suspicious.
			atomic.AddUint64(&w.staleBaseACKs, 1)
		}
	}

	// 2. Bitmap scan
	if len(ack.Bitmap) > 0 {
		windowBits := len(ack.Bitmap) * 8
		var largestAcked uint32 = ack.BaseACK

		// First pass: find largestAcked for reorder threshold
		for i := 0; i < windowBits; i++ {
			seqNo := ack.BaseACK + 1 + uint32(i)
			// Bits at/beyond largestSent must not inflate largestAcked;
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
				// Require seqNo strictly below largestAcked. Without
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
	// crafted block with Start=0, End=0xFFFFFFFF.
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
			// applies (block.End >= w.next).
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
	// bounded in size to prevent mass-drop amplification.
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
// BumpXmitTime maintains for this comparison (the adapter bumps it on
// every retransmit).
func (w *SendWindow) Expired(rto time.Duration) []*SendEntry {
	w.mu.Lock()
	defer w.mu.Unlock()

	now := time.Now()
	var expired []*SendEntry
	for _, entry := range w.entries {
		if entry.Acked || !entry.Written {
			continue
		}
		if now.Sub(entry.XmitTime) > rto {
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

// InFlightBytes returns the wire bytes of all unacknowledged written
// frames in this window: the sum of SendEntry.InFlightBytes, the same
// kind and the same per-entry count the session counter holds, so the
// counter equals this sum over the wired windows at any moment w.mu is
// held.
//
// A caller gating sends on it must sum InFlightBytes() across the
// session's live streams and pass that plus the prospective frameSize into
// CUBIC.CanSend — CUBIC's contract is `inFlight < cwnd`, so a per-frame
// call with frameSize alone would return true unconditionally and bypass
// congestion control. The session's sessionInFlight atomic counter (wired
// via SetSessionInFlightCounter) is the fast path the adapter's write
// loop reads; this method is one window's total, read by this package's
// tests and by no caller in the adapter.
//
// O(entries) per call under the SendWindow lock — entries count is
// bounded by maxSize (typically a few hundred).
func (w *SendWindow) InFlightBytes() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	var total int64
	for _, e := range w.entries {
		total += e.InFlightBytes
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
