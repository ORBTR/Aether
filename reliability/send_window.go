/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package reliability

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/ORBTR/aether"
)

// Caps preventing CPU exhaustion from malicious Composite ACK frames.
// An attacker post-authentication could otherwise craft an ACK that pins
// the send CPU for seconds by claiming a huge cumulative jump or range.
// See _SECURITY.md §3.2.
const (
	// MaxACKCumulativeJump caps the distance between the current send-window
	// base and ack.BaseACK. A normal peer's BaseACK advances by small numbers
	// per ACK; jumps larger than this are rejected.
	MaxACKCumulativeJump uint32 = 4096

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

	// BBRv2 per-packet delivery-rate sample. Stamped at send time by the
	// adapter via congestion.BBRController.OnSend, read back by the
	// adapter when the matching ACK arrives so it can call OnAckSampled
	// instead of the degraded OnAck path. Opaque value — the SendWindow
	// doesn't introspect it.
	BBRSample interface{}
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
}

// SuspiciousACKsCount returns the number of Composite ACKs rejected
// because they failed sanity checks (ACK CPU-exhaustion defence).
func (w *SendWindow) SuspiciousACKsCount() uint64 {
	return atomic.LoadUint64(&w.suspiciousACKs)
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
	entry := &SendEntry{
		Frame:  frame,
		SentAt: time.Now(),
	}
	w.entries[seq] = entry
	w.next++
	return seq, entry
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
func (w *SendWindow) AckRange(start, end uint32) int {
	w.mu.Lock()
	defer w.mu.Unlock()

	count := 0
	for seq := start; seq <= end; seq++ {
		if entry, ok := w.entries[seq]; ok {
			entry.Acked = true
			delete(w.entries, seq)
			count++
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

	return count
}

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
		// (can legitimately happen with reordered ACKs).
		return nil, nil
	}

	// 1. Cumulative ACK (bounded by MaxACKCumulativeJump)
	for seq := w.base; seq <= ack.BaseACK; seq++ {
		if entry, ok := w.entries[seq]; ok {
			entry.Acked = true
			acked = append(acked, entry)
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
					delete(w.entries, seqNo)
				}
			} else {
				// bit=0: missing — implicit NACK if reorder threshold met
				if _, ok := w.entries[seqNo]; ok {
					if int(largestAcked-seqNo) >= reorderThreshold {
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
			delete(w.entries, seq)
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

// Expired returns all entries that have been in-flight longer than the given RTO.
// These are candidates for retransmission.
func (w *SendWindow) Expired(rto time.Duration) []*SendEntry {
	w.mu.Lock()
	defer w.mu.Unlock()

	now := time.Now()
	var expired []*SendEntry
	for _, entry := range w.entries {
		if !entry.Acked && now.Sub(entry.SentAt) > rto {
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
