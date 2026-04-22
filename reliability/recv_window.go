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

// DefaultRecvWindowMaxBytes is the default byte cap for a RecvWindow's
// reorder buffer when the caller doesn't specify one. A 64-entry
// reorder buffer with 64 KB payloads could otherwise reach 4 MB per
// stream, which multiplies hard against peer count × stream count.
// 512 KB is comfortable for normal reorder depths while bounding
// per-stream worst-case memory.
const DefaultRecvWindowMaxBytes int64 = 512 * 1024

// RecvWindow tracks received frames on the receiver side, reorders out-of-order
// frames, and generates SACK blocks for selective acknowledgment.
type RecvWindow struct {
	mu           sync.Mutex
	expected     uint32               // next expected SeqNo (cumulative ACK point)
	buffer       map[uint32][]byte    // out-of-order frames: SeqNo → payload
	bufTime      map[uint32]time.Time // out-of-order frames: SeqNo → buffer arrival time
	maxGap       int                  // max reorder buffer size (frame count)
	maxBytes     int64                // max total bytes buffered (0 = unlimited)
	bufferedBytes int64               // current sum of buffered payload bytes
	maxAge       time.Duration        // max time a frame can sit in reorder buffer (0 = unlimited)
	lastRecvTime time.Time            // when the last data frame was received (for ACK delay)
	dropCount    uint64               // atomic: frames dropped due to reorder buffer full
}

// NewRecvWindow creates a receive window with the given maximum reorder
// gap (frame count). The byte cap defaults to DefaultRecvWindowMaxBytes.
// Callers wanting a tighter or looser byte cap should use
// NewRecvWindowWithCap.
func NewRecvWindow(maxGap int) *RecvWindow {
	return NewRecvWindowWithCap(maxGap, DefaultRecvWindowMaxBytes)
}

// NewRecvWindowWithCap creates a receive window with an explicit byte
// cap on the reorder buffer in addition to the frame-count cap. Out-of-
// order frames that would push bufferedBytes past maxBytes are rejected
// the same way as frames that would exceed maxGap (dropCount bumped,
// caller can observe via DropsCount). Passing maxBytes <= 0 disables
// the byte cap (frame-count cap still applies).
func NewRecvWindowWithCap(maxGap int, maxBytes int64) *RecvWindow {
	if maxBytes < 0 {
		maxBytes = 0
	}
	return &RecvWindow{
		buffer:   make(map[uint32][]byte),
		bufTime:  make(map[uint32]time.Time),
		maxGap:   maxGap,
		maxBytes: maxBytes,
	}
}

// SetMaxAge sets the maximum time a frame can remain in the reorder buffer.
// Frames older than this are silently dropped during delivery flushes.
// Used for partial reliability (e.g., real-time streams where stale data is useless).
func (w *RecvWindow) SetMaxAge(d time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.maxAge = d
}

// Insert records a received frame. Returns the list of in-order payloads
// that can be delivered to the application (may be empty if the frame is
// out-of-order, or multiple if this frame fills a gap).
func (w *RecvWindow) Insert(seqNo uint32, payload []byte) [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.lastRecvTime = time.Now()

	if seqNo < w.expected {
		return nil // duplicate or already delivered
	}

	if seqNo == w.expected {
		// In-order: deliver immediately + flush any buffered successors
		delivered := [][]byte{copyPayload(payload)}
		w.expected++

		// Flush buffered successors, skipping expired frames
		for {
			p, ok := w.buffer[w.expected]
			if !ok {
				break
			}
			// MaxAge check: drop frames that sat in the buffer too long
			if w.maxAge > 0 {
				if arrived, hasTime := w.bufTime[w.expected]; hasTime && time.Since(arrived) > w.maxAge {
					w.bufferedBytes -= int64(len(p))
					delete(w.buffer, w.expected)
					delete(w.bufTime, w.expected)
					w.expected++
					continue // skip expired frame
				}
			}
			delivered = append(delivered, p)
			w.bufferedBytes -= int64(len(p))
			delete(w.buffer, w.expected)
			delete(w.bufTime, w.expected)
			w.expected++
		}
		if w.bufferedBytes < 0 {
			w.bufferedBytes = 0
		}
		return delivered
	}

	// Out-of-order: buffer it with arrival timestamp, subject to both
	// the frame-count cap and the byte cap. A byte cap breach is treated
	// the same as a frame-count breach — drop with dropCount++.
	payloadLen := int64(len(payload))
	if len(w.buffer) >= w.maxGap {
		atomic.AddUint64(&w.dropCount, 1)
		return nil
	}
	if w.maxBytes > 0 && w.bufferedBytes+payloadLen > w.maxBytes {
		atomic.AddUint64(&w.dropCount, 1)
		return nil
	}
	w.buffer[seqNo] = copyPayload(payload)
	w.bufTime[seqNo] = time.Now()
	w.bufferedBytes += payloadLen
	return nil
}

// DropsCount returns the total number of frames dropped by this receive
// window because the reorder buffer was full when they arrived. Always
// monotonic; safe to call from any goroutine.
func (w *RecvWindow) DropsCount() uint64 {
	return atomic.LoadUint64(&w.dropCount)
}

// ExpectedSeqNo returns the next expected sequence number (cumulative ACK point).
func (w *RecvWindow) ExpectedSeqNo() uint32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.expected
}

// GenerateBitmap generates a received-packet bitmap for the Composite ACK.
// Bit i=1 means SeqNo (expected+i) has been received (is in the reorder buffer).
// windowBits must be 32, 64, 128, or 256. Returns (bitmap, ackDelayUs, hasGap).
// The bitmap ONLY represents the forward window relative to the cumulative ACK.
func (w *RecvWindow) GenerateBitmap(windowBits int) (bitmap []byte, ackDelayUs uint32, hasGap bool) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// ACK delay: time since last data frame was received
	if !w.lastRecvTime.IsZero() {
		delayUs := time.Since(w.lastRecvTime).Microseconds()
		if delayUs > 0 && delayUs < int64(^uint32(0)) {
			ackDelayUs = uint32(delayUs)
		}
	}

	hasGap = len(w.buffer) > 0
	if windowBits <= 0 || len(w.buffer) == 0 {
		return nil, ackDelayUs, hasGap
	}

	bitmapBytes := windowBits / 8
	bitmap = make([]byte, bitmapBytes)

	for i := 0; i < windowBits; i++ {
		seqNo := w.expected + uint32(i)
		if _, ok := w.buffer[seqNo]; ok {
			bitmap[i/8] |= 1 << (uint(i) % 8)
		}
	}

	return bitmap, ackDelayUs, hasGap
}

// NeedExtendedRanges returns true if there are buffered packets beyond the bitmap window.
func (w *RecvWindow) NeedExtendedRanges(windowBits int) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	limit := w.expected + uint32(windowBits)
	for seq := range w.buffer {
		if seq >= limit {
			return true
		}
	}
	return false
}

// ExtendedRanges returns SACK blocks for packets beyond the bitmap window.
func (w *RecvWindow) ExtendedRanges(windowBits int) []aether.SACKBlock {
	w.mu.Lock()
	defer w.mu.Unlock()
	limit := w.expected + uint32(windowBits)

	// Collect SeqNos beyond the bitmap window
	var seqs []uint32
	for seq := range w.buffer {
		if seq >= limit {
			seqs = append(seqs, seq)
		}
	}
	if len(seqs) == 0 {
		return nil
	}
	sortUint32(seqs)

	// Build contiguous ranges
	var blocks []aether.SACKBlock
	start, end := seqs[0], seqs[0]
	for i := 1; i < len(seqs); i++ {
		if seqs[i] == end+1 {
			end = seqs[i]
		} else {
			blocks = append(blocks, aether.SACKBlock{Start: start, End: end})
			start, end = seqs[i], seqs[i]
		}
	}
	blocks = append(blocks, aether.SACKBlock{Start: start, End: end})

	if len(blocks) > aether.MaxExtRanges {
		blocks = blocks[:aether.MaxExtRanges]
	}
	return blocks
}

// MissingRanges returns SACK blocks describing received ranges after gaps.
// The caller uses these to build ACK frames with selective acknowledgment.
func (w *RecvWindow) MissingRanges() []aether.SACKBlock {
	w.mu.Lock()
	defer w.mu.Unlock()

	if len(w.buffer) == 0 {
		return nil
	}

	// Collect all buffered SeqNos and sort
	seqs := make([]uint32, 0, len(w.buffer))
	for seq := range w.buffer {
		seqs = append(seqs, seq)
	}
	sortUint32(seqs)

	// Build SACK blocks from contiguous ranges
	var blocks []aether.SACKBlock
	start := seqs[0]
	end := seqs[0]

	for i := 1; i < len(seqs); i++ {
		if seqs[i] == end+1 {
			end = seqs[i]
		} else {
			blocks = append(blocks, aether.SACKBlock{Start: start, End: end})
			start = seqs[i]
			end = seqs[i]
		}
	}
	blocks = append(blocks, aether.SACKBlock{Start: start, End: end})

	// Limit to MaxSACKBlocks
	if len(blocks) > aether.MaxSACKBlocks {
		blocks = blocks[:aether.MaxSACKBlocks]
	}

	return blocks
}

// BufferedCount returns the number of out-of-order frames buffered.
func (w *RecvWindow) BufferedCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.buffer)
}

// Spread returns the distance from expected SeqNo to the highest buffered SeqNo.
// Returns 0 if the buffer is empty. Used by ACKEngine for bitmap size selection.
func (w *RecvWindow) Spread() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.buffer) == 0 {
		return 0
	}
	var maxSeq uint32
	for seq := range w.buffer {
		if seq > maxSeq {
			maxSeq = seq
		}
	}
	if maxSeq <= w.expected {
		return 0
	}
	return int(maxSeq - w.expected)
}

// Drain returns all buffered out-of-order payloads in SeqNo order,
// regardless of gaps. Used during stream close to deliver remaining data.
// After drain, the buffer is empty and expected advances past all drained frames.
func (w *RecvWindow) Drain() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()

	if len(w.buffer) == 0 {
		return nil
	}

	// Collect and sort all buffered SeqNos
	seqs := make([]uint32, 0, len(w.buffer))
	for seq := range w.buffer {
		seqs = append(seqs, seq)
	}
	sortUint32(seqs)

	// Deliver all in order
	delivered := make([][]byte, 0, len(seqs))
	for _, seq := range seqs {
		delivered = append(delivered, w.buffer[seq])
	}

	// Clear buffer and advance expected
	if len(seqs) > 0 {
		w.expected = seqs[len(seqs)-1] + 1
	}
	w.buffer = make(map[uint32][]byte)
	w.bufTime = make(map[uint32]time.Time)
	w.bufferedBytes = 0

	return delivered
}

// copyPayload makes a copy to avoid aliasing.
func copyPayload(p []byte) []byte {
	cp := make([]byte, len(p))
	copy(cp, p)
	return cp
}

// sortUint32 sorts a slice of uint32 in ascending order (insertion sort for small slices).
func sortUint32(s []uint32) {
	for i := 1; i < len(s); i++ {
		key := s[i]
		j := i - 1
		for j >= 0 && s[j] > key {
			s[j+1] = s[j]
			j--
		}
		s[j+1] = key
	}
}
