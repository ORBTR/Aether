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
	"github.com/ORBTR/aether/metrics"
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
	mu            sync.Mutex
	expected      uint32               // next expected SeqNo (cumulative ACK point)
	buffer        map[uint32][]byte    // out-of-order frames: SeqNo → payload
	bufTime       map[uint32]time.Time // out-of-order frames: SeqNo → buffer arrival time
	marked        map[uint32]bool      // out-of-order frames inserted marked (InsertMarked); absent = unmarked
	ends          map[uint32]bool      // out-of-order frames inserted as the stream's end (InsertEnd)
	maxGap        int                  // max reorder buffer size (frame count)
	maxBytes      int64                // max total bytes buffered (0 = unlimited)
	bufferedBytes int64                // current sum of buffered payload bytes
	maxAge        time.Duration        // max time a frame can sit in reorder buffer (0 = unlimited)
	lastRecvTime  time.Time            // when the last data frame was received (for ACK delay)
	dropCount     uint64               // atomic: frames dropped due to reorder buffer full

	// holHist is the head-of-line-block histogram. When non-nil, every buffered frame that
	// is flushed in order records (deliveryTime − bufferArrivalTime) into
	// this histogram. The distribution describes how long each frame was
	// head-of-line blocked waiting for its predecessors. Set by the session
	// adapter via SetHOLHist so all streams on one session share a single
	// histogram; nil means no measurement (in-order or unmonitored streams).
	holHist *metrics.DurationHist
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
		marked:   make(map[uint32]bool),
		ends:     make(map[uint32]bool),
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

// SetHOLHist wires a head-of-line-block histogram into this window.
// When set, each buffered frame that is delivered in order records
// (deliveryTime − bufferArrivalTime) so operators can see the HOL-block
// latency distribution. Passing nil disables the measurement. Safe to call
// before the first Insert; must not be called concurrently with Insert.
func (w *RecvWindow) SetHOLHist(h *metrics.DurationHist) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.holHist = h
}

// RecvDelivery is one in-order payload InsertMarked or DrainMarked hands
// back, with the mark its frame was inserted under. The Noise adapter marks a
// DATA frame that carries one fragment envelope (aether.Frame.IsFragment), so
// the flag the frame header carried reaches reassembly after reordering, which
// sees payloads only. End says the frame carries no message and is the peer's
// CLOSE (InsertEnd), which reaches its reader behind every frame sequenced before
// it.
type RecvDelivery struct {
	Payload []byte
	Marked  bool
	End     bool
}

// Insert records a received frame. Returns the list of in-order payloads
// that can be delivered to the application (may be empty if the frame is
// out-of-order, or multiple if this frame fills a gap).
func (w *RecvWindow) Insert(seqNo uint32, payload []byte) [][]byte {
	delivered, _ := w.InsertChecked(seqNo, payload)
	return delivered
}

// InsertChecked is Insert plus an accepted flag. accepted is false only
// when the frame was dropped because the reorder buffer was full (frame-
// count or byte cap). Callers that gate a replay-window commit on durable
// buffering (the adapter's handleData) use this so a capacity-dropped frame's retransmit is
// still deliverable later instead of being marked seen and discarded.
func (w *RecvWindow) InsertChecked(seqNo uint32, payload []byte) (delivered [][]byte, accepted bool) {
	marked, accepted := w.InsertMarked(seqNo, payload, false)
	return payloadsOf(marked), accepted
}

// InsertMarked is InsertChecked for a caller that carries one bit per frame
// through the reorder buffer: each delivered payload comes back with the mark
// its own frame was inserted under. A re-insert of a still-buffered frame takes
// the latest mark; a frame dropped for age drops its mark with it.
func (w *RecvWindow) InsertMarked(seqNo uint32, payload []byte, mark bool) (delivered []RecvDelivery, accepted bool) {
	return w.insert(seqNo, payload, mark, false)
}

// InsertEnd is InsertMarked for a frame that carries no message and takes a
// sequence number to end the stream's receive side: the adapter's handleClose
// inserts the peer's CLOSE here, and its RecvDelivery comes back End once every
// frame before it has been delivered. A CLOSE that overtook a frame, or whose
// predecessor is lost, waits in the buffer like any frame, and the ACK engine reads
// its sequence number from this window like any frame's.
func (w *RecvWindow) InsertEnd(seqNo uint32) (delivered []RecvDelivery, accepted bool) {
	return w.insert(seqNo, nil, false, true)
}

func (w *RecvWindow) insert(seqNo uint32, payload []byte, mark, end bool) (delivered []RecvDelivery, accepted bool) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.lastRecvTime = time.Now()

	if seqNo < w.expected {
		return nil, true // duplicate or already delivered — no buffering needed
	}

	if seqNo == w.expected {
		// In-order: deliver immediately + flush any buffered successors
		delivered := []RecvDelivery{{Payload: copyPayload(payload), Marked: mark, End: end}}
		w.expected++

		// Flush buffered successors, skipping expired frames.
		// For each flushed buffered frame, record the time it spent
		// head-of-line blocked (bufferArrivalTime → now) into holHist.
		// Frames that arrive in order and are delivered immediately have
		// zero HOL-block time and are not recorded — the histogram represents
		// only frames that were genuinely reordered and had to wait.
		now := time.Now()
		for {
			p, ok := w.buffer[w.expected]
			if !ok {
				break
			}
			// MaxAge check: drop frames that sat in the buffer too long
			if w.maxAge > 0 {
				if arrived, hasTime := w.bufTime[w.expected]; hasTime && now.Sub(arrived) > w.maxAge {
					w.bufferedBytes -= int64(len(p))
					delete(w.buffer, w.expected)
					delete(w.bufTime, w.expected)
					delete(w.marked, w.expected)
					delete(w.ends, w.expected)
					w.expected++
					continue // skip expired frame
				}
			}
			// HOL-block measurement: time from buffer arrival to delivery.
			if w.holHist != nil {
				if arrived, hasTime := w.bufTime[w.expected]; hasTime {
					w.holHist.Record(now.Sub(arrived))
				}
			}
			delivered = append(delivered, RecvDelivery{Payload: p, Marked: w.marked[w.expected], End: w.ends[w.expected]})
			w.bufferedBytes -= int64(len(p))
			delete(w.buffer, w.expected)
			delete(w.bufTime, w.expected)
			delete(w.marked, w.expected)
			delete(w.ends, w.expected)
			w.expected++
		}
		if w.bufferedBytes < 0 {
			w.bufferedBytes = 0
		}
		return delivered, true
	}

	// Out-of-order: buffer it with arrival timestamp, subject to both
	// the frame-count cap and the byte cap. A byte cap breach is treated
	// the same as a frame-count breach — drop with dropCount++.
	//
	// A re-inserted still-buffered seq (reachable via the dispatch layer's
	// ResultAncient at/above-floor fall-through) must not double-count
	// bufferedBytes. Discount the existing entry's length up front so the
	// cap checks and the accumulator both see a replace, not an add;
	// otherwise bufferedBytes inflates (reset only by Drain) until it nears
	// maxBytes and the window degrades to strict in-order.
	payloadLen := int64(len(payload))
	if old, exists := w.buffer[seqNo]; exists {
		w.bufferedBytes -= int64(len(old))
		if w.bufferedBytes < 0 {
			w.bufferedBytes = 0
		}
	}
	if _, exists := w.buffer[seqNo]; !exists && len(w.buffer) >= w.maxGap {
		atomic.AddUint64(&w.dropCount, 1)
		return nil, false
	}
	if w.maxBytes > 0 && w.bufferedBytes+payloadLen > w.maxBytes {
		atomic.AddUint64(&w.dropCount, 1)
		return nil, false
	}
	w.buffer[seqNo] = copyPayload(payload)
	w.bufTime[seqNo] = time.Now()
	if mark {
		w.marked[seqNo] = true
	} else {
		delete(w.marked, seqNo)
	}
	if end {
		w.ends[seqNo] = true
	} else {
		delete(w.ends, seqNo)
	}
	w.bufferedBytes += payloadLen
	return nil, true
}

// payloadsOf strips the marks off deliveries for the unmarked entry points.
func payloadsOf(d []RecvDelivery) [][]byte {
	if d == nil {
		return nil
	}
	out := make([][]byte, len(d))
	for i := range d {
		out[i] = d[i].Payload
	}
	return out
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
// regardless of gaps, for a caller that ends a stream without waiting for the
// gaps to fill. After drain, the buffer is empty and expected advances past all
// drained frames. The adapter's sessions do not call it: a peer's CLOSE reaches
// its reader in sequence (InsertEnd), behind every frame before it.
func (w *RecvWindow) Drain() [][]byte {
	return payloadsOf(w.DrainMarked())
}

// DrainMarked is Drain with each payload's mark (InsertMarked).
func (w *RecvWindow) DrainMarked() []RecvDelivery {
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
	delivered := make([]RecvDelivery, 0, len(seqs))
	for _, seq := range seqs {
		delivered = append(delivered, RecvDelivery{Payload: w.buffer[seq], Marked: w.marked[seq], End: w.ends[seq]})
	}

	// Clear buffer and advance expected
	if len(seqs) > 0 {
		w.expected = seqs[len(seqs)-1] + 1
	}
	w.buffer = make(map[uint32][]byte)
	w.bufTime = make(map[uint32]time.Time)
	w.marked = make(map[uint32]bool)
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
