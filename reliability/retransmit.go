/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package reliability

import (
	"container/heap"
	"sync"
	"time"

	"github.com/ORBTR/aether"
)

// RetransmitEntry tracks a frame pending retransmission.
//
// When enqueued via EnqueueFromSend, Send points at the shared
// *SendEntry owned by the SendWindow so updates to Retries / Frame are
// visible to both sides without duplicating fields. The legacy Enqueue
// path leaves Send nil and keeps the per-entry Retries counter local.
type RetransmitEntry struct {
	Frame      *aether.Frame
	Send       *SendEntry    // optional shared send-side entry; nil for legacy callers
	NextRetry  time.Time
	EnqueuedAt time.Time     // original enqueue time (for accurate MaxAge check)
	Retries    int
	RTO        time.Duration // RTO at time of enqueue (for exponential backoff)
	index      int           // heap index
}

// DefaultRetransmitMaxBytes caps the total payload bytes held in the
// retransmit queue. A 64-entry WindowSize × ~70 KB payloads could hit
// 4.5 MB per stream worst case; the byte cap keeps this bounded
// independently of frame count.
const DefaultRetransmitMaxBytes int64 = 512 * 1024

// RetransmitQueue is a priority queue of frames awaiting retransmission,
// ordered by NextRetry time. Integrates with the RTTEstimator for RTO calculation.
//
// seqIndex maps SeqNo → current position in the heap, kept in sync by
// Push/Pop/Swap. Remove(seqNo) becomes O(log N) instead of O(N) (#12).
//
// Memory bounds: bufferedBytes + maxBytes enforce a payload-byte cap
// on the queue in addition to any frame-count limit the caller imposes
// via the send window. When Enqueue would push bufferedBytes past
// maxBytes, the oldest entry (lowest NextRetry) is dropped from the
// heap — the higher-level retry path (e.g. RTO at the session layer)
// is responsible for eventually noticing the shortfall.
type RetransmitQueue struct {
	mu            sync.Mutex
	queue         retransmitHeap
	seqIndex      map[uint32]int
	rtt           *RTTEstimator
	maxRetries    int           // 0 = unlimited
	maxAge        time.Duration // 0 = no deadline. Frames older than this are dropped instead of retransmitted.
	maxBytes      int64         // 0 = unlimited
	bufferedBytes int64
}

// NewRetransmitQueue creates a retransmission queue.
// maxRetries=0 means unlimited retries (reliable mode).
// Use SetMaxAge to enable deadline-based dropping.
// A default byte cap (DefaultRetransmitMaxBytes) is applied; override
// via SetMaxBytes.
func NewRetransmitQueue(rtt *RTTEstimator, maxRetries int) *RetransmitQueue {
	q := &RetransmitQueue{
		rtt:        rtt,
		maxRetries: maxRetries,
		seqIndex:   make(map[uint32]int),
		maxBytes:   DefaultRetransmitMaxBytes,
	}
	q.queue.idx = q.seqIndex
	heap.Init(&q.queue)
	return q
}

// SetMaxBytes overrides the queue's payload-byte cap. Pass 0 to disable
// the cap (frame-count limits still apply at the SendWindow level).
func (q *RetransmitQueue) SetMaxBytes(n int64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if n < 0 {
		n = 0
	}
	q.maxBytes = n
}

// frameBytes returns the payload byte count used for cap accounting.
// Uses len(frame.Payload) as a conservative proxy for on-wire size;
// accounting errors bounded by Aether header (~50 bytes) per frame
// are acceptable for a memory cap.
func frameBytes(f *aether.Frame) int64 {
	if f == nil {
		return 0
	}
	return int64(len(f.Payload))
}

// removeBySeq performs an indexed O(log N) heap remove. Caller must hold q.mu.
// Updates bufferedBytes to reflect the dropped entry's payload size.
func (q *RetransmitQueue) removeBySeq(seqNo uint32) bool {
	idx, ok := q.seqIndex[seqNo]
	if !ok {
		return false
	}
	entry := q.queue.data[idx]
	heap.Remove(&q.queue, idx)
	q.bufferedBytes -= frameBytes(entry.Frame)
	if q.bufferedBytes < 0 {
		q.bufferedBytes = 0
	}
	return true
}

// Enqueue adds a frame to the retransmission queue.
// The frame will be due for retransmit after the current RTO.
//
// When enforcing the byte cap, the oldest un-acked entry (lowest
// NextRetry — the one that has been in flight longest and is closest
// to fire) is dropped to make room. Callers relying on the retransmit
// queue for guaranteed delivery should set maxRetries + maxAge at the
// session layer so the caller notices the shortfall, since a dropped
// retransmit entry is no longer retried by this queue.
func (q *RetransmitQueue) Enqueue(frame *aether.Frame) {
	q.mu.Lock()
	defer q.mu.Unlock()

	incoming := frameBytes(frame)
	// Evict the oldest entry until the incoming frame fits under the
	// byte cap. Skip eviction if the incoming frame alone exceeds the
	// cap (a single giant frame must still be queued; the cap is a
	// soft aggregate, not a per-frame limit).
	if q.maxBytes > 0 && incoming <= q.maxBytes {
		for q.queue.Len() > 0 && q.bufferedBytes+incoming > q.maxBytes {
			oldest := heap.Pop(&q.queue).(*RetransmitEntry)
			q.bufferedBytes -= frameBytes(oldest.Frame)
		}
		if q.bufferedBytes < 0 {
			q.bufferedBytes = 0
		}
	}

	now := time.Now()
	rto := q.rtt.RTO()
	entry := &RetransmitEntry{
		Frame:      frame,
		NextRetry:  now.Add(rto),
		EnqueuedAt: now,
		Retries:    0,
		RTO:        rto,
	}
	heap.Push(&q.queue, entry)
	q.bufferedBytes += incoming
}

// EnqueueFromSend is like Enqueue but links the retransmit entry to the
// caller's existing *SendEntry so both sides share a single backing
// struct for the in-flight frame. Saves one allocation per send and
// lets the retransmit machinery observe updates (e.g. BBRSample) on
// the live send entry without a callback.
func (q *RetransmitQueue) EnqueueFromSend(se *SendEntry) {
	if se == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()

	incoming := frameBytes(se.Frame)
	if q.maxBytes > 0 && incoming <= q.maxBytes {
		for q.queue.Len() > 0 && q.bufferedBytes+incoming > q.maxBytes {
			oldest := heap.Pop(&q.queue).(*RetransmitEntry)
			q.bufferedBytes -= frameBytes(oldest.Frame)
		}
		if q.bufferedBytes < 0 {
			q.bufferedBytes = 0
		}
	}

	now := time.Now()
	rto := q.rtt.RTO()
	entry := &RetransmitEntry{
		Frame:      se.Frame,
		Send:       se,
		NextRetry:  now.Add(rto),
		EnqueuedAt: now,
		Retries:    0,
		RTO:        rto,
	}
	heap.Push(&q.queue, entry)
	q.bufferedBytes += incoming
}

// Dequeue returns the next frame due for retransmit (NextRetry <= now).
// Returns nil if no frames are due. Automatically re-enqueues the entry
// with doubled RTO (exponential backoff) if maxRetries is not exceeded.
func (q *RetransmitQueue) Dequeue() *aether.Frame {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.queue.Len() == 0 {
		return nil
	}

	// Peek at the earliest entry
	entry := q.queue.data[0]
	if time.Now().Before(entry.NextRetry) {
		return nil // not due yet
	}

	// Pop it
	heap.Pop(&q.queue)
	entryBytes := frameBytes(entry.Frame)

	entry.Retries++

	// Check deadline — drop frames that have expired
	// Check deadline using the original enqueue time (accurate across retries)
	if q.maxAge > 0 {
		age := time.Since(entry.EnqueuedAt)
		if age > q.maxAge {
			q.bufferedBytes -= entryBytes
			if q.bufferedBytes < 0 {
				q.bufferedBytes = 0
			}
			return nil // expired — skip retransmit, stale data
		}
	}

	// Check max retries
	if q.maxRetries > 0 && entry.Retries > q.maxRetries {
		q.bufferedBytes -= entryBytes
		if q.bufferedBytes < 0 {
			q.bufferedBytes = 0
		}
		return nil // exceeded max retries — drop
	}

	// Re-enqueue with doubled RTO (exponential backoff). bufferedBytes
	// is unchanged since the same entry stays in the queue.
	entry.RTO *= 2
	maxRTO := 60 * time.Second
	if entry.RTO > maxRTO {
		entry.RTO = maxRTO
	}
	entry.NextRetry = time.Now().Add(entry.RTO)
	heap.Push(&q.queue, entry)

	return entry.Frame
}

// Remove removes a frame from the queue by SeqNo (when ACKed). O(log N)
// via the seqIndex map maintained by Push/Pop/Swap.
func (q *RetransmitQueue) Remove(seqNo uint32) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.removeBySeq(seqNo)
}

// Len returns the number of entries in the queue.
func (q *RetransmitQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.queue.Len()
}

// SetMaxAge sets the deadline for frame expiration. Frames older than maxAge
// are dropped instead of retransmitted. Set to 0 to disable deadlines.
func (q *RetransmitQueue) SetMaxAge(maxAge time.Duration) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.maxAge = maxAge
}

// NextDueIn returns the duration until the next retransmit is due.
// Returns 0 if a retransmit is due now, or a large value if the queue is empty.
func (q *RetransmitQueue) NextDueIn() time.Duration {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.queue.Len() == 0 {
		return time.Hour // no pending retransmits
	}

	until := time.Until(q.queue.data[0].NextRetry)
	if until < 0 {
		return 0
	}
	return until
}

// ────────────────────────────────────────────────────────────────────────────
// Indexed min-heap ordered by NextRetry. The `idx` map is owned by the
// enclosing RetransmitQueue and updated on every Push/Pop/Swap so that
// Remove(seqNo) can find an entry's heap position in O(1).
// ────────────────────────────────────────────────────────────────────────────

type retransmitHeap struct {
	data []*RetransmitEntry
	idx  map[uint32]int // SeqNo → heap position; mirrors data positions
}

func (h *retransmitHeap) Len() int { return len(h.data) }

func (h *retransmitHeap) Less(i, j int) bool {
	return h.data[i].NextRetry.Before(h.data[j].NextRetry)
}

func (h *retransmitHeap) Swap(i, j int) {
	h.data[i], h.data[j] = h.data[j], h.data[i]
	h.data[i].index = i
	h.data[j].index = j
	if h.idx != nil {
		h.idx[h.data[i].Frame.SeqNo] = i
		h.idx[h.data[j].Frame.SeqNo] = j
	}
}

func (h *retransmitHeap) Push(x interface{}) {
	entry := x.(*RetransmitEntry)
	entry.index = len(h.data)
	h.data = append(h.data, entry)
	if h.idx != nil {
		h.idx[entry.Frame.SeqNo] = entry.index
	}
}

func (h *retransmitHeap) Pop() interface{} {
	n := len(h.data)
	entry := h.data[n-1]
	h.data[n-1] = nil
	entry.index = -1
	h.data = h.data[:n-1]
	if h.idx != nil {
		delete(h.idx, entry.Frame.SeqNo)
	}
	return entry
}
