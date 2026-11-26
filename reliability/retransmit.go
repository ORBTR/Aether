/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package reliability

import (
	"container/heap"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ORBTR/aether"
)

// RetransmitEntry tracks a frame pending retransmission.
//
// When enqueued via EnqueueFromSend, Send points at the shared
// *SendEntry owned by the SendWindow so updates to Retries / Frame are
// visible to both sides without duplicating fields. The Enqueue
// path leaves Send nil and keeps the per-entry Retries counter local.
//
// PayloadBytes is len(Frame.Payload) as it was when the entry was enqueued:
// the payload bytes the sender handed over, which the byte cap counts
// (bufferedBytes adds it at Enqueue and subtracts it wherever the entry
// leaves: removeBySeq, evictForRoomLocked, Dequeue's acked drop and
// advanceEntryLocked's age and max-retries drops). It is read instead of
// the frame because Frame is the sender's live frame: the adapter's
// writeFrame swaps Frame.Payload for its compressed form when that is
// shorter and, with a session key, for the ciphertext, under the session's
// writeMu after the sender has enqueued it here, while Dequeue runs on
// reliabilityTick, Remove on the readLoop's
// handleACK and the eviction on a later sender's Enqueue, none under
// writeMu. The entry's own count keeps every path from reading what the
// write loop is committing and keeps the sum the payload bytes it is named
// for, whatever length the committed Payload has.
type RetransmitEntry struct {
	Frame        *aether.Frame
	Send         *SendEntry // optional shared send-side entry; nil for Enqueue callers
	PayloadBytes int64
	NextRetry    time.Time
	EnqueuedAt   time.Time // original enqueue time (for accurate MaxAge check)
	Retries      int
	RTO          time.Duration // RTO at time of enqueue (for exponential backoff)
	index        int           // heap index
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
// Push/Pop/Swap, so removeBySeq finds an entry in O(1) and heap.Remove
// runs in O(log N).
//
// Memory bounds: bufferedBytes + maxBytes enforce a payload-byte cap
// on the queue in addition to any frame-count limit the caller imposes
// via the send window. bufferedBytes is the sum of the queued entries'
// PayloadBytes, each fixed at its Enqueue, so it is exactly the payload
// bytes the queue holds and returns to 0 when the queue empties. When
// Enqueue would push bufferedBytes past maxBytes, the oldest entry
// (lowest NextRetry) is dropped from the heap — the higher-level retry
// path (e.g. RTO at the session layer) is responsible for eventually
// noticing the shortfall.
//
// After Enqueue the queue reads nothing of a frame but Frame.SeqNo (the
// heap index), which the send window writes once before any enqueue;
// Frame.Payload and Frame.Length belong to the adapter's writeFrame from
// the moment the sender hands the frame to the scheduler.
type RetransmitQueue struct {
	mu            sync.Mutex
	queue         retransmitHeap
	seqIndex      map[uint32]int
	rtt           *RTTEstimator
	maxRetries    int           // 0 = unlimited
	maxAge        time.Duration // 0 = no deadline. Frames older than this are dropped instead of retransmitted.
	maxBytes      int64         // 0 = unlimited
	bufferedBytes int64
	// onEvict (if set) is invoked for every entry the queue drops to make
	// room — byte-cap eviction, deadline drop, max-retries drop. The
	// adapter's createStream registers a callback that counts the eviction
	// and logs it, so a reliable frame that lost its RTO safety net is
	// visible rather than a send window that never advances. Called WITH
	// q.mu held; callbacks must not re-enter the queue.
	onEvict func(*RetransmitEntry)

	// ackedOnDequeue is an atomic counter of entries dropped at Dequeue
	// time because their underlying SendEntry was already marked Acked:
	// ProcessCompositeACK sets Send.Acked and the adapter's handleACK calls
	// Remove afterwards, so an RTO firing between the two finds an acked
	// entry at the heap top. The count makes those withheld retransmits
	// observable. Read via AckedOnDequeueCount().
	ackedOnDequeue uint64
}

// SetOnEvict installs the eviction callback. Pass nil to clear.
// Concurrent-safe but typically called once at session-init time.
func (q *RetransmitQueue) SetOnEvict(fn func(*RetransmitEntry)) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.onEvict = fn
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

// frameBytes returns the payload bytes of a frame being enqueued, the count
// RetransmitEntry.PayloadBytes keeps for its lifetime. It reads Frame.Payload, so
// it is for a caller whose frame no other goroutine can reach yet (Enqueue);
// noiseStream.recordWrite, on the write loop's path, gives the plaintext count the
// SendEntry recorded to EnqueueSized. The header is not counted: the cap is named
// for payload bytes.
func frameBytes(f *aether.Frame) int64 {
	if f == nil {
		return 0
	}
	return int64(len(f.Payload))
}

// removeBySeq performs an indexed O(log N) heap remove. Caller must hold q.mu.
// Subtracts the entry's own PayloadBytes, the count its Enqueue added.
func (q *RetransmitQueue) removeBySeq(seqNo uint32) bool {
	idx, ok := q.seqIndex[seqNo]
	if !ok {
		return false
	}
	entry := q.queue.data[idx]
	heap.Remove(&q.queue, idx)
	q.bufferedBytes -= entry.PayloadBytes
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
// retransmit entry is not retried by this queue again.
func (q *RetransmitQueue) Enqueue(frame *aether.Frame) {
	q.EnqueueSized(frame, frameBytes(frame))
}

// EnqueueSized is Enqueue with the frame's payload size given by the caller, for
// a frame whose Payload already holds its committed form: noiseStream.recordWrite
// calls it at the frame's first write with the plaintext count from AddEntry, so
// the RTO runs from the write and the cap counts what Enqueue counts.
func (q *RetransmitQueue) EnqueueSized(frame *aether.Frame, incoming int64) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.evictForRoomLocked(incoming)

	now := time.Now()
	rto := q.rtt.RTO()
	entry := &RetransmitEntry{
		Frame:        frame,
		PayloadBytes: incoming,
		NextRetry:    now.Add(rto),
		EnqueuedAt:   now,
		Retries:      0,
		RTO:          rto,
	}
	heap.Push(&q.queue, entry)
	q.bufferedBytes += incoming
}

// evictForRoomLocked pops the oldest entries until incoming fits under
// the byte cap, subtracting each one's own PayloadBytes. Notifies onEvict
// for each evicted entry so upper layers can release flow-control credit /
// bump metrics. Caller holds q.mu.
func (q *RetransmitQueue) evictForRoomLocked(incoming int64) {
	if q.maxBytes <= 0 || incoming > q.maxBytes {
		return
	}
	for q.queue.Len() > 0 && q.bufferedBytes+incoming > q.maxBytes {
		oldest := heap.Pop(&q.queue).(*RetransmitEntry)
		q.bufferedBytes -= oldest.PayloadBytes
		if q.onEvict != nil {
			q.onEvict(oldest)
		}
	}
	if q.bufferedBytes < 0 {
		q.bufferedBytes = 0
	}
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
	q.evictForRoomLocked(incoming)

	now := time.Now()
	rto := q.rtt.RTO()
	entry := &RetransmitEntry{
		Frame:        se.Frame,
		Send:         se,
		PayloadBytes: incoming,
		NextRetry:    now.Add(rto),
		EnqueuedAt:   now,
		Retries:      0,
		RTO:          rto,
	}
	heap.Push(&q.queue, entry)
	q.bufferedBytes += incoming
}

// Dequeue returns the next frame due for retransmit (NextRetry <= now).
// Returns nil if no frames are due. Automatically re-enqueues the entry
// with doubled RTO (exponential backoff) if maxRetries is not exceeded.
//
// Loops past any heap-top entries whose SendWindow side has already been
// marked Acked — ProcessCompositeACK marks Send.Acked=true and removes
// the entry from retransmitQ in two separate operations, and an RTO
// firing in that TOCTOU window would otherwise replay an already-
// delivered frame. Silently dropping just the heap top would block the
// next legitimately-due entry behind it for one tick; loop so callers
// always see the freshest unACKed due frame in a single call.
func (q *RetransmitQueue) Dequeue() *aether.Frame {
	q.mu.Lock()
	defer q.mu.Unlock()

	for {
		if q.queue.Len() == 0 {
			return nil
		}

		// Peek at the earliest entry
		entry := q.queue.data[0]
		if time.Now().Before(entry.NextRetry) {
			return nil // not due yet
		}

		// Pop it. The entry's own count, not the frame's current length:
		// this runs on reliabilityTick while the write loop may be
		// committing the frame (see RetransmitEntry.PayloadBytes).
		heap.Pop(&q.queue)
		entryBytes := entry.PayloadBytes

		// Drop entries whose underlying SendWindow entry was already ACKed.
		// Send is nil for callers that use Enqueue without a shared
		// *SendEntry — the check is gated on it. Counter surfaces the
		// drop so post-ACK RTO
		// races don't manifest as silent retransmit suppression.
		if entry.Send != nil && entry.Send.Acked {
			q.bufferedBytes -= entryBytes
			if q.bufferedBytes < 0 {
				q.bufferedBytes = 0
			}
			atomic.AddUint64(&q.ackedOnDequeue, 1)
			continue // try the next due entry
		}

		return q.advanceEntryLocked(entry, entryBytes)
	}
}

// advanceEntryLocked handles the post-pop bookkeeping for a non-ACKed
// retransmit entry: retry counting, deadline/cap checks, RTO backoff,
// re-enqueue. Returns the frame to retransmit, or nil if the entry was
// dropped because of deadline or maxRetries.
//
// Caller holds q.mu. Split out of Dequeue so the ACKed-on-dequeue loop
// can `continue` past stale entries without nesting all of this logic.
func (q *RetransmitQueue) advanceEntryLocked(entry *RetransmitEntry, entryBytes int64) *aether.Frame {
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
			// Honour the onEvict contract on the deadline drop path too (as
			// evictForRoomLocked does); without it an expired frame vanishes
			// with no credit release, metric or stream signal.
			if q.onEvict != nil {
				q.onEvict(entry)
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
		// Notify onEvict on the max-retries drop as well.
		if q.onEvict != nil {
			q.onEvict(entry)
		}
		return nil // exceeded max retries — drop
	}

	// Re-enqueue with doubled RTO (exponential backoff). bufferedBytes
	// is unchanged since the same entry stays in the queue.
	//
	// Reconcile the doubled value with the live RTTEstimator RTO so the
	// entry never retransmits earlier than the path's current RTT, and
	// never stays stuck at a stale-high value after the estimator recovers:
	//   - live > doubled  → RTT spiked above our backoff; take the live RTO
	//     (keeping the smaller doubled value here would retransmit early
	//     and produce spurious duplicates after a spike).
	//   - live*2 < doubled → estimator recovered well below; catch down to
	//     live*2 so an earlier backoff doesn't stay pinned.
	//   - otherwise        → keep the doubled value.
	entry.RTO *= 2
	if live := q.rtt.RTO(); live > 0 {
		if live > entry.RTO {
			entry.RTO = live
		} else if live*2 < entry.RTO {
			entry.RTO = live * 2
		}
	}
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

// Clear drops every entry and reports how many it dropped, for a stream that has
// ended: its frames are owed no retransmit, so an entry left here would be handed to
// whatever the caller's next Dequeue feeds, and the adapter's reliability tick, which
// works from a snapshot of its streams, could put an ended stream's frame under an ID
// the next stream has taken. noiseStream.teardown calls it. It does not call onEvict:
// no reliable frame of a live stream loses its safety net here.
func (q *RetransmitQueue) Clear() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	n := len(q.queue.data)
	for i := range q.queue.data {
		q.queue.data[i].index = -1
		q.queue.data[i] = nil
	}
	q.queue.data = q.queue.data[:0]
	clear(q.seqIndex)
	q.bufferedBytes = 0
	return n
}

// AckedOnDequeueCount returns the number of retransmit entries dropped
// at Dequeue time because their underlying SendEntry was already Acked
// by ProcessCompositeACK in the window before Remove ran. A non-zero
// rate is benign: each count is a duplicate retransmit withheld; a
// sustained high rate means ACKs and RTOs are interleaving
// pathologically and is worth investigating.
func (q *RetransmitQueue) AckedOnDequeueCount() uint64 {
	return atomic.LoadUint64(&q.ackedOnDequeue)
}

// BufferedBytes returns the payload bytes of the entries the queue holds,
// the sum the cap SetMaxBytes sets is compared against.
func (q *RetransmitQueue) BufferedBytes() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.bufferedBytes
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
