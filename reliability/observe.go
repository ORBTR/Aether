/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package reliability

import (
	"sync"
	"time"
)

// StreamObserveMetrics holds per-stream observation metrics.
// Returned by ObserveEngine.Metrics() for monitoring and adaptive decisions.
type StreamObserveMetrics struct {
	PacketsReceived      int64  `json:"packetsReceived"`
	BytesReceived        int64  `json:"bytesReceived"`
	HighestSeqNo         uint32 `json:"highestSeqNo"`
	GapCount             int64  `json:"gapCount"`     // cumulative: total forward gaps ever observed (not current missing)
	ReorderCount         int64  `json:"reorderCount"` // cumulative: total out-of-order arrivals
	MaxReorderDistance   int    `json:"maxReorderDistance"`
	LossEstimatePermille int    `json:"lossEstimatePermille"` // 0-1000, cumulative (highestSeq - received) / highestSeq
	JitterUs             int64  `json:"jitterUs"`             // inter-arrival jitter in µs (RFC 3550 EMA)
}

// ObserveEngine tracks receive-side stream metrics without generating ACK
// frames or enforcing reliability. Used on TCP/WS/QUIC adapters for uniform
// observability across all transport types.
//
// Thread-safe via mutex. All fields accessed under o.mu.
//
// Semantics:
//   - GapCount is cumulative (total forward gaps ever seen, never decremented).
//     A gap of 3 missing SeqNos counts as 3. Late arrivals increment ReorderCount
//     but do NOT decrement GapCount.
//   - LossEstimate is cumulative over the session lifetime: (highestSeq - received) / highestSeq.
//     Early loss is diluted over time. For windowed loss, use the ACKEngine's ring buffer.
type ObserveEngine struct {
	mu sync.Mutex

	expectedSeq uint32
	highestSeq  uint32
	lastArrival time.Time

	packetsReceived int64
	bytesReceived   int64
	gapCount        int64
	reorderCount    int64
	maxReorderDist  int

	jitterUs int64 // RFC 3550 exponential moving average

	prevInterarrivalUs   int64 // previous inter-arrival spacing (µs) for jitter variation
	havePrevInterarrival bool

	lossWindowReceived int64
	lossWindowExpected int64
}

// NewObserveEngine creates a new per-stream observation engine.
// expectedSeq starts at 0 because Aether stream sequence numbers start at 0;
// seeding it to 1 counted every stream's first frame (seq 0) as a reorder.
func NewObserveEngine() *ObserveEngine {
	return &ObserveEngine{expectedSeq: 0}
}

// RecordReceive records a received data frame.
// seqNo is the Aether frame SeqNo (or a local monotonic counter on TCP).
// size is the payload byte count.
func (o *ObserveEngine) RecordReceive(seqNo uint32, size int, arrivalTime time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.packetsReceived++
	o.bytesReceived += int64(size)

	if seqNo > o.highestSeq {
		o.highestSeq = seqNo
	}

	// The first frame establishes the sequence baseline and must not be
	// counted as a gap or reorder. Different transports start their counter
	// at different values (Aether/noise stream seqs start at 0; the TCP
	// adapter feeds a monotonic counter starting at 1), so anchoring on the
	// first observed seq is more robust than a fixed initial expectedSeq —
	// seeding expectedSeq to 1 previously mislabelled seq 0 as a reorder.
	if o.packetsReceived == 1 {
		o.expectedSeq = seqNo + 1
	} else if seqNo > o.expectedSeq {
		o.gapCount += int64(seqNo - o.expectedSeq)
		o.expectedSeq = seqNo + 1
	} else if seqNo == o.expectedSeq {
		o.expectedSeq = seqNo + 1
	} else {
		o.reorderCount++
		dist := int(o.expectedSeq - seqNo)
		if dist > o.maxReorderDist {
			o.maxReorderDist = dist
		}
	}

	// Inter-arrival jitter (RFC 3550 §A.8). We have no sender timestamp on
	// the data path, so we approximate transit-time variation by the change
	// in inter-arrival spacing between consecutive packets: for a uniformly
	// paced sender, variation in arrival spacing ≈ variation in transit time.
	// EMAing the raw spacing (the previous behaviour) converged to the mean
	// inter-arrival interval instead — a steady 20 ms stream reported
	// ~20000 µs of "jitter" rather than ~0, making the metric useless.
	if !o.lastArrival.IsZero() {
		diff := arrivalTime.Sub(o.lastArrival).Microseconds()
		if diff < 0 {
			diff = -diff
		}
		if o.havePrevInterarrival {
			d := diff - o.prevInterarrivalUs
			if d < 0 {
				d = -d
			}
			o.jitterUs += (d - o.jitterUs) / 16
		}
		o.prevInterarrivalUs = diff
		o.havePrevInterarrival = true
	}
	o.lastArrival = arrivalTime

	o.lossWindowReceived++
	o.lossWindowExpected = int64(o.highestSeq)
}

// Metrics returns a snapshot of current observation metrics.
func (o *ObserveEngine) Metrics() StreamObserveMetrics {
	o.mu.Lock()
	defer o.mu.Unlock()

	var lossPermille int
	if o.lossWindowExpected > 0 {
		missed := o.lossWindowExpected - o.lossWindowReceived
		if missed < 0 {
			missed = 0
		}
		lossPermille = int(missed * 1000 / o.lossWindowExpected)
	}

	return StreamObserveMetrics{
		PacketsReceived:      o.packetsReceived,
		BytesReceived:        o.bytesReceived,
		HighestSeqNo:         o.highestSeq,
		GapCount:             o.gapCount,
		ReorderCount:         o.reorderCount,
		MaxReorderDistance:   o.maxReorderDist,
		LossEstimatePermille: lossPermille,
		JitterUs:             o.jitterUs,
	}
}

// Reset clears all counters.
func (o *ObserveEngine) Reset() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.expectedSeq = 1
	o.highestSeq = 0
	o.lastArrival = time.Time{}
	o.packetsReceived = 0
	o.bytesReceived = 0
	o.gapCount = 0
	o.reorderCount = 0
	o.maxReorderDist = 0
	o.jitterUs = 0
	o.lossWindowReceived = 0
	o.lossWindowExpected = 0
}
