/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

// Package scheduler implements weighted fair queuing (WFQ) for Aether streams.
// Streams have weights and dependencies forming a priority tree.
// Higher-weight streams get proportionally more bandwidth.
package scheduler

import (
	"sync"

	"github.com/ORBTR/aether"
)

// DefaultWeight is the default scheduling weight for new streams.
const DefaultWeight uint8 = 128

// Scheduler implements weighted fair queuing across Aether streams.
// Each stream has a weight (1-255) and an optional dependency (parent stream).
// The scheduler decides which stream's frame to send next when multiple
// streams have data ready.
// RealtimeCapPercent is the maximum fraction of bandwidth that REALTIME streams
// can consume before being temporarily demoted to INTERACTIVE priority.
// Prevents a misbehaving REALTIME caller from starving other classes.
const RealtimeCapPercent = 10

type Scheduler struct {
	mu      sync.Mutex
	streams map[uint64]*scheduledStream
	order   []uint64 // round-robin order for WFQ

	// REALTIME bandwidth cap tracking
	realtimeBytes int64 // bytes sent from REALTIME class in current window
	totalBytes    int64 // total bytes sent in current window

	// Wake channel — Enqueue does a non-blocking signal so the writeLoop
	// can park on a select instead of polling with time.Sleep(1ms).
	// Buffered at 1: a single pending signal collapses any number of
	// Enqueue events that landed before the writeLoop drained.
	wakeCh chan struct{}
}

type scheduledStream struct {
	streamID     uint64
	weight       uint8
	dependency   uint64 // parent stream ID (0 = root)
	latencyClass aether.LatencyClass
	queue        []*aether.Frame
	// probe holds a pending TLP loss probe (RFC 8985 §7.5). At most one
	// probe per stream — TLP semantics permits a single probe in flight
	// at a time, and a re-arm replaces any pending one. Probes are
	// dequeued ahead of `queue` and are transmitted outside the
	// congestion window (the writeLoop bypasses CanSend when Dequeue
	// reports isProbe=true).
	probe        *aether.Frame
	deficit      float64 // WFQ virtual finish time
	isRetransmit bool    // next frame is a retransmit (cost 2x)
}

// NewScheduler creates an empty scheduler.
func NewScheduler() *Scheduler {
	return &Scheduler{
		streams: make(map[uint64]*scheduledStream),
		wakeCh:  make(chan struct{}, 1),
	}
}

// WakeCh returns a channel that fires whenever Enqueue makes new work
// available. Consumers (writeLoop) park on it instead of polling.
// The channel is buffered at 1: multiple Enqueue calls between drains
// collapse to one signal — Dequeue must drain its queues until empty
// after each wake.
func (s *Scheduler) WakeCh() <-chan struct{} {
	return s.wakeCh
}

// signalWake performs a non-blocking send on wakeCh.
// Caller must NOT hold s.mu (a blocked send would deadlock with
// any consumer that tries to take s.mu after waking).
func (s *Scheduler) signalWake() {
	select {
	case s.wakeCh <- struct{}{}:
	default:
		// Already pending — writeLoop will see this enqueue when it drains.
	}
}

// Wake forces an external wake-up. Use when something other than Enqueue
// has changed (e.g. congestion window advanced, pacer rate raised) and
// the writeLoop should re-evaluate even though no new frame was queued.
func (s *Scheduler) Wake() {
	s.signalWake()
}

// MarkRetransmit flags the next enqueue for a stream as a retransmit (2x cost penalty).
// Called by the reliability layer when re-enqueuing a frame after RTO or NACK.
func (s *Scheduler) MarkRetransmit(streamID uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ss, ok := s.streams[streamID]; ok {
		ss.isRetransmit = true
	}
}

// Register adds a stream to the scheduler with the given weight, dependency, and latency class.
func (s *Scheduler) Register(streamID uint64, weight uint8, dependency uint64) {
	s.RegisterWithClass(streamID, weight, dependency, aether.DefaultLatencyClass(streamID))
}

// RegisterWithClass adds a stream with an explicit latency class.
func (s *Scheduler) RegisterWithClass(streamID uint64, weight uint8, dependency uint64, class aether.LatencyClass) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if weight == 0 {
		weight = DefaultWeight
	}

	s.streams[streamID] = &scheduledStream{
		streamID:     streamID,
		weight:       weight,
		dependency:   dependency,
		latencyClass: class,
	}
	s.order = append(s.order, streamID)
}

// Unregister removes a stream from the scheduler. Any queued frames are
// dropped — but they're returned to the caller (and the pending probe,
// if any) so upper layers can release the flow-control credit they
// reserved at Enqueue time. Without that return path, every
// stream-teardown burnt the credit reserved for in-queue frames,
// eventually draining the conn-level window (was the
// H-Scheduler-Unregister-Leak finding).
//
// Returns (droppedFrames, droppedProbe). Callers (adapter teardown
// paths) iterate the frames and call ReleaseUnsent on stream-window +
// conn-window for each payload length.
func (s *Scheduler) Unregister(streamID uint64) (droppedFrames []*aether.Frame, droppedProbe *aether.Frame) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if ss, ok := s.streams[streamID]; ok {
		if len(ss.queue) > 0 {
			droppedFrames = append([]*aether.Frame(nil), ss.queue...)
		}
		droppedProbe = ss.probe
	}
	delete(s.streams, streamID)

	// Remove from order
	for i, id := range s.order {
		if id == streamID {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
	return droppedFrames, droppedProbe
}

// SetWeight updates a stream's scheduling weight.
func (s *Scheduler) SetWeight(streamID uint64, weight uint8) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if ss, ok := s.streams[streamID]; ok {
		if weight == 0 {
			weight = DefaultWeight
		}
		ss.weight = weight
	}
}

// Enqueue adds a frame to a stream's send queue and wakes the writeLoop.
// If the stream is not registered, the frame is dropped silently.
func (s *Scheduler) Enqueue(streamID uint64, frame *aether.Frame) {
	s.mu.Lock()
	queued := false
	if ss, ok := s.streams[streamID]; ok {
		ss.queue = append(ss.queue, frame)
		queued = true
	}
	s.mu.Unlock()
	if queued {
		s.signalWake()
	}
}

// EnqueueProbe queues a TLP loss probe for a stream. Per RFC 8985 §7.5
// the probe MUST be transmitted outside the congestion window so it can
// recover from cwnd-collapse deadlocks (where every retransmit is
// blocked by CanSend because losses have driven cwnd to zero). The
// scheduler holds at most one probe per stream (TLP allows one in
// flight at a time); a subsequent EnqueueProbe replaces the prior
// pending probe when TLP re-arms. Probes are dequeued ahead of every
// other class — including REALTIME — because they are the only way to
// break a stalled connection.
//
// Pairs with Dequeue's isProbe return: the writeLoop reads the flag
// and bypasses the CanSend check, completing the §7.5 contract.
func (s *Scheduler) EnqueueProbe(streamID uint64, frame *aether.Frame) {
	s.mu.Lock()
	queued := false
	if ss, ok := s.streams[streamID]; ok {
		ss.probe = frame
		queued = true
	}
	s.mu.Unlock()
	if queued {
		s.signalWake()
	}
}

// Dequeue returns the next frame to send and whether it is a TLP probe.
//
// Ordering (strict, top-down):
//  1. Pending TLP probes across any stream — absolute priority (RFC 8985
//     §7.5: probes must be sent promptly to recover from cwnd collapse).
//  2. REALTIME class (unless over RealtimeCapPercent bandwidth share).
//  3. INTERACTIVE class.
//  4. BULK class.
//
// Within steps 2–4, WFQ picks the best stream by virtual finish time.
//
// isProbe=true tells the writeLoop to bypass congestion-window checks
// (CanSend) for this frame, per RFC 8985 §7.5. isProbe=false means the
// frame goes through normal cwnd flow control.
func (s *Scheduler) Dequeue() (*aether.Frame, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// s.order iteration safety: every mutator of s.order
	// (Register / Unregister / RegisterWithClass) also acquires s.mu,
	// so the backing array cannot be reallocated mid-iteration. If a
	// future refactor introduces an unlock-relock pattern inside this
	// function, snapshot s.order into a local slice before iterating.
	if len(s.order) == 0 {
		return nil, false
	}

	// 1. TLP probes have absolute priority. Walk s.order so probes are
	// drained in a stable, registration-ordered sequence rather than
	// map-iteration order (deterministic ordering helps tests + log
	// readability without affecting correctness).
	for _, streamID := range s.order {
		ss, ok := s.streams[streamID]
		if !ok || ss.probe == nil {
			continue
		}
		frame := ss.probe
		ss.probe = nil
		// Probes do not consume the REALTIME cap counters — they are
		// recovery traffic, not application traffic.
		return frame, true
	}

	// 2. Determine if REALTIME is over its bandwidth cap
	realtimeCapped := false
	if s.totalBytes > 0 && s.realtimeBytes*100/s.totalBytes > int64(RealtimeCapPercent) {
		realtimeCapped = true
	}
	// Decay counters periodically to avoid unbounded growth
	if s.totalBytes > 1024*1024 { // reset after 1MB window
		s.realtimeBytes /= 2
		s.totalBytes /= 2
	}

	// 3. Try each latency class in priority order: REALTIME → INTERACTIVE → BULK
	// If REALTIME is capped, skip it and let INTERACTIVE/BULK catch up
	for _, targetClass := range []aether.LatencyClass{aether.ClassREALTIME, aether.ClassINTERACTIVE, aether.ClassBULK} {
		if targetClass == aether.ClassREALTIME && realtimeCapped {
			continue // REALTIME over 10% cap — demote to INTERACTIVE round
		}
		frame := s.dequeueFromClass(targetClass)
		if frame != nil {
			// Track bandwidth per class for REALTIME cap
			bytesOut := int64(aether.HeaderSize) + int64(frame.Length)
			s.totalBytes += bytesOut
			if targetClass == aether.ClassREALTIME {
				s.realtimeBytes += bytesOut
			}
			return frame, false
		}
	}

	return nil, false
}

// dequeueFromClass picks the best frame within a specific latency class using WFQ.
func (s *Scheduler) dequeueFromClass(targetClass aether.LatencyClass) *aether.Frame {
	var bestIdx int = -1
	var bestFinish float64

	for i, streamID := range s.order {
		ss, ok := s.streams[streamID]
		if !ok || len(ss.queue) == 0 || ss.latencyClass != targetClass {
			continue
		}

		// Cost-aware virtual finish time:
		// cost = frameSize + retransmitPenalty
		// Retransmits cost 2x (discourages retransmit storms).
		// FEC repair frames cost 0.5x (encourage repair over retransmit).
		frameSize := float64(aether.HeaderSize) + float64(ss.queue[0].Length)
		cost := frameSize
		if ss.isRetransmit {
			cost *= 2.0 // retransmit penalty
		}
		if ss.queue[0].Type == aether.TypeFEC_REPAIR {
			cost *= 0.5 // FEC bonus (cheaper than retransmit)
		}
		finish := ss.deficit + cost/float64(ss.weight)

		if bestIdx == -1 || finish < bestFinish {
			bestIdx = i
			bestFinish = finish
		}
	}

	if bestIdx == -1 {
		return nil
	}

	streamID := s.order[bestIdx]
	ss := s.streams[streamID]
	frame := ss.queue[0]
	ss.queue = ss.queue[1:]

	// Advance virtual time
	frameSize := float64(aether.HeaderSize) + float64(frame.Length)
	ss.deficit += frameSize / float64(ss.weight)

	// Clear the retransmit flag after consuming it. The flag is documented
	// as single-shot ("next enqueue for a stream as a retransmit") but was
	// only ever set true and never cleared — so any stream that ever lost
	// a packet kept the 2x WFQ cost penalty applied to every subsequent
	// non-retransmit frame for the rest of the stream's lifetime,
	// permanently de-prioritising it against healthy peers. Clear here,
	// inside the same s.mu critical section that owns ss.isRetransmit.
	ss.isRetransmit = false

	return frame
}

// IsEmpty returns true if all stream queues — including pending TLP
// probes — are empty.
func (s *Scheduler) IsEmpty() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, ss := range s.streams {
		if len(ss.queue) > 0 || ss.probe != nil {
			return false
		}
	}
	return true
}

// Len returns the total number of queued frames across all streams,
// including any pending TLP probes.
func (s *Scheduler) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	total := 0
	for _, ss := range s.streams {
		total += len(ss.queue)
		if ss.probe != nil {
			total++
		}
	}
	return total
}

// QueueLen returns the number of queued frames for a specific stream.
func (s *Scheduler) QueueLen(streamID uint64) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	if ss, ok := s.streams[streamID]; ok {
		return len(ss.queue)
	}
	return 0
}

// StreamCount returns the number of registered streams.
func (s *Scheduler) StreamCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.streams)
}
