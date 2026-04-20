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
	// See _implementation_plan.md Concern #2.
	wakeCh chan struct{}
}

type scheduledStream struct {
	streamID     uint64
	weight       uint8
	dependency   uint64 // parent stream ID (0 = root)
	latencyClass aether.LatencyClass
	queue        []*aether.Frame
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

// Unregister removes a stream from the scheduler. Any queued frames are dropped.
func (s *Scheduler) Unregister(streamID uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.streams, streamID)

	// Remove from order
	for i, id := range s.order {
		if id == streamID {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
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

// Dequeue returns the next frame to send based on latency class + weighted fair queuing.
// Returns nil if all queues are empty.
//
// Algorithm:
//  1. Strict priority between latency classes: REALTIME > INTERACTIVE > BULK
//  2. Within each class: WFQ via virtual finish time (weight-proportional)
//
// This ensures control plane frames (REALTIME) never wait behind bulk data.
func (s *Scheduler) Dequeue() *aether.Frame {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.order) == 0 {
		return nil
	}

	// Determine if REALTIME is over its bandwidth cap
	realtimeCapped := false
	if s.totalBytes > 0 && s.realtimeBytes*100/s.totalBytes > int64(RealtimeCapPercent) {
		realtimeCapped = true
	}
	// Decay counters periodically to avoid unbounded growth
	if s.totalBytes > 1024*1024 { // reset after 1MB window
		s.realtimeBytes /= 2
		s.totalBytes /= 2
	}

	// Try each latency class in priority order: REALTIME → INTERACTIVE → BULK
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
			return frame
		}
	}

	return nil
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

	return frame
}

// IsEmpty returns true if all stream queues are empty.
func (s *Scheduler) IsEmpty() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, ss := range s.streams {
		if len(ss.queue) > 0 {
			return false
		}
	}
	return true
}

// Len returns the total number of queued frames across all streams.
func (s *Scheduler) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	total := 0
	for _, ss := range s.streams {
		total += len(ss.queue)
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
