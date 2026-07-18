/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

// Package scheduler implements weighted fair queuing (WFQ) for Aether streams.
// Streams have weights and dependencies forming a priority tree.
// Higher-weight streams get proportionally more bandwidth.
package scheduler

import (
	"sync"
	"sync/atomic"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/metrics"
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
	nonBulkStreak int   // AER-082: consecutive non-BULK dequeues (BULK anti-starvation)

	// Wake channel — Enqueue does a non-blocking signal so the writeLoop
	// can park on a select instead of polling with time.Sleep(1ms).
	// Buffered at 1: a single pending signal collapses any number of
	// Enqueue events that landed before the writeLoop drained.
	wakeCh chan struct{}

	// queueDepth tracks the total number of frames currently queued
	// across all streams (including pending TLP probes). Maintained as
	// an atomic counter so OBS-9 scheduler-depth sampling does not need
	// to acquire s.mu and walk the stream map (which Len() does).
	// Mutated inside the same s.mu critical sections that own the
	// queues — eventual consistency is bounded to the moment between
	// queue-mutation and counter-add.
	queueDepth atomic.Int64

	// depthHist is the optional OBS-9 scheduler-depth histogram. Wired
	// by the owning session via SetDepthHist; nil disables sampling
	// (default for schedulers constructed via NewScheduler). Sampled on
	// every wake-signal path (Enqueue / EnqueueProbe / external Wake)
	// and on every ObserveDepth call (writeLoop just before parking on
	// WakeCh) — the two events the audit identified as the natural
	// sampling points for queue depth.
	depthHist *metrics.Uint32Ring
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

// SetDepthHist wires an OBS-9 scheduler-depth histogram into the
// scheduler. Sampled on every wake signal (Enqueue / EnqueueProbe /
// external Wake) and on every ObserveDepth call (writeLoop just before
// it parks on WakeCh) so the histogram captures both the "work arrives"
// and "queue drained, idle" faces of the queue-depth distribution.
//
// Must be called BEFORE the scheduler sees concurrent traffic. The
// field is wired once at session-create time and never swapped —
// concurrent reads of an immutable pointer don't need atomic protection.
// Pass nil to disable (default for schedulers constructed via
// NewScheduler).
func (s *Scheduler) SetDepthHist(h *metrics.Uint32Ring) {
	s.depthHist = h
}

// recordDepth pushes the current queue depth into the wired OBS-9
// histogram (no-op if SetDepthHist hasn't been called). Internal
// helper shared by signalWake (work-arrives face) and ObserveDepth
// (drained-idle face). Cost: one atomic.Load plus one mutex'd uint32
// store to the ring — well under 100 ns.
func (s *Scheduler) recordDepth() {
	if s.depthHist == nil {
		return
	}
	d := s.queueDepth.Load()
	if d < 0 {
		d = 0
	}
	if d > 0xFFFFFFFF {
		d = 0xFFFFFFFF
	}
	s.depthHist.Record(uint32(d))
}

// ObserveDepth records the current queue depth into the wired OBS-9
// histogram. Called by the writeLoop just before it parks on WakeCh so
// the histogram sees the "queue drained, idle" tail of the
// distribution as well as the "work arrives" tail captured at
// signalWake. No-op if SetDepthHist hasn't been called.
func (s *Scheduler) ObserveDepth() {
	s.recordDepth()
}

// signalWake performs a non-blocking send on wakeCh.
// Caller must NOT hold s.mu (a blocked send would deadlock with
// any consumer that tries to take s.mu after waking).
//
// Side-effect: samples the current queue depth into the OBS-9
// histogram if wired. signalWake fires on every Enqueue /
// EnqueueProbe / external Wake() so this samples the "work-arrives"
// face of the depth distribution; the writeLoop's pre-park
// ObserveDepth() captures the "queue-drained, idle" face. Together
// they describe the full scheduler-occupancy distribution.
func (s *Scheduler) signalWake() {
	s.recordDepth()
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
			s.queueDepth.Add(-int64(len(ss.queue)))
		}
		droppedProbe = ss.probe
		if droppedProbe != nil {
			s.queueDepth.Add(-1)
		}
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
		// AE-M-08: seed an idle/newly-registered stream's WFQ deficit up to
		// the current virtual start time of its class on the empty→backlogged
		// edge. A stream registers (and re-registers on reopen) with
		// deficit=0, and dequeueFromClass selects the minimum-finish stream,
		// so a zero-deficit newcomer would win every Dequeue in its class
		// until its deficit climbed to match — starving established same-class
		// streams for that catch-up window (and giving a trivial
		// re-registration griefing lever). Seeding to the class minimum
		// equalises the newcomer with the current front-runner; the `>` guard
		// only ever raises the deficit, so a stream already ahead (one whose
		// queue briefly drained mid-send) keeps its earned virtual time and is
		// never demoted. Mirrors the multipath WDRR seed at
		// manager.go:addPathLocked.
		if len(ss.queue) == 0 {
			if vs := s.classVirtualStartLocked(ss.latencyClass); vs > ss.deficit {
				ss.deficit = vs
			}
		}
		ss.queue = append(ss.queue, frame)
		queued = true
		s.queueDepth.Add(1)
	}
	s.mu.Unlock()
	if queued {
		s.signalWake()
	}
}

// classVirtualStartLocked returns the WFQ virtual start time for a latency
// class: the minimum deficit among the streams of that class that are
// currently backlogged (queue non-empty). Callers hold s.mu. Returns 0 when
// no stream of the class is backlogged — Enqueue's `>` guard then leaves the
// caller's own deficit untouched. Used to seed an idle/newly-registered
// stream so it cannot monopolise its class from deficit=0 (AE-M-08).
func (s *Scheduler) classVirtualStartLocked(class aether.LatencyClass) float64 {
	found := false
	var minDeficit float64
	for _, ss := range s.streams {
		if ss.latencyClass != class || len(ss.queue) == 0 {
			continue
		}
		if !found || ss.deficit < minDeficit {
			minDeficit = ss.deficit
			found = true
		}
	}
	return minDeficit
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
		// Probes replace any prior pending probe — only the net delta
		// (+1 if no probe was pending, 0 if one was) goes into the
		// depth counter so it tracks actual queue occupancy.
		if ss.probe == nil {
			s.queueDepth.Add(1)
		}
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

	// Snapshot s.order into a local slice before iterating. Even though
	// every mutator of s.order acquires s.mu, snapshotting decouples the
	// iteration from any future refactor that introduces an unlock-relock
	// pattern (or a helper that mutates s.order while iterating) — a
	// concurrent Unregister reallocating the backing array mid-iteration
	// would otherwise cause an index skip or out-of-bounds crash. The
	// copy is cheap (uint64 per stream) and immune to mutation.
	if len(s.order) == 0 {
		return nil, false
	}
	order := append([]uint64(nil), s.order...)

	// 1. TLP probes have absolute priority. Walk order so probes are
	// drained in a stable, registration-ordered sequence rather than
	// map-iteration order (deterministic ordering helps tests + log
	// readability without affecting correctness).
	for _, streamID := range order {
		ss, ok := s.streams[streamID]
		if !ok || ss.probe == nil {
			continue
		}
		frame := ss.probe
		ss.probe = nil
		s.queueDepth.Add(-1)
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

	// 3. Try each latency class in priority order: REALTIME → INTERACTIVE → BULK.
	// AE-H-05: a capped REALTIME class is DEMOTED into the INTERACTIVE round
	// (its streams compete there via WFQ) rather than dropped from every round.
	// Dropping it stalled a REALTIME-only connection forever: with no other
	// class queued, Dequeue returned nil, totalBytes froze below the 1MB decay
	// threshold, and the pinned >10% ratio never recovered. Demotion keeps the
	// cap's purpose (REALTIME loses its absolute priority over other classes)
	// while guaranteeing forward progress when nothing else competes.
	// AER-082: anti-starvation floor for BULK. Strict class priority (only
	// REALTIME is capped) otherwise lets a saturating INTERACTIVE stream starve
	// BULK indefinitely. After bulkStarvationLimit consecutive non-BULK
	// dequeues, serve one BULK frame first if any is queued so BULK always
	// makes forward progress.
	if s.nonBulkStreak >= bulkStarvationLimit {
		s.nonBulkStreak = 0
		if frame, _ := s.dequeueFromClass(aether.ClassBULK, order, false); frame != nil {
			s.totalBytes += int64(aether.HeaderSize) + int64(frame.Length)
			return frame, false
		}
		// No BULK queued — fall through to the normal priority order.
	}

	for _, targetClass := range []aether.LatencyClass{aether.ClassREALTIME, aether.ClassINTERACTIVE, aether.ClassBULK} {
		if targetClass == aether.ClassREALTIME && realtimeCapped {
			continue // capped REALTIME is served in the INTERACTIVE round below
		}
		// Fold capped REALTIME streams into the INTERACTIVE round so their
		// frames still make progress at INTERACTIVE priority (AE-H-05).
		demoteRealtime := realtimeCapped && targetClass == aether.ClassINTERACTIVE
		frame, isRealtime := s.dequeueFromClass(targetClass, order, demoteRealtime)
		if frame != nil {
			// Track bandwidth per class for REALTIME cap. A demoted REALTIME
			// frame served in the INTERACTIVE round still counts as REALTIME
			// so the cap ratio stays accurate.
			bytesOut := int64(aether.HeaderSize) + int64(frame.Length)
			s.totalBytes += bytesOut
			if isRealtime {
				s.realtimeBytes += bytesOut
			}
			// AER-082: track the non-BULK streak for the anti-starvation floor.
			if targetClass == aether.ClassBULK {
				s.nonBulkStreak = 0
			} else {
				s.nonBulkStreak++
			}
			return frame, false
		}
	}

	return nil, false
}

// bulkStarvationLimit is the number of consecutive non-BULK dequeues after
// which the scheduler forces one BULK frame to prevent starvation (AER-082).
const bulkStarvationLimit = 16

// dequeueFromClass picks the best frame within a specific latency class using WFQ.
// order is the caller's snapshot of s.order (see Dequeue): iterating the snapshot
// keeps this routine immune to concurrent Unregister reallocations even if a
// future refactor unlocks s.mu mid-Dequeue.
//
// includeRealtime folds REALTIME streams into this round in addition to
// targetClass — used to serve a capped (demoted) REALTIME class in the
// INTERACTIVE round (AE-H-05). The returned bool reports whether the chosen
// frame belonged to a REALTIME stream so the caller charges the REALTIME
// bandwidth counter correctly.
func (s *Scheduler) dequeueFromClass(targetClass aether.LatencyClass, order []uint64, includeRealtime bool) (*aether.Frame, bool) {
	var bestIdx int = -1
	var bestFinish float64

	for i, streamID := range order {
		ss, ok := s.streams[streamID]
		if !ok || len(ss.queue) == 0 {
			continue
		}
		// Serve the target class, plus REALTIME streams when a capped REALTIME
		// class is being demoted into this round (AE-H-05).
		if ss.latencyClass != targetClass && !(includeRealtime && ss.latencyClass == aether.ClassREALTIME) {
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
		return nil, false
	}

	streamID := order[bestIdx]
	ss := s.streams[streamID]
	frame := ss.queue[0]
	ss.queue = ss.queue[1:]
	s.queueDepth.Add(-1)

	// Advance virtual time by the SAME cost used for selection (AE-L-07),
	// not the raw frame size. Recompute the retransmit(2x)/FEC(0.5x) cost
	// for the chosen frame — mirroring the selection metric above — so the
	// penalty/bonus persists in the accumulated deficit instead of only
	// tilting the one-shot tie-break. Without this a stream that keeps
	// retransmitting accrues the same virtual time as a clean stream sending
	// equal bytes, defeating the "discourage retransmit storms / encourage
	// repair" intent. ss.isRetransmit is still set here (cleared below), so
	// this block MUST stay above that clear.
	frameSize := float64(aether.HeaderSize) + float64(frame.Length)
	cost := frameSize
	if ss.isRetransmit {
		cost *= 2.0 // retransmit penalty (mirrors selection cost)
	}
	if frame.Type == aether.TypeFEC_REPAIR {
		cost *= 0.5 // FEC bonus (mirrors selection cost)
	}
	ss.deficit += cost / float64(ss.weight)

	// Clear the retransmit flag after consuming it. The flag is documented
	// as single-shot ("next enqueue for a stream as a retransmit") but was
	// only ever set true and never cleared — so any stream that ever lost
	// a packet kept the 2x WFQ cost penalty applied to every subsequent
	// non-retransmit frame for the rest of the stream's lifetime,
	// permanently de-prioritising it against healthy peers. Clear here,
	// inside the same s.mu critical section that owns ss.isRetransmit.
	ss.isRetransmit = false

	return frame, ss.latencyClass == aether.ClassREALTIME
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
