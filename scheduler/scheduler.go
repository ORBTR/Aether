/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
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
	nonBulkStreak int   // consecutive non-BULK dequeues; Dequeue serves BULK at bulkStarvationLimit

	// Wake channel — Enqueue does a non-blocking signal so the writeLoop
	// can park on a select instead of polling with time.Sleep(1ms).
	// Buffered at 1: a single pending signal collapses any number of
	// Enqueue events that landed before the writeLoop drained.
	wakeCh chan struct{}

	// queueDepth tracks the total number of frames currently queued
	// across all streams (including pending TLP probes). Maintained as
	// an atomic counter so depth sampling (recordDepth) does not need
	// to acquire s.mu and walk the stream map (which Len() does).
	// Mutated inside the same s.mu critical sections that own the
	// queues — eventual consistency is bounded to the moment between
	// queue-mutation and counter-add.
	queueDepth atomic.Int64

	// registrations numbers the registrations: RegisterWithClass gives each the next
	// value, so no two registrations of one scheduler share a Registration.
	registrations uint64

	// depthHist is the optional scheduler-depth histogram. Wired
	// by the owning session via SetDepthHist; nil disables sampling
	// (default for schedulers constructed via NewScheduler). Sampled on
	// every wake-signal path (Enqueue / EnqueueProbe / external Wake)
	// and on every ObserveDepth call (writeLoop just before parking on
	// WakeCh) — the two natural sampling points for queue depth.
	depthHist *metrics.Uint32Ring
}

// Registration names one registration of a stream ID with the scheduler. The zero
// value names none. A session that reuses an ID for a later stream registers it again
// and gets a new Registration, so a frame Dequeue hands out (DequeueFrom) can be told
// from a frame of the stream that held the ID before (NoiseSession's write loop drops
// such a frame), and an ended stream's exit can leave alone the registration its
// successor holds (UnregisterRegistration).
type Registration uint64

type scheduledStream struct {
	streamID     uint64
	reg          Registration
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

// SetDepthHist wires a scheduler-depth histogram into the
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

// recordDepth pushes the current queue depth into the wired depth
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

// ObserveDepth records the current queue depth into the wired depth
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
// Side-effect: samples the current queue depth into the depth
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
func (s *Scheduler) Register(streamID uint64, weight uint8, dependency uint64) Registration {
	return s.RegisterWithClass(streamID, weight, dependency, aether.DefaultLatencyClass(streamID))
}

// RegisterWithClass adds a stream with an explicit latency class and returns the
// registration's name. A registration already under the ID is replaced: what it still
// held is dropped as Unregister drops it, and the ID keeps its place in the round-robin
// order. NoiseSession.createStream registers a stream before it publishes it, under the
// lock its exits take the stream out under, so the ID's next stream can replace the
// registration of a stream whose exit has not yet unregistered it.
func (s *Scheduler) RegisterWithClass(streamID uint64, weight uint8, dependency uint64, class aether.LatencyClass) Registration {
	s.mu.Lock()
	defer s.mu.Unlock()

	if weight == 0 {
		weight = DefaultWeight
	}

	s.registrations++
	reg := Registration(s.registrations)
	if prev, ok := s.streams[streamID]; ok {
		s.dropQueuedLocked(prev)
	} else {
		s.order = append(s.order, streamID)
	}
	s.streams[streamID] = &scheduledStream{
		streamID:     streamID,
		reg:          reg,
		weight:       weight,
		dependency:   dependency,
		latencyClass: class,
	}
	return reg
}

// dropQueuedLocked takes what a registration still holds out of the depth count and
// returns it. Callers hold s.mu and remove or replace the registration.
func (s *Scheduler) dropQueuedLocked(ss *scheduledStream) (droppedFrames []*aether.Frame, droppedProbe *aether.Frame) {
	if len(ss.queue) > 0 {
		droppedFrames = append([]*aether.Frame(nil), ss.queue...)
		s.queueDepth.Add(-int64(len(ss.queue)))
	}
	droppedProbe = ss.probe
	if droppedProbe != nil {
		s.queueDepth.Add(-1)
	}
	return droppedFrames, droppedProbe
}

// Unregister removes a stream from the scheduler and drops its queued frames
// and its pending probe, returning them as (droppedFrames, droppedProbe) for a
// caller that accounts for frames that will never reach the wire.
// TCPSession.releaseStream gives each dropped frame's room back to its stream's
// Send (releaseSendRoom). NoiseSession.releaseStream discards the return: the credit
// a dropped frame carries was charged by the stream's Send, which recorded the
// connection charge on the stream (noiseStream.commitConnCharge) before it called
// Enqueue. A reset stream's settlement counts every charge so recorded, these frames'
// included: the RESET closes the record (settleCharges, from settleLocalReset and
// settlePeerReset), and the peer's statement of what its consumer returned, its RESET
// of the stream or its acknowledgment of this side's (Consumed), returns the rest
// (returnUnconsumed), so nothing here is returned twice or left out. A stream that
// leaves on both CLOSEs has no frame left here.
func (s *Scheduler) Unregister(streamID uint64) (droppedFrames []*aether.Frame, droppedProbe *aether.Frame) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unregisterLocked(streamID, 0)
}

// UnregisterRegistration is Unregister for the registration reg alone: when the ID is
// registered again since (RegisterWithClass), the later registration stays as it is and
// nothing is dropped. NoiseSession.releaseStream passes the ending stream's registration,
// since a stream the peer opens under the ID can register between that stream's leaving
// s.streams and its exit reaching the scheduler.
func (s *Scheduler) UnregisterRegistration(streamID uint64, reg Registration) (droppedFrames []*aether.Frame, droppedProbe *aether.Frame) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unregisterLocked(streamID, reg)
}

// unregisterLocked removes the ID's registration, or only reg's when reg is not zero.
// Callers hold s.mu.
func (s *Scheduler) unregisterLocked(streamID uint64, reg Registration) (droppedFrames []*aether.Frame, droppedProbe *aether.Frame) {
	ss, ok := s.streams[streamID]
	if ok && reg != 0 && ss.reg != reg {
		return nil, nil
	}
	if ok {
		droppedFrames, droppedProbe = s.dropQueuedLocked(ss)
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

// Enqueue adds a frame to a stream's send queue and wakes the writeLoop, and
// reports whether it did: a stream that is not registered takes no frame, and a
// caller that promised the frame to someone (tcpStream.Send) tells them.
func (s *Scheduler) Enqueue(streamID uint64, frame *aether.Frame) bool {
	s.mu.Lock()
	queued := false
	if ss, ok := s.streams[streamID]; ok {
		// Seed an idle/newly-registered stream's WFQ deficit up to
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
	return queued
}

// classVirtualStartLocked returns the WFQ virtual start time for a latency
// class: the minimum deficit among the streams of that class that are
// currently backlogged (queue non-empty). Callers hold s.mu. Returns 0 when
// no stream of the class is backlogged — Enqueue's `>` guard then leaves the
// caller's own deficit untouched. Used to seed an idle/newly-registered
// stream so it cannot monopolise its class from deficit=0 (Enqueue).
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

// DequeueProbe returns the next pending TLP probe, or nil when none is pending.
// The writeLoop calls it in place of Dequeue while it holds a frame the CanSend
// gate refused: a probe goes outside the congestion window (RFC 8985 §7.5), so a
// refused frame must not stand in front of it.
func (s *Scheduler) DequeueProbe() *aether.Frame {
	frame, _ := s.DequeueProbeFrom()
	return frame
}

// DequeueProbeFrom is DequeueProbe that also names the registration the probe came
// from (DequeueFrom).
func (s *Scheduler) DequeueProbeFrom() (*aether.Frame, Registration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dequeueProbeLocked(s.order)
}

// dequeueProbeLocked takes the first pending probe in order and names its
// registration. Callers hold s.mu.
// Walks order so probes are drained in a stable, registration-ordered sequence
// rather than map-iteration order (deterministic ordering helps tests + log
// readability without affecting correctness). Probes do not consume the REALTIME
// cap counters — they are recovery traffic, not application traffic.
func (s *Scheduler) dequeueProbeLocked(order []uint64) (*aether.Frame, Registration) {
	for _, streamID := range order {
		ss, ok := s.streams[streamID]
		if !ok || ss.probe == nil {
			continue
		}
		frame := ss.probe
		ss.probe = nil
		s.queueDepth.Add(-1)
		return frame, ss.reg
	}
	return nil, 0
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
	frame, isProbe, _ := s.DequeueFrom()
	return frame, isProbe
}

// DequeueFrom is Dequeue that also names the registration the frame came from, zero
// with no frame. Frames are queued by stream ID, and a session that reuses an ID
// registers it again for the next stream (RegisterWithClass), so the ID alone does not
// say whose frame it is: NoiseSession's write loop compares the registration with the
// one the stream now under the ID holds, and drops a frame of a stream that has ended.
func (s *Scheduler) DequeueFrom() (*aether.Frame, bool, Registration) {
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
		return nil, false, 0
	}
	order := append([]uint64(nil), s.order...)

	// 1. TLP probes have absolute priority.
	if frame, reg := s.dequeueProbeLocked(order); frame != nil {
		return frame, true, reg
	}

	// 2. Determine if REALTIME is over its bandwidth cap
	realtimeCapped := s.totalBytes > 0 && s.realtimeBytes*100/s.totalBytes > int64(RealtimeCapPercent)
	// Decay counters periodically to avoid unbounded growth
	if s.totalBytes > 1024*1024 { // reset after 1MB window
		s.realtimeBytes /= 2
		s.totalBytes /= 2
	}

	// 3. Try each latency class in priority order: REALTIME → INTERACTIVE → BULK.
	// A capped REALTIME class is DEMOTED into the INTERACTIVE round
	// (its streams compete there via WFQ) rather than dropped from every round.
	// Dropped, a REALTIME-only connection would stall forever: with no other
	// class queued, Dequeue returns nil, totalBytes freezes below the 1MB decay
	// threshold, and the pinned >10% ratio never recovers. Demotion keeps the
	// cap's purpose (REALTIME loses its absolute priority over other classes)
	// while guaranteeing forward progress when nothing else competes.
	// Anti-starvation floor for BULK. Strict class priority (only
	// REALTIME is capped) otherwise lets a saturating INTERACTIVE stream starve
	// BULK indefinitely. After bulkStarvationLimit consecutive non-BULK
	// dequeues, serve one BULK frame first if any is queued so BULK always
	// makes forward progress.
	if s.nonBulkStreak >= bulkStarvationLimit {
		s.nonBulkStreak = 0
		if frame, _, reg := s.dequeueFromClass(aether.ClassBULK, order, false); frame != nil {
			s.totalBytes += int64(aether.HeaderSize) + int64(frame.Length)
			return frame, false, reg
		}
		// No BULK queued — fall through to the normal priority order.
	}

	for _, targetClass := range []aether.LatencyClass{aether.ClassREALTIME, aether.ClassINTERACTIVE, aether.ClassBULK} {
		if targetClass == aether.ClassREALTIME && realtimeCapped {
			continue // capped REALTIME is served in the INTERACTIVE round below
		}
		// Fold capped REALTIME streams into the INTERACTIVE round so their
		// frames still make progress at INTERACTIVE priority.
		demoteRealtime := realtimeCapped && targetClass == aether.ClassINTERACTIVE
		frame, isRealtime, reg := s.dequeueFromClass(targetClass, order, demoteRealtime)
		if frame != nil {
			// Track bandwidth per class for REALTIME cap. A demoted REALTIME
			// frame served in the INTERACTIVE round still counts as REALTIME
			// so the cap ratio stays accurate.
			bytesOut := int64(aether.HeaderSize) + int64(frame.Length)
			s.totalBytes += bytesOut
			if isRealtime {
				s.realtimeBytes += bytesOut
			}
			// Track the non-BULK streak for the anti-starvation floor.
			if targetClass == aether.ClassBULK {
				s.nonBulkStreak = 0
			} else {
				s.nonBulkStreak++
			}
			return frame, false, reg
		}
	}

	return nil, false, 0
}

// bulkStarvationLimit is the number of consecutive non-BULK dequeues after
// which the scheduler forces one BULK frame to prevent starvation (Dequeue).
const bulkStarvationLimit = 16

// dequeueFromClass picks the best frame within a specific latency class using WFQ.
// order is the caller's snapshot of s.order (see Dequeue): iterating the snapshot
// keeps this routine immune to concurrent Unregister reallocations even if a
// future refactor unlocks s.mu mid-Dequeue.
//
// includeRealtime folds REALTIME streams into this round in addition to
// targetClass — used to serve a capped (demoted) REALTIME class in the
// INTERACTIVE round (Dequeue). The returned bool reports whether the chosen
// frame belonged to a REALTIME stream so the caller charges the REALTIME
// bandwidth counter correctly, and the Registration names the registration it came
// from (DequeueFrom).
func (s *Scheduler) dequeueFromClass(targetClass aether.LatencyClass, order []uint64, includeRealtime bool) (*aether.Frame, bool, Registration) {
	var bestIdx = -1
	var bestFinish float64

	for i, streamID := range order {
		ss, ok := s.streams[streamID]
		if !ok || len(ss.queue) == 0 {
			continue
		}
		// Serve the target class, plus REALTIME streams when a capped REALTIME
		// class is being demoted into this round.
		if ss.latencyClass != targetClass && (!includeRealtime || ss.latencyClass != aether.ClassREALTIME) {
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
		return nil, false, 0
	}

	streamID := order[bestIdx]
	ss := s.streams[streamID]
	frame := ss.queue[0]
	ss.queue = ss.queue[1:]
	s.queueDepth.Add(-1)

	// Advance virtual time by the SAME cost used for selection,
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

	// Clear the retransmit flag once it has priced this frame: MarkRetransmit
	// marks only the next frame of the stream as a retransmit, and a flag left
	// set would charge the 2x cost to every later frame of a stream that once
	// retransmitted, de-prioritising it against healthy streams. Cleared here,
	// inside the same s.mu critical section that owns ss.isRetransmit.
	ss.isRetransmit = false

	return frame, ss.latencyClass == aether.ClassREALTIME, ss.reg
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
