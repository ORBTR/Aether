/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"sync/atomic"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/flow"
)

// WindowUpdater is called with the stream ID and credit amount to send
// a WINDOW_UPDATE frame to the remote peer.
type WindowUpdater func(streamID uint64, credit uint64)

// CongestionSignaler is called by the delivery path to emit an explicit
// CONGESTION frame back to the sender when the receive-side queue drops a
// frame after backpressure expires. Optional: callers that pass nil get
// the pre-existing behaviour (silent drop + grant). Agnostic across
// transports — both NoiseSession and TCPSession implement SendCongestion
// and can plug the same callback shape in here.
type CongestionSignaler func(payload aether.CongestionPayload) error

// DeliveryStats tracks per-stream delivery metrics for monitoring and
// adaptive behavior. Counters are atomic for lock-free access from
// the readLoop and monitoring goroutines.
//
// Per-stream-class breakout (Stream0*, Stream1*, StreamOther*) lets the
// caller attribute drops/backpressure to gossip (stream-0), reliable
// RPC (stream-1), or dynamic streams without growing the map by streamID.
// This is the verification surface used to confirm whether a recvCh
// capacity bump on a specific stream actually moves the needle: a fix
// for stream-0 should show Stream0Dropped flattening while Stream1Dropped
// and StreamOtherDropped continue to track their own pressure.
type DeliveryStats struct {
	Delivered    atomic.Int64 // frames successfully delivered to recvCh
	Dropped      atomic.Int64 // frames dropped (recvCh full after backpressure)
	Backpressure atomic.Int64 // frames that hit the slow path (recvCh was full initially)
	BytesDropped atomic.Int64 // total bytes in dropped frames

	// Per-stream-class counters. Mirror the aggregate fields above so the
	// monitoring layer can compare a single class against its own total
	// without dividing by guesswork.
	Stream0Delivered    atomic.Int64 // gossip frames delivered
	Stream0Dropped      atomic.Int64 // gossip frames dropped after backpressure
	Stream0Backpressure atomic.Int64 // gossip frames that hit the slow path

	Stream1Delivered    atomic.Int64 // reliable-RPC frames delivered
	Stream1Dropped      atomic.Int64 // reliable-RPC frames dropped after backpressure
	Stream1Backpressure atomic.Int64 // reliable-RPC frames that hit the slow path

	StreamOtherDelivered    atomic.Int64 // keepalive/control/dynamic frames delivered
	StreamOtherDropped      atomic.Int64 // keepalive/control/dynamic frames dropped
	StreamOtherBackpressure atomic.Int64 // keepalive/control/dynamic frames slow-path
}

// recordDelivered increments the aggregate and per-stream-class delivered
// counter for streamID.
func (s *DeliveryStats) recordDelivered(streamID uint64) {
	s.Delivered.Add(1)
	switch streamID {
	case 0:
		s.Stream0Delivered.Add(1)
	case 1:
		s.Stream1Delivered.Add(1)
	default:
		s.StreamOtherDelivered.Add(1)
	}
}

// recordBackpressure increments the aggregate and per-stream-class
// backpressure counter for streamID.
func (s *DeliveryStats) recordBackpressure(streamID uint64) {
	s.Backpressure.Add(1)
	switch streamID {
	case 0:
		s.Stream0Backpressure.Add(1)
	case 1:
		s.Stream1Backpressure.Add(1)
	default:
		s.StreamOtherBackpressure.Add(1)
	}
}

// recordDropped increments the aggregate and per-stream-class dropped
// counter for streamID.
func (s *DeliveryStats) recordDropped(streamID uint64, nbytes int) {
	s.Dropped.Add(1)
	s.BytesDropped.Add(int64(nbytes))
	switch streamID {
	case 0:
		s.Stream0Dropped.Add(1)
	case 1:
		s.Stream1Dropped.Add(1)
	default:
		s.StreamOtherDropped.Add(1)
	}
}

// DropRate returns the fraction of frames dropped (0.0 to 1.0).
func (s *DeliveryStats) DropRate() float64 {
	total := s.Delivered.Load() + s.Dropped.Load()
	if total == 0 {
		return 0
	}
	return float64(s.Dropped.Load()) / float64(total)
}

// backpressureConfig controls the delivery behavior when recvCh is full.
const (
	// minBackpressure is the shortest wait before dropping a frame.
	// Used under sustained overflow to minimize readLoop stalling.
	minBackpressure = 10 * time.Millisecond

	// maxBackpressure is the longest wait before dropping a frame.
	// Lowered to 2ms diagnostic value: investigation showed bidirpc_wait
	// p99 ~= total p99 on WS same-origin, suggesting a per-stream stall
	// somewhere on the deliver path. If raising the drop bar surfaces
	// climbing deliver_backpressure with p99 dropping, this constant is
	// the dominant contributor and we keep it at 2ms. If
	// deliver_backpressure stays ~0 and p99 unchanged, the dominant
	// cause is upstream of deliver (writeLoop HoL) and we accept the
	// slightly-higher drop bar as cheap.
	maxBackpressure = 2 * time.Millisecond

	// dropRateThreshold: when the recent drop rate exceeds this,
	// reduce backpressure to avoid stalling the readLoop.
	dropRateThreshold = 0.1 // 10%

	// stream1MaxBackpressure is the wait window before dropping a
	// stream-1 frame. Stream-1 carries reliable bidi RPC: the caller
	// blocks on its reply channel up to the full callerRequestTTL
	// (Library/dispatch/hwp_dispatch.go: 30s) waiting for a response.
	// A silent drop here desynchronises caller and credit accounting
	// and produces a 30s deadline-exceeded sample with no retry. Pay
	// a per-call latency penalty of waiting up to 1s rather than
	// burning the 30s deadline. AE-M-02: on the noise adapter this 1s
	// wait is now paid on the per-stream deliverLoop goroutine, NOT the
	// shared readLoop — a slow stream-1 consumer blocks only its own
	// delivery goroutine while the readLoop keeps draining the noiseConn
	// inbox (inbound ACKs for every other stream). Far cheaper than the
	// silent 30s RPC timeouts ws_same-origin p99 has been pinned to. See
	// workflow wd4zasivv synthesis.
	stream1MaxBackpressure = 1 * time.Second
)

// DeliverToRecvCh delivers a payload to a stream's receive channel with
// adaptive backpressure. On a successful delivery no grant is emitted
// here — the stream's Receive() path records consumption through a
// grantDebouncer so grants advertise application-level progress, not
// transport-level arrival. On a drop, credit is granted directly for the
// dropped bytes to prevent permanent sender stall.
//
// Design:
//  1. Fast path: non-blocking send to recvCh (zero latency on the readLoop)
//  2. Slow path: recvCh full — wait with adaptive backpressure for the
//     application to drain. Duration scales with recent drop rate:
//     - Low drops (< 10%): wait up to 2ms (keeps readLoop responsive)
//     - High drops (>= 10%): wait only 10ms (sustained overload, don't stall)
//  3. After backpressure expires: drop the frame but grant credit anyway
//     to prevent permanent sender stall
//
// The adaptive backpressure gives the application time to catch up
// without stalling the readLoop (which serves ALL streams) under
// sustained load.
//
// stats is optional — pass nil if metrics are not needed.
func DeliverToRecvCh(recvCh chan<- []byte, payload []byte, window *flow.StreamWindow, streamID uint64, sendUpdate WindowUpdater, stats ...*DeliveryStats) bool {
	return DeliverToRecvChWithSignals(recvCh, payload, window, streamID, sendUpdate, nil, stats...)
}

// DeliverToRecvChWithSignals is the full-featured variant that also emits a
// CONGESTION frame back to the sender when a drop occurs. Callers that
// wire this get receiver-driven backpressure: the sender's existing
// CongestionThrottle applies the returned pacing without waiting for the
// session-level stuck detector.
//
// sendCongestion may be nil — in which case behaviour matches DeliverToRecvCh
// (silent drop + drop-path grant).
//
// Successful deliveries do NOT grant credit here. The stream's Receive()
// path owns that via a grantDebouncer; grants advertise application-
// level progress so a slow consumer actually backpressures the sender.
//
// The CONGESTION payload emitted on drop uses severity scaled by the
// observed drop rate:
//   - Drop rate < 10% : severity = 50, reason = QueueFull, backoff = 200 ms
//   - Drop rate ≥ 10% : severity = 80, reason = Downstream, backoff = 500 ms
//
// These were picked to keep the signal actionable without flapping:
// moderate severity on the first drop so the sender tapers, higher
// severity under sustained pressure. Sender's CongestionThrottle.Apply
// already merges multiple signals so repeated fires don't compound.
func DeliverToRecvChWithSignals(
	recvCh chan<- []byte,
	payload []byte,
	window *flow.StreamWindow,
	streamID uint64,
	sendUpdate WindowUpdater,
	sendCongestion CongestionSignaler,
	stats ...*DeliveryStats,
) bool {
	// Hot path — no defer recover here. The recovery for racy
	// closed-channel sends lives on the call-site teardown paths where
	// the race actually matters (noise_dispatch handleClose drain loop,
	// TCP deliverToStream). Adding a defer here adds enough overhead to
	// flake the grant-debouncer coalesce test under load.
	// Fast path: non-blocking delivery. No grant here — Receive() owns it.
	select {
	case recvCh <- payload:
		if len(stats) > 0 && stats[0] != nil {
			stats[0].recordDelivered(streamID)
		}
		return true
	default:
	}

	// Slow path: recvCh full — adaptive backpressure.
	// Check recent drop rate to decide how long to wait.
	wait := maxBackpressure
	sustained := false
	if len(stats) > 0 && stats[0] != nil {
		stats[0].recordBackpressure(streamID)
		if stats[0].DropRate() >= dropRateThreshold {
			wait = minBackpressure // sustained overload — don't stall
			sustained = true
		}
	}

	// Stream-1 carries reliable bidi RPC. Override the adaptive wait
	// with a much longer ceiling so a transient recvCh full does NOT
	// translate into a 30s deadline-exceeded on the caller. See the
	// comment on stream1MaxBackpressure above.
	if streamID == 1 {
		wait = stream1MaxBackpressure
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case recvCh <- payload:
		if len(stats) > 0 && stats[0] != nil {
			stats[0].recordDelivered(streamID)
		}
		return true
	case <-timer.C:
		// Application didn't drain in time — drop frame, grant credit
		// directly to prevent permanent sender stall (the dropped bytes
		// will never reach Receive(), so the debouncer won't see them).
		dropGrantCredit(window, payload, streamID, sendUpdate)
		if len(stats) > 0 && stats[0] != nil {
			stats[0].recordDropped(streamID, len(payload))
		}
		// Receiver-driven backpressure: signal the sender to slow down so
		// future frames arrive at a pace the application can actually
		// drain. Severity + backoff scale with whether this is a one-off
		// slowdown or sustained pressure.
		if sendCongestion != nil {
			p := aether.CongestionPayload{
				Reason:    aether.CongestionQueueFull,
				Severity:  50,
				BackoffMs: 200,
			}
			if sustained {
				p.Reason = aether.CongestionDownstream
				p.Severity = 80
				p.BackoffMs = 500
			}
			_ = sendCongestion(p)
		}
		return false
	}
}

// dropGrantCredit accounts for bytes that never reached the application
// (dropped after backpressure expired) by calling ReceiverConsume and
// emitting a WINDOW_UPDATE if any trigger fires. This path MUST remain
// direct — it runs in the delivery goroutine, not a reader goroutine, so
// the grantDebouncer (which lives on the reader side) wouldn't see these
// bytes otherwise and the sender would stall forever on permanently-lost
// credit.
//
// Used only on the drop path. Successful deliveries let the reader's
// debouncer handle grants.
func dropGrantCredit(window *flow.StreamWindow, payload []byte, streamID uint64, sendUpdate WindowUpdater) {
	if window != nil && sendUpdate != nil {
		if grant := window.ReceiverConsume(int64(len(payload))); grant > 0 {
			sendUpdate(streamID, uint64(grant))
		}
	}
}

// recvChCapacity returns the receive channel buffer size for a given stream ID.
// Sized per stream type to reduce maximum payload accumulation:
//   - Gossip (0): 128 slots (was 32 — a 32-slot channel paired with the
//     2ms maxBackpressure ceiling cascaded into CongestionDownstream
//     sev=80 reason=5 emissions on UDP, throttling the sender and
//     surfacing as walker proving timeouts on noise-UDP edges. 128 slots
//     gives ~4× headroom for a single full-snapshot IBLT burst at the
//     cost of an extra ~3 MB worst-case buffer per peer. Verify with
//     DeliveryStats.Stream0Dropped flattening post-deploy while
//     Stream1Dropped / StreamOtherDropped track their own pressure.)
//   - RPC (1): 128 slots (was 32 — bumped after wd4zasivv synthesis
//     showed cross-region ws_same-origin sessions running 8-11 active
//     parallel streams saturated the 32-slot channel during burst,
//     forcing stream-1 into the drop path and producing 30s RPC
//     timeouts. 128 slots gives ~16× headroom for realistic concurrency
//     at the cost of an extra ~24 KB worst-case buffer per peer.)
//   - Keepalive (2): 4 slots (1 ping per 10-30s)
//   - Control (3): 4 slots (infrequent handshake)
//   - Dynamic (10+): 8 slots (one-shot request/response)
func recvChCapacity(streamID uint64) int {
	switch streamID {
	case 0:
		return 128
	case 1:
		return 128
	case 2:
		return 4
	case 3:
		return 4
	default:
		return 8
	}
}
