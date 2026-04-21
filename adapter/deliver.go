/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
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
type DeliveryStats struct {
	Delivered    atomic.Int64 // frames successfully delivered to recvCh
	Dropped      atomic.Int64 // frames dropped (recvCh full after backpressure)
	Backpressure atomic.Int64 // frames that hit the slow path (recvCh was full initially)
	BytesDropped atomic.Int64 // total bytes in dropped frames
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
	// Used for occasional overflow (application momentarily slow).
	maxBackpressure = 200 * time.Millisecond

	// dropRateThreshold: when the recent drop rate exceeds this,
	// reduce backpressure to avoid stalling the readLoop.
	dropRateThreshold = 0.1 // 10%
)

// DeliverToRecvCh delivers a payload to a stream's receive channel with
// adaptive backpressure. On a successful delivery no grant is emitted
// here — the stream's Receive() path records consumption through a
// grantDebouncer so grants advertise application-level progress, not
// transport-level arrival (the 1B design from the mesh-stabilization
// plan). On a drop, credit is granted directly for the dropped bytes to
// prevent permanent sender stall.
//
// Design:
//  1. Fast path: non-blocking send to recvCh (zero latency on the readLoop)
//  2. Slow path: recvCh full — wait with adaptive backpressure for the
//     application to drain. Duration scales with recent drop rate:
//     - Low drops (< 10%): wait up to 200ms (application is generally keeping up)
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
// path owns that via a grantDebouncer (per the 1B design); grants
// advertise application-level progress so a slow consumer actually
// backpressures the sender.
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
	// Fast path: non-blocking delivery. No grant here — Receive() owns it.
	select {
	case recvCh <- payload:
		if len(stats) > 0 && stats[0] != nil {
			stats[0].Delivered.Add(1)
		}
		return true
	default:
	}

	// Slow path: recvCh full — adaptive backpressure.
	// Check recent drop rate to decide how long to wait.
	wait := maxBackpressure
	sustained := false
	if len(stats) > 0 && stats[0] != nil {
		stats[0].Backpressure.Add(1)
		if stats[0].DropRate() >= dropRateThreshold {
			wait = minBackpressure // sustained overload — don't stall
			sustained = true
		}
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case recvCh <- payload:
		if len(stats) > 0 && stats[0] != nil {
			stats[0].Delivered.Add(1)
		}
		return true
	case <-timer.C:
		// Application didn't drain in time — drop frame, grant credit
		// directly to prevent permanent sender stall (the dropped bytes
		// will never reach Receive(), so the debouncer won't see them).
		dropGrantCredit(window, payload, streamID, sendUpdate)
		if len(stats) > 0 && stats[0] != nil {
			stats[0].Dropped.Add(1)
			stats[0].BytesDropped.Add(int64(len(payload)))
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
//   - Gossip (0): 16 slots (2 messages/exchange, 8× headroom)
//   - RPC (1): 32 slots (up to 3 parallel probes, 10× headroom)
//   - Keepalive (2): 4 slots (1 ping per 10-30s)
//   - Control (3): 4 slots (infrequent handshake)
//   - Dynamic (10+): 8 slots (one-shot request/response)
func recvChCapacity(streamID uint64) int {
	switch streamID {
	case 0:
		return 16
	case 1:
		return 32
	case 2:
		return 4
	case 3:
		return 4
	default:
		return 8
	}
}
