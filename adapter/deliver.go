/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package adapter

import (
	"sync/atomic"
	"time"

	"github.com/ORBTR/aether/flow"
)

// WindowUpdater is called with the stream ID and credit amount to send
// a WINDOW_UPDATE frame to the remote peer.
type WindowUpdater func(streamID uint64, credit uint64)

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
// correct flow control accounting and adaptive backpressure.
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
// Credit is granted on delivery AND on drop (after backpressure). This
// prevents the flow control drain bug while bounding wasted bandwidth.
// The adaptive backpressure gives the application time to catch up without
// stalling the readLoop (which serves ALL streams) under sustained load.
//
// stats is optional — pass nil if metrics are not needed.
func DeliverToRecvCh(recvCh chan<- []byte, payload []byte, window *flow.StreamWindow, streamID uint64, sendUpdate WindowUpdater, stats ...*DeliveryStats) bool {
	// Fast path: non-blocking delivery
	select {
	case recvCh <- payload:
		grantCredit(window, payload, streamID, sendUpdate)
		if len(stats) > 0 && stats[0] != nil {
			stats[0].Delivered.Add(1)
		}
		return true
	default:
	}

	// Slow path: recvCh full — adaptive backpressure.
	// Check recent drop rate to decide how long to wait.
	wait := maxBackpressure
	if len(stats) > 0 && stats[0] != nil {
		stats[0].Backpressure.Add(1)
		if stats[0].DropRate() >= dropRateThreshold {
			wait = minBackpressure // sustained overload — don't stall
		}
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case recvCh <- payload:
		grantCredit(window, payload, streamID, sendUpdate)
		if len(stats) > 0 && stats[0] != nil {
			stats[0].Delivered.Add(1)
		}
		return true
	case <-timer.C:
		// Application didn't drain in time — drop frame, grant credit
		// to prevent permanent sender stall.
		grantCredit(window, payload, streamID, sendUpdate)
		if len(stats) > 0 && stats[0] != nil {
			stats[0].Dropped.Add(1)
			stats[0].BytesDropped.Add(int64(len(payload)))
		}
		return false
	}
}

// grantCredit calls ReceiverConsume and sends a WINDOW_UPDATE if the
// auto-grant threshold is met. The returned value from ReceiverConsume is
// the CUMULATIVE total granted since stream start (not a delta) — it is
// passed as-is to the WINDOW_UPDATE payload so the sender's ApplyUpdate
// can compute the delta and drop stale/duplicate frames.
func grantCredit(window *flow.StreamWindow, payload []byte, streamID uint64, sendUpdate WindowUpdater) {
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
