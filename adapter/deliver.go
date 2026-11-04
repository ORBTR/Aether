/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"sync/atomic"

	"github.com/ORBTR/aether/flow"
)

// WindowUpdater is called with the stream ID and credit amount to send
// a WINDOW_UPDATE frame to the remote peer.
type WindowUpdater func(streamID uint64, credit uint64)

// DeliveryStats counts a session's receive-side deliveries for monitoring.
// Counters are atomic for lock-free access from the readLoop and monitoring
// goroutines; the session's DeliveryStats() accessor hands them to the
// consumer that sums a session's stats.
//
// Per-stream-class breakout (Stream0*, Stream1*, StreamOther*) lets the
// caller attribute refusals to gossip (stream-0), reliable RPC (stream-1),
// or dynamic streams without growing the map by streamID. One class's
// counters move with that class's own pressure: a TCPSession whose stream-0
// delivery queue (tcpStream.recvQ) is the one that overruns shows
// Stream0Dropped rising while Stream1Dropped and StreamOtherDropped track
// their own.
type DeliveryStats struct {
	Delivered    atomic.Int64 // frames queued for the stream's consumer
	Dropped      atomic.Int64 // frames the session refused: on a TCPSession the message that did not fit its stream's delivery queue and ended the stream (overrun); on a NoiseSession a credit violation or a full control-frame limit
	Backpressure atomic.Int64 // frames that did not fit their stream's delivery queue: on a TCPSession each is also counted in Dropped (overrun); a NoiseSession counts none
	BytesDropped atomic.Int64 // total bytes in dropped frames

	// Per-stream-class counters. Mirror the aggregate fields above so the
	// monitoring layer can compare a single class against its own total
	// without dividing by guesswork.
	Stream0Delivered    atomic.Int64 // gossip frames delivered
	Stream0Dropped      atomic.Int64 // gossip frames refused
	Stream0Backpressure atomic.Int64 // gossip frames that did not fit the queue

	Stream1Delivered    atomic.Int64 // reliable-RPC frames delivered
	Stream1Dropped      atomic.Int64 // reliable-RPC frames refused
	Stream1Backpressure atomic.Int64 // reliable-RPC frames that did not fit the queue

	StreamOtherDelivered    atomic.Int64 // keepalive/control/dynamic frames delivered
	StreamOtherDropped      atomic.Int64 // keepalive/control/dynamic frames refused
	StreamOtherBackpressure atomic.Int64 // keepalive/control/dynamic frames that did not fit the queue
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

// releaseCredit grants back n bytes that will never reach the application,
// through ReceiverConsume and a WINDOW_UPDATE if a trigger fires.
// noiseStream.reassemble uses it for bytes the sender charged that the reader's
// debouncer will never see, because they never become a message Receive returns.
func releaseCredit(window *flow.StreamWindow, n int64, streamID uint64, sendUpdate WindowUpdater) {
	if n <= 0 {
		return
	}
	if window != nil && sendUpdate != nil {
		if grant := window.ReceiverConsume(n); grant > 0 {
			sendUpdate(streamID, uint64(grant))
		}
	}
}

// recvChCapacity is the per-stream-type message count that bounds what no credit
// paces on a NoiseSession: noiseStream bounds its queue by the sender's credit in
// bytes and uses twice this count only for the control frames no credit is
// charged for (enqueueControl). Sized per stream type to the bursts each one
// carries:
//   - Gossip (0): 128. One full-snapshot IBLT burst arrives back to back,
//     and a smaller count fills during it; 128 gives about four times that
//     burst at a worst case of a few MB buffered per peer.
//     DeliveryStats.Stream0Dropped is where a fill shows, apart from
//     Stream1Dropped and StreamOtherDropped.
//   - RPC (1): 128. Eight to eleven parallel RPC streams sharing a session
//     burst their requests together; 128 gives about sixteen times a
//     smaller count's headroom for that concurrency at a worst case of a few
//     tens of KB per peer.
//   - Keepalive (2): 4 (one ping per 10-30 s)
//   - Control (3): 4 (infrequent handshake)
//   - Dynamic (10+): 8 (one-shot request/response)
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
