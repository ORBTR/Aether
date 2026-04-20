/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package flow

import (
	"context"
	"fmt"
	"sync"

	"golang.org/x/sync/semaphore"
)

// DefaultConnCredit is the initial connection-level credit (4 MB).
//
// Sized to absorb the observed gossip burst pattern: full-state exchanges
// run ~70-100 KB per round-trip and the receiver only emits a
// WINDOW_UPDATE after the 25% auto-grant threshold (1 MB for the old
// default) was consumed — so roughly 4 round-trips of silence before
// grants started flowing back. Under high-rate gossip (post-restart
// convergence storm) that produced "insufficient connection credit after
// 10s" timeouts where observed avail was 40-70 KB vs 72 KB needed —
// credit WAS flowing back, just not fast enough to keep up with the
// leading edge of a burst.
//
// 4 MB covers ~16 back-to-back 72 KB exchanges before any stall,
// comfortably more than the grant-emission cycle. Auto-tuning + the
// 16 MB cap can still grow per-peer as BDP dictates.
const DefaultConnCredit int64 = 4 * 1024 * 1024

// DefaultMaxConnCredit is the maximum connection-level credit (16 MB).
const DefaultMaxConnCredit int64 = 16 * 1024 * 1024

// ConnWindow implements connection-level aggregate flow control.
// Prevents any single stream from starving the connection.
// All stream sends must also consume from the connection window.
//
// Both Consume and StreamWindow.Consume block up to ConsumeTimeout waiting
// for credit via a semaphore. Previously Consume was synchronous (error on
// exhaustion); that made sense when TCP backpressure at the stream level
// absorbed pacing, but on Noise-UDP a brief conn-level exhaustion would
// surface as an immediate error even though a WINDOW_UPDATE was about to
// arrive. Blocking gives grants time to land.
//
// WINDOW_UPDATE semantics match StreamWindow: wire value is the peer's
// CUMULATIVE total granted since stream start. ApplyUpdate computes delta
// against grantsReceived and drops stale / duplicate / reordered frames.
type ConnWindow struct {
	mu sync.Mutex

	// Send-side semaphore, pre-sized to DefaultMaxConnCredit (16 MB).
	// Effective window = DefaultMaxConnCredit - initialDeficit - dataOutstanding.
	// ApplyUpdate growth of sendCredit is bounded by grantsReceived / dataOutstanding
	// so we never Release past capacity.
	sem             *semaphore.Weighted
	initialDeficit  int64
	dataOutstanding int64

	// initialSize is the configured starting credit (e.g. 1 MB); used for
	// the auto-grant threshold computation.
	initialSize int64

	// Receive-side bookkeeping.
	recvCredit int64
	consumed   int64
	lastGrant  int64

	// Cumulative grant counters — identical semantics to StreamWindow.
	grantsEmitted  int64
	grantsReceived int64
}

// NewConnWindow creates a connection-level flow control window.
func NewConnWindow(initialCredit int64) *ConnWindow {
	if initialCredit <= 0 {
		initialCredit = DefaultConnCredit
	}
	capacity := DefaultMaxConnCredit
	if initialCredit > capacity {
		capacity = initialCredit
	}
	sem := semaphore.NewWeighted(capacity)
	var deficit int64
	if initialCredit < capacity {
		deficit = capacity - initialCredit
		_ = sem.Acquire(context.Background(), deficit)
	}
	return &ConnWindow{
		sem:            sem,
		initialDeficit: deficit,
		initialSize:    initialCredit,
		recvCredit:     initialCredit,
	}
}

// Consume reserves n bytes of connection-level credit before a Send.
// Small frames (≤ MinGuaranteedWindow) bypass the semaphore entirely so
// control traffic (WINDOW_UPDATE, ACK, PING/PONG) always flows. Larger
// frames block up to ConsumeTimeout waiting for credit via sem.Acquire.
func (w *ConnWindow) Consume(ctx context.Context, n int64) error {
	if n <= 0 {
		return nil
	}
	if n <= MinGuaranteedWindow {
		return nil
	}
	acquireCtx, cancel := context.WithTimeout(ctx, ConsumeTimeout)
	defer cancel()
	if err := w.sem.Acquire(acquireCtx, n); err != nil {
		return fmt.Errorf("aether flow: insufficient connection credit after %s (need %d, have %d): %w",
			ConsumeTimeout, n, w.Available(), err)
	}
	w.mu.Lock()
	w.dataOutstanding += n
	w.mu.Unlock()
	return nil
}

// ApplyUpdate processes a connection-level WINDOW_UPDATE where credit is
// the peer's cumulative total. Delta = credit - grantsReceived; stale
// frames (delta ≤ 0) are dropped. Positive delta is released back to the
// semaphore, capped at dataOutstanding so we never release past capacity.
func (w *ConnWindow) ApplyUpdate(credit int64) {
	if credit <= 0 {
		return
	}
	w.mu.Lock()
	if credit <= w.grantsReceived {
		w.mu.Unlock()
		return
	}
	delta := credit - w.grantsReceived
	w.grantsReceived = credit
	granted := delta
	if granted > w.dataOutstanding {
		granted = w.dataOutstanding
	}
	w.dataOutstanding -= granted
	w.mu.Unlock()
	if granted > 0 {
		w.sem.Release(granted)
	}
}

// ReceiverConsume records receiver consumption and returns the CUMULATIVE
// grant total if the threshold is met (0 otherwise). Cumulative return
// value makes the wire grant idempotent across loss.
func (w *ConnWindow) ReceiverConsume(n int64) int64 {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.recvCredit -= n
	w.consumed += n
	sinceLastGrant := w.consumed - w.lastGrant

	threshold := int64(float64(w.initialSize) * AutoGrantThreshold)
	if sinceLastGrant >= threshold {
		grant := sinceLastGrant
		if w.recvCredit+grant > DefaultMaxConnCredit {
			grant = DefaultMaxConnCredit - w.recvCredit
		}
		if grant < 0 {
			grant = 0
		}
		w.recvCredit += grant
		w.lastGrant = w.consumed
		w.grantsEmitted += grant
		return w.grantsEmitted
	}
	return 0
}

// Available returns the sender's remaining connection credit.
func (w *ConnWindow) Available() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return DefaultMaxConnCredit - w.initialDeficit - w.dataOutstanding
}

// CurrentGrant returns the current cumulative-emitted value so callers can
// periodically re-transmit it as a connection-level WINDOW_UPDATE. Breaks
// the UDP-loss-induced deadlock where a dropped grant stalls the sender
// and no further data arrives to re-trigger the threshold. Returns 0 if
// no grant has ever been emitted.
func (w *ConnWindow) CurrentGrant() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.grantsEmitted
}
