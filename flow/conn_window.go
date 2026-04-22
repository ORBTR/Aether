/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package flow

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

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

	// Grant-trigger telemetry — mirrors StreamWindow. See the four-
	// trigger comment on StreamWindow.ReceiverConsume for rationale.
	thresholdGrants uint64
	eagerGrants     uint64
	watermarkGrants uint64
	timedGrants     uint64

	// lastGrantTime drives the TIMED trigger; initialized at construction
	// so a brand-new conn can't fire TIMED on the very first payload.
	lastGrantTime time.Time
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
		lastGrantTime:  time.Now(),
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

// ReleaseOnACK releases connection-level sender credit corresponding to
// bytes the peer acknowledged. Delta-based (caller passes sum of newly-
// acked Frame.Length), capped at dataOutstanding so ACK-path and
// WINDOW_UPDATE-path together never over-release. See
// StreamWindow.ReleaseOnACK for the full rationale (same approach at
// stream scope).
func (w *ConnWindow) ReleaseOnACK(ackedBytesDelta int64) {
	if ackedBytesDelta <= 0 {
		return
	}
	w.mu.Lock()
	release := ackedBytesDelta
	if release > w.dataOutstanding {
		release = w.dataOutstanding
	}
	w.dataOutstanding -= release
	w.mu.Unlock()
	if release > 0 {
		w.sem.Release(release)
	}
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
// grant total if any of the four grant triggers fire (0 otherwise).
//
// Four triggers mirror StreamWindow.ReceiverConsume — see that doc-comment
// for the full rationale. Summary:
//   - THRESHOLD: sinceLastGrant >= 25% of initial (steady-state)
//   - EAGER:     this single payload >= 50% of threshold (burst)
//   - WATERMARK: recvCredit < 25% of initialSize (pre-stall)
//   - TIMED:     wall-clock gap since lastGrantTime >= GrantMaxInterval
//     when any bytes have been consumed (small-payload-large-window gap)
//
// Conn-level typically carries aggregate gossip traffic where per-stream
// flow control is the main gate, but the conn window still stalls the
// whole connection if it runs dry faster than grants return — so the same
// trigger logic applies here.
func (w *ConnWindow) ReceiverConsume(n int64) int64 {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.recvCredit -= n
	w.consumed += n
	sinceLastGrant := w.consumed - w.lastGrant

	threshold := int64(float64(w.initialSize) * AutoGrantThreshold)
	lowWatermark := int64(float64(w.initialSize) * LowWatermarkFraction)
	eagerPayloadFloor := int64(float64(threshold) * EagerGrantPayloadFraction)
	switch {
	case sinceLastGrant >= threshold:
		return w.grantLocked(sinceLastGrant, "threshold")
	case n >= eagerPayloadFloor && sinceLastGrant > 0:
		return w.grantLocked(sinceLastGrant, "eager")
	case w.recvCredit < lowWatermark && sinceLastGrant > 0:
		return w.grantLocked(sinceLastGrant, "watermark")
	case sinceLastGrant > 0 && time.Since(w.lastGrantTime) >= GrantMaxInterval:
		return w.grantLocked(sinceLastGrant, "timed")
	}
	return 0
}

// grantLocked emits a grant and advances cumulative accounting. Caller
// must hold w.mu. Returns 0 if the effective grant would be non-positive
// (e.g. recvCredit already at the cap).
func (w *ConnWindow) grantLocked(sinceLastGrant int64, trigger string) int64 {
	grant := sinceLastGrant
	if w.recvCredit+grant > DefaultMaxConnCredit {
		grant = DefaultMaxConnCredit - w.recvCredit
	}
	if grant <= 0 {
		return 0
	}
	w.recvCredit += grant
	w.lastGrant = w.consumed
	w.grantsEmitted += grant
	w.lastGrantTime = time.Now()
	switch trigger {
	case "threshold":
		atomic.AddUint64(&w.thresholdGrants, 1)
	case "eager":
		atomic.AddUint64(&w.eagerGrants, 1)
	case "watermark":
		atomic.AddUint64(&w.watermarkGrants, 1)
	case "timed":
		atomic.AddUint64(&w.timedGrants, 1)
	}
	return w.grantsEmitted
}

// Available returns the sender's remaining connection credit.
func (w *ConnWindow) Available() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return DefaultMaxConnCredit - w.initialDeficit - w.dataOutstanding
}

// ConnStats is a point-in-time snapshot of conn-window state for metrics.
type ConnStats struct {
	Outstanding     int64
	RecvCredit      int64
	Consumed        int64
	GrantsEmitted   int64
	GrantsReceived  int64
	ThresholdGrants uint64
	EagerGrants     uint64
	WatermarkGrants uint64
	TimedGrants     uint64
}

// Stats returns a snapshot of the conn window's state. Lock-free read of
// atomic counters + single mu.Lock for the non-atomic fields.
func (w *ConnWindow) Stats() ConnStats {
	w.mu.Lock()
	out := ConnStats{
		Outstanding:    w.dataOutstanding,
		RecvCredit:     w.recvCredit,
		Consumed:       w.consumed,
		GrantsEmitted:  w.grantsEmitted,
		GrantsReceived: w.grantsReceived,
	}
	w.mu.Unlock()
	out.ThresholdGrants = atomic.LoadUint64(&w.thresholdGrants)
	out.EagerGrants = atomic.LoadUint64(&w.eagerGrants)
	out.WatermarkGrants = atomic.LoadUint64(&w.watermarkGrants)
	out.TimedGrants = atomic.LoadUint64(&w.timedGrants)
	return out
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
