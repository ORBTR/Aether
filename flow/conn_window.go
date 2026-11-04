/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
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

// DefaultConnCredit is the initial connection-level credit: the bounds
// profile's session memory ceiling (BoundsProfile.ConnCredit), so credit a
// sender holds always fits what the receiver's queues may hold.
//
// It also has to carry a gossip burst. A full-state exchange runs ~70-100 KB per
// round-trip and the receiver emits a WINDOW_UPDATE only once the
// AutoGrantThreshold fraction (25%) of this credit has been consumed or
// GrantMaxInterval has passed, so the credit covers the exchanges sent before a
// grant flows back; a sender short of it waits out ConsumeTimeout (10 s) in
// Consume and fails with ErrCreditExhausted. 16 MiB covers over 200 back-to-back
// 72 KB exchanges.
const DefaultConnCredit int64 = DefaultSessionMemoryCeiling

// DefaultMaxConnCredit is the least capacity NewConnWindow builds a window
// with, the same 16 MiB: a window built with less credit than this holds the
// difference back as its deficit.
const DefaultMaxConnCredit int64 = DefaultSessionMemoryCeiling

// ConnWindow implements connection-level aggregate flow control.
// Prevents any single stream from starving the connection.
// All stream sends must also consume from the connection window.
//
// Both Consume and StreamWindow.Consume block up to ConsumeTimeout waiting
// for credit via a semaphore: on Noise-UDP a brief conn-level exhaustion
// would otherwise surface as an immediate error even though a WINDOW_UPDATE
// was about to arrive. Blocking gives grants time to land.
//
// WINDOW_UPDATE semantics match StreamWindow: wire value is the peer's
// CUMULATIVE total granted since stream start. ApplyUpdate computes delta
// against grantsReceived and drops stale / duplicate / reordered frames.
type ConnWindow struct {
	mu sync.Mutex

	// Send-side semaphore, pre-sized to maxSize (max(initialCredit,
	// DefaultMaxConnCredit)). Effective window = maxSize - initialDeficit
	// - dataOutstanding. ApplyUpdate growth of sendCredit is bounded by
	// grantsReceived / dataOutstanding so we never Release past capacity.
	sem             *semaphore.Weighted
	initialDeficit  int64
	dataOutstanding int64

	// maxSize is the true semaphore capacity captured at construction —
	// max(initialCredit, DefaultMaxConnCredit). grantLocked (recv cap) and
	// Available (send report) use it instead of the DefaultMaxConnCredit
	// constant so a window built with initialCredit > 16 MB still emits
	// grants and reports an accurate Available.
	maxSize int64

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
		maxSize:        capacity,
		initialDeficit: deficit,
		initialSize:    initialCredit,
		recvCredit:     initialCredit,
		lastGrantTime:  time.Now(),
	}
}

// Consume reserves n bytes of connection-level credit before a Send, blocking
// up to ConsumeTimeout via sem.Acquire and failing with ErrCreditExhausted.
// Every byte is charged; control frames never call it (see MinGuaranteedWindow).
func (w *ConnWindow) Consume(ctx context.Context, n int64) error {
	if n <= 0 {
		return nil
	}
	acquireCtx, cancel := context.WithTimeout(ctx, ConsumeTimeout)
	defer cancel()
	if err := w.sem.Acquire(acquireCtx, n); err != nil {
		return fmt.Errorf("aether flow: insufficient connection credit after %s (need %d, have %d): %w: %w",
			ConsumeTimeout, n, w.Available(), ErrCreditExhausted, err)
	}
	w.mu.Lock()
	w.dataOutstanding += n
	w.mu.Unlock()
	return nil
}

// ReleaseUnsent returns connection credit that no grant from the peer will
// return: the connection-level mirror of StreamWindow.ReleaseUnsent. Its
// callers are noiseStream.Send, when a step after this window's Consume fails
// before the bytes reach the transport (the peer never sees them, so never
// grants them), and the RESET exits (noiseStream.Reset, handleReset), with the
// bytes a RESET left charged on a stream that no grant covers (the peer's queue
// stops granting for that stream at the RESET).
// Without it each such Send or stream would shrink the window, which every
// stream of the session shares, for the session's life, until Consume fails
// with ErrCreditExhausted on every stream.
//
// Capped at dataOutstanding so over-release composes safely with
// ApplyUpdate.
func (w *ConnWindow) ReleaseUnsent(n int64) {
	if n <= 0 {
		return
	}
	w.mu.Lock()
	release := n
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
	// Cap against the true capacity (maxSize), not the
	// DefaultMaxConnCredit constant, so a window constructed with
	// initialCredit > 16 MB still emits grants instead of pinning at 0.
	if w.recvCredit+grant > w.maxSize {
		grant = w.maxSize - w.recvCredit
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

// ReceiveCeilings returns the two bounds a session's receive side holds this
// window's peer to: initial, the credit the peer's sender starts with, and
// maximum, the semaphore capacity. A session's window is built at the bounds
// profile's connection credit, where the two are the one number the profile's
// memory ceiling derives; NoiseSession's receive queues refuse a peer past it,
// and signalReceiveOverload reads the fraction of it they hold.
func (w *ConnWindow) ReceiveCeilings() (initial, maximum int64) {
	return w.initialSize, w.maxSize
}

// Withhold takes n bytes off the grants this window has yet to emit, for bytes the
// consumer has returned or will return here that the peer's sender has already taken
// back itself: handleReset passes what it granted on a stream past what the peer's
// RESET says its grants had returned, since that sender released the rest of the
// stream's charge at the RESET, those bytes among them. A grant past that would give
// the sender the same credit twice, and a sender holding more credit than this
// session's queues can admit is reset as if it ignored credit. Cumulative: the next
// grants wait until consumption passes what is withheld, and the receive window
// counts the bytes as granted. Overflow-safe: a count at or below zero is ignored.
func (w *ConnWindow) Withhold(n int64) {
	if n <= 0 {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if n > w.maxSize-w.recvCredit {
		w.recvCredit = w.maxSize
	} else {
		w.recvCredit += n
	}
	w.lastGrant += n
}

// Available returns the sender's remaining connection credit.
func (w *ConnWindow) Available() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.maxSize - w.initialDeficit - w.dataOutstanding
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
