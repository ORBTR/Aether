/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

package adapter

import (
	"sync"
	"time"
)

// GrantCoalesceWindow is the maximum debounce delay before a grant is
// flushed. Short enough that a slow consumer feels immediate (25 ms is
// below human-perception for terminal I/O), long enough that a burst of
// rapid Reads coalesces into one WINDOW_UPDATE.
const GrantCoalesceWindow = 25 * time.Millisecond

// GrantImmediateFraction — if pending consume is at least this fraction of
// the window's initialCredit, flush immediately instead of waiting for
// the coalesce timer. Keeps burst responsiveness: a fast consumer reading
// back-to-back payloads still triggers grants as the window drains, not
// 25 ms later.
const GrantImmediateFraction = 0.5

// grantable is the minimal flow-window surface used by the debouncer.
// Matches both StreamWindow and ConnWindow; keeps grantDebouncer
// parametric over what kind of window it's debouncing.
type grantable interface {
	ReceiverConsume(n int64) int64
}

// grantDebouncer coalesces receiver-side consume accounting into
// batched WINDOW_UPDATE emissions.
//
// Why this exists (1B in the mesh-stabilization plan):
//
// Before the debouncer, `ReceiverConsume` was called at frame-receipt
// time (inside deliver.go / noise_dispatch.go) — grants advertised credit
// as soon as bytes landed in recvCh, regardless of whether the
// application had consumed them. A slow application couldn't backpressure
// the sender; the recvCh buffer had to fill before any throttling
// happened, and then frames were dropped (with credit still granted!) to
// avoid deadlock.
//
// After the debouncer, `ReceiverConsume` is called at application-read
// time (inside stream.Receive()). The debouncer batches a 25 ms window of
// consume events into one `ReceiverConsume` call → one WINDOW_UPDATE
// frame on the wire. The coalesce window is short enough to be
// imperceptible to the application; the immediate-fraction escape hatch
// keeps bursts responsive.
//
// The debouncer is agnostic: it works the same for per-stream
// StreamWindow and per-session ConnWindow — the caller supplies the
// grantable + the sendUpdate callback.
type grantDebouncer struct {
	mu             sync.Mutex
	window         grantable
	sendUpdate     WindowUpdater
	streamID       uint64
	immediateFloor int64
	coalesceWindow time.Duration

	pending int64
	timer   *time.Timer
	closed  bool
}

// newGrantDebouncer creates a debouncer bound to a grantable window and
// send callback. immediateFloor is typically 50% of the window's initial
// credit — set to 0 to disable the immediate-flush escape hatch (always
// wait for the coalesce window).
func newGrantDebouncer(
	window grantable,
	sendUpdate WindowUpdater,
	streamID uint64,
	immediateFloor int64,
) *grantDebouncer {
	if immediateFloor < 0 {
		immediateFloor = 0
	}
	return &grantDebouncer{
		window:         window,
		sendUpdate:     sendUpdate,
		streamID:       streamID,
		immediateFloor: immediateFloor,
		coalesceWindow: GrantCoalesceWindow,
	}
}

// Record adds n bytes to the pending-consume total. If the total crosses
// immediateFloor, flushes immediately; otherwise starts (or reuses) the
// debounce timer so a later Record within the coalesce window rides the
// same flush. Safe to call from multiple goroutines.
//
// The application's Receive() calls this after successfully reading a
// payload from the stream's recvCh (post-reassembly for fragmented
// payloads).
func (d *grantDebouncer) Record(n int64) {
	if n <= 0 {
		return
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	d.pending += n
	// Immediate-flush escape hatch: if the pending total represents a
	// meaningful fraction of the window, don't hold it for 25 ms — the
	// sender is likely hitting the window edge and we want grants in
	// flight now, not 25 ms later.
	if d.immediateFloor > 0 && d.pending >= d.immediateFloor {
		d.flushLocked()
		d.mu.Unlock()
		return
	}
	// Batched flush: start the timer if not already running. A subsequent
	// Record within the window rides the same pending flush.
	if d.timer == nil {
		d.timer = time.AfterFunc(d.coalesceWindow, d.timedFlush)
	}
	d.mu.Unlock()
}

// timedFlush runs when the debounce timer fires. Not called while holding
// d.mu because AfterFunc fires on its own goroutine.
func (d *grantDebouncer) timedFlush() {
	d.mu.Lock()
	d.timer = nil
	if !d.closed {
		d.flushLocked()
	}
	d.mu.Unlock()
}

// flushLocked computes the cumulative grant via ReceiverConsume and emits
// a single WINDOW_UPDATE if any of the four triggers fire. Caller must
// hold d.mu.
//
// Cancels any pending timer on the way out — we've just satisfied the
// reason the timer existed.
func (d *grantDebouncer) flushLocked() {
	if d.pending <= 0 {
		return
	}
	n := d.pending
	d.pending = 0
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	if d.window == nil {
		return
	}
	grant := d.window.ReceiverConsume(n)
	if grant > 0 && d.sendUpdate != nil {
		d.sendUpdate(d.streamID, uint64(grant))
	}
}

// Flush forces an immediate emission of any pending grant. Used on
// stream/session close so accumulated bytes don't get stranded.
func (d *grantDebouncer) Flush() {
	d.mu.Lock()
	if !d.closed {
		d.flushLocked()
	}
	d.mu.Unlock()
}

// Close cancels any pending timer, flushes the remaining pending total
// (so the peer still gets credit for already-consumed bytes), and marks
// the debouncer inert. Subsequent Record calls are no-ops. Idempotent.
func (d *grantDebouncer) Close() {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	d.closed = true
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	d.flushLocked()
	d.mu.Unlock()
}
