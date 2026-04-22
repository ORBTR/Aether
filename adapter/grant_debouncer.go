/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

package adapter

import (
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/ORBTR/aether"
)

// GrantCoalesceWindow is the maximum debounce delay before a grant is
// flushed. Short enough that a slow consumer feels immediate (25 ms is
// below human-perception for terminal I/O), long enough that a burst of
// rapid Reads coalesces into one WINDOW_UPDATE.
//
// Operators can override via AETHER_GRANT_COALESCE_MS at process start.
// Default 25ms; set to 1ms for aggressive flushing during incident
// response (trade more WINDOW_UPDATE frames for faster sender
// unblocking).
var GrantCoalesceWindow = 25 * time.Millisecond

// GrantImmediateFraction — if pending consume is at least this fraction of
// the window's initialCredit, flush immediately instead of waiting for
// the coalesce timer. Keeps burst responsiveness: a fast consumer reading
// back-to-back payloads still triggers grants as the window drains, not
// 25 ms later.
//
// Operators can override via AETHER_GRANT_IMMEDIATE_FRACTION at process
// start. Default 0.5; lower values (e.g. 0.01) make grants fire
// aggressively on small consumes.
var GrantImmediateFraction = 0.5

// GrantWatchdogInterval enables a safety-net goroutine that force-flushes
// any pending grant if `interval` elapses with pending > 0 and no flush
// has happened. Default 0 (disabled) — the coalesce timer is normally
// sufficient. Set via AETHER_GRANT_WATCHDOG_MS for incident response;
// e.g. 500ms catches deadlocks where the timer path is skipped
// (scheduling stalls, Record never called, etc.) without spamming
// grants in healthy flows.
var GrantWatchdogInterval time.Duration

// dbgGrant is the debug logger for the grant debouncer. Enable with
// DEBUG=aether.flow.debouncer (or any ancestor like aether.flow). Logs
// every Record / timed flush / immediate flush / watchdog flush with
// pending totals and the grant emitted — expensive in high-throughput
// paths so keep it off by default.
var dbgGrant = aether.NewDebugLogger("aether.flow.debouncer")

func init() {
	if v := os.Getenv("AETHER_GRANT_COALESCE_MS"); v != "" {
		if ms, err := strconv.Atoi(v); err == nil && ms > 0 {
			GrantCoalesceWindow = time.Duration(ms) * time.Millisecond
		}
	}
	if v := os.Getenv("AETHER_GRANT_IMMEDIATE_FRACTION"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 && f <= 1 {
			GrantImmediateFraction = f
		}
	}
	if v := os.Getenv("AETHER_GRANT_WATCHDOG_MS"); v != "" {
		if ms, err := strconv.Atoi(v); err == nil && ms > 0 {
			GrantWatchdogInterval = time.Duration(ms) * time.Millisecond
		}
	}
	if dbgGrant.Enabled() {
		dbgGrant.Printf("init coalesce=%s immediateFraction=%.3f watchdog=%s",
			GrantCoalesceWindow, GrantImmediateFraction, GrantWatchdogInterval)
	}
}

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

	// Watchdog state: lastFlushUnix records the wall time of the most
	// recent flush. The watchdog goroutine (if enabled) checks this on
	// each tick and force-flushes if pending > 0 and the gap exceeds
	// GrantWatchdogInterval. Protected by mu.
	lastFlushUnix int64
	watchdogStop  chan struct{}
}

// newGrantDebouncer creates a debouncer bound to a grantable window and
// send callback. immediateFloor is typically 50% of the window's initial
// credit — set to 0 to disable the immediate-flush escape hatch (always
// wait for the coalesce window).
//
// If GrantWatchdogInterval > 0 (via AETHER_GRANT_WATCHDOG_MS), spawns a
// single watchdog goroutine that force-flushes stuck pending grants.
// The watchdog exits on Close().
func newGrantDebouncer(
	window grantable,
	sendUpdate WindowUpdater,
	streamID uint64,
	immediateFloor int64,
) *grantDebouncer {
	if immediateFloor < 0 {
		immediateFloor = 0
	}
	d := &grantDebouncer{
		window:         window,
		sendUpdate:     sendUpdate,
		streamID:       streamID,
		immediateFloor: immediateFloor,
		coalesceWindow: GrantCoalesceWindow,
		lastFlushUnix:  time.Now().UnixNano(),
	}
	if GrantWatchdogInterval > 0 {
		d.watchdogStop = make(chan struct{})
		go d.runWatchdog(GrantWatchdogInterval)
	}
	return d
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
		if dbgGrant.Enabled() {
			dbgGrant.Printf("stream=%d Record n=%d pending=%d floor=%d → immediate flush",
				d.streamID, n, d.pending, d.immediateFloor)
		}
		d.flushLocked("immediate")
		d.mu.Unlock()
		return
	}
	// Batched flush: start the timer if not already running. A subsequent
	// Record within the window rides the same pending flush.
	if d.timer == nil {
		if dbgGrant.Enabled() {
			dbgGrant.Printf("stream=%d Record n=%d pending=%d → timer start (%s)",
				d.streamID, n, d.pending, d.coalesceWindow)
		}
		d.timer = time.AfterFunc(d.coalesceWindow, d.timedFlush)
	} else if dbgGrant.Enabled() {
		dbgGrant.Printf("stream=%d Record n=%d pending=%d → timer running",
			d.streamID, n, d.pending)
	}
	d.mu.Unlock()
}

// timedFlush runs when the debounce timer fires. Not called while holding
// d.mu because AfterFunc fires on its own goroutine.
func (d *grantDebouncer) timedFlush() {
	d.mu.Lock()
	d.timer = nil
	if !d.closed {
		d.flushLocked("timer")
	}
	d.mu.Unlock()
}

// flushLocked computes the cumulative grant via ReceiverConsume and emits
// a single WINDOW_UPDATE if any of the four triggers fire. Caller must
// hold d.mu. The reason string is for debug logging only.
//
// Cancels any pending timer on the way out — we've just satisfied the
// reason the timer existed.
func (d *grantDebouncer) flushLocked(reason string) {
	if d.pending <= 0 {
		return
	}
	n := d.pending
	d.pending = 0
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	d.lastFlushUnix = time.Now().UnixNano()
	if d.window == nil {
		if dbgGrant.Enabled() {
			dbgGrant.Printf("stream=%d flush(%s) n=%d window=nil → drop", d.streamID, reason, n)
		}
		return
	}
	grant := d.window.ReceiverConsume(n)
	if dbgGrant.Enabled() {
		dbgGrant.Printf("stream=%d flush(%s) n=%d grant=%d", d.streamID, reason, n, grant)
	}
	if grant > 0 && d.sendUpdate != nil {
		d.sendUpdate(d.streamID, uint64(grant))
	}
}

// Flush forces an immediate emission of any pending grant. Used on
// stream/session close so accumulated bytes don't get stranded.
func (d *grantDebouncer) Flush() {
	d.mu.Lock()
	if !d.closed {
		d.flushLocked("explicit")
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
	d.flushLocked("close")
	stopCh := d.watchdogStop
	d.watchdogStop = nil
	d.mu.Unlock()
	if stopCh != nil {
		close(stopCh)
	}
}

// runWatchdog is the optional safety-net loop that force-flushes pending
// grants when the coalesce-timer path has failed to do so within the
// watchdog interval. Closes on grant-debouncer Close.
//
// Why this exists: the timer path relies on Record starting a
// time.AfterFunc. If Record is skipped (application bypassed the
// debouncer somehow), or the timer goroutine was descheduled long
// enough for pending to accumulate across multiple coalesce windows,
// the sender stalls waiting for a grant that never arrives. The
// watchdog catches those cases — cheap to run, only fires when
// something is actually wrong.
func (d *grantDebouncer) runWatchdog(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-d.watchdogStop:
			return
		case <-ticker.C:
			d.mu.Lock()
			if d.closed {
				d.mu.Unlock()
				return
			}
			if d.pending > 0 {
				gap := time.Since(time.Unix(0, d.lastFlushUnix))
				if gap >= interval {
					if dbgGrant.Enabled() {
						dbgGrant.Printf("stream=%d watchdog trip pending=%d gap=%s",
							d.streamID, d.pending, gap)
					}
					d.flushLocked("watchdog")
				}
			}
			d.mu.Unlock()
		}
	}
}
