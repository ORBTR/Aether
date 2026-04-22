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
// flushed. Short enough that a slow consumer feels immediate (5 ms is
// below human-perception for interactive I/O) but responsive enough for
// gossip convergence bursts where the sender is sensitive to even a few
// milliseconds of grant delay.
//
// Operators can override via AETHER_GRANT_COALESCE_MS at process start.
// Default 5ms; set to 1ms for aggressive flushing during incident
// response (trade more WINDOW_UPDATE frames for faster sender
// unblocking).
var GrantCoalesceWindow = 5 * time.Millisecond

// GrantImmediateFraction — if pending consume is at least this fraction of
// the window's initialCredit, flush immediately instead of waiting for
// the coalesce timer. Keeps burst responsiveness: a fast consumer reading
// back-to-back payloads still triggers grants as the window drains.
//
// Operators can override via AETHER_GRANT_IMMEDIATE_FRACTION at process
// start. Default 0.1 — a 400 KB pending on a 4 MB window flushes now
// instead of waiting for the coalesce timer. Lower values (e.g. 0.01)
// make grants fire aggressively on small consumes.
var GrantImmediateFraction = 0.1

// GrantWatchdogInterval is the cadence at which the shared sweeper
// goroutine force-flushes any pending grant whose last flush is older
// than this interval. Always on — catches rare cases where the coalesce
// timer path was skipped (scheduling stall, Record never called,
// AfterFunc descheduled long enough that pending accumulates) without
// spamming grants in healthy flows.
//
// Operators can override via AETHER_GRANT_WATCHDOG_MS at process start.
// Default 500ms. Set to a larger value to reduce sweeper wake-ups on
// idle fleets; set lower during incident response.
var GrantWatchdogInterval = 500 * time.Millisecond

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

// minWatchdogSweeperInterval is the floor for the shared sweeper's tick
// rate. Avoids configurations where a tiny GrantWatchdogInterval spins
// the sweeper goroutine hot without observable benefit.
const minWatchdogSweeperInterval = 100 * time.Millisecond

// watchdogRegistry holds every live grantDebouncer and drives a single
// sweeper goroutine that force-flushes stuck pending grants. One
// goroutine per process (regardless of peer count × stream count)
// replaces the previous model of one watchdog goroutine per debouncer,
// which scaled to 800+ goroutines on a 200-peer × 4-stream fleet.
type watchdogRegistry struct {
	mu         sync.Mutex
	debouncers map[*grantDebouncer]struct{}
	running    bool
	emptyTicks int // consecutive ticks with zero registered debouncers
}

// emptyTicksBeforeExit is how many consecutive empty ticks the sweeper
// observes before it exits. Re-registration (new stream opened) lazily
// restarts it. Keeping the sweeper alive for a few ticks past the last
// Close avoids churn on transient registry emptiness.
const emptyTicksBeforeExit = 4

var sharedWatchdog = &watchdogRegistry{
	debouncers: make(map[*grantDebouncer]struct{}),
}

// register adds d to the sweeper's set and starts the sweeper goroutine
// on first registration (or resumes it if it had exited on empty).
func (r *watchdogRegistry) register(d *grantDebouncer) {
	r.mu.Lock()
	r.debouncers[d] = struct{}{}
	r.emptyTicks = 0
	startSweeper := !r.running
	if startSweeper {
		r.running = true
	}
	r.mu.Unlock()
	if startSweeper {
		go r.runSweeper()
	}
}

// deregister removes d from the sweeper's set. The sweeper itself
// observes the empty set on a tick and exits; no immediate stop signal
// is needed.
func (r *watchdogRegistry) deregister(d *grantDebouncer) {
	r.mu.Lock()
	delete(r.debouncers, d)
	r.mu.Unlock()
}

// runSweeper is the single package-level goroutine that walks every
// registered debouncer on each tick and force-flushes any whose pending
// has been stuck for longer than GrantWatchdogInterval.
//
// Tick cadence is max(GrantWatchdogInterval, minWatchdogSweeperInterval)
// — the watchdog interval is the gap after which a flush is considered
// stuck; the sweeper runs at least that often. The inner walk is
// O(N) debouncers but the per-debouncer work is a trylock + a pointer
// check, so walking 800 entries every 500 ms is cheap.
func (r *watchdogRegistry) runSweeper() {
	interval := GrantWatchdogInterval
	if interval < minWatchdogSweeperInterval {
		interval = minWatchdogSweeperInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	gapThreshold := GrantWatchdogInterval
	for range ticker.C {
		r.mu.Lock()
		if len(r.debouncers) == 0 {
			r.emptyTicks++
			if r.emptyTicks >= emptyTicksBeforeExit {
				r.running = false
				r.mu.Unlock()
				return
			}
			r.mu.Unlock()
			continue
		}
		r.emptyTicks = 0
		// Snapshot the debouncer set under the registry lock so the
		// per-debouncer gap check below can acquire each debouncer's mu
		// without holding the registry lock (avoids lock ordering
		// issues with Close).
		victims := make([]*grantDebouncer, 0, len(r.debouncers))
		for d := range r.debouncers {
			victims = append(victims, d)
		}
		r.mu.Unlock()
		for _, d := range victims {
			d.checkAndFlushStuck(gapThreshold)
		}
	}
}

// grantDebouncer coalesces receiver-side consume accounting into
// batched WINDOW_UPDATE emissions.
//
// ReceiverConsume is called at application-read time (inside
// stream.Receive()) so that grants advertise application-level progress,
// not frame arrival. Driving grant emission from frame receipt would
// let the recv buffer fill without backpressuring the sender — when the
// buffer then overflowed, frames would be dropped after their credit had
// already been granted. By only recording bytes once the application has
// pulled them out, a slow consumer naturally backpressures the sender.
//
// The debouncer batches a short window of consume events into one
// ReceiverConsume call → one WINDOW_UPDATE frame on the wire. The
// coalesce window is short enough to be imperceptible to the
// application; the immediate-fraction escape hatch keeps bursts
// responsive.
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
	// recent flush. The shared sweeper goroutine checks this on each
	// tick and force-flushes if pending > 0 and the gap exceeds
	// GrantWatchdogInterval. Protected by mu.
	lastFlushUnix int64
}

// newGrantDebouncer creates a debouncer bound to a grantable window and
// send callback. immediateFloor is typically a small fraction of the
// window's initial credit — set to 0 to disable the immediate-flush
// escape hatch (always wait for the coalesce window).
//
// The debouncer registers with the shared watchdog sweeper, which
// force-flushes stuck pending grants at GrantWatchdogInterval cadence.
// Deregisters automatically on Close().
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
	sharedWatchdog.register(d)
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
	// meaningful fraction of the window, don't hold it — the sender is
	// likely hitting the window edge and we want grants in flight now,
	// not a full coalesce window later.
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
// the debouncer inert. Subsequent Record calls are no-ops. Deregisters
// from the shared watchdog sweeper. Idempotent.
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
	d.mu.Unlock()
	sharedWatchdog.deregister(d)
}

// checkAndFlushStuck is called by the shared watchdog sweeper. If the
// debouncer has accumulated pending without flushing for at least
// `gapThreshold`, force a flush so the sender doesn't stall waiting for
// a grant that was already earned but never delivered.
func (d *grantDebouncer) checkAndFlushStuck(gapThreshold time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.pending <= 0 {
		return
	}
	gap := time.Since(time.Unix(0, d.lastFlushUnix))
	if gap < gapThreshold {
		return
	}
	if dbgGrant.Enabled() {
		dbgGrant.Printf("stream=%d watchdog trip pending=%d gap=%s",
			d.streamID, d.pending, gap)
	}
	d.flushLocked("watchdog")
}
