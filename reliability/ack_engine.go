/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

// ACKEngine manages Composite ACK generation for a single stream.
// Implements adaptive ACK frequency (ACK every N packets OR every T ms),
// bitmap auto-scaling (0/32/64/128/256 bits), loss density tracking,
// and ACK-lite mode for the common no-gap case.

package reliability

import (
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ORBTR/aether"
)

// ackEmitCount counts ACK emissions across all engines globally.
// Periodically logged so we can observe whether ACKs are being
// generated at all on a node (vs being dropped on the wire).
var ackEmitCount atomic.Uint64
var lastAckLogAt atomic.Int64 // unix nanos of last log emission

// ACK-emit reason counters — distinguishes which OnDataReceived
// trigger caused each flushLocked. The delay-timer path imposes a
// ~MaxDelay (25ms default) RTT floor for small RPC responses that
// don't satisfy any of the immediate triggers (gap / control /
// post-idle / max-packets), so it is the candidate latency amplifier
// for low-RTT RPC.
//   ackEmitImmediate  — gap / control stream / first frame after
//                       idle / max-packets threshold.
//   ackEmitDelayTimer — adaptive delayed-ACK timer fired with no
//                       immediate trigger applied.
//   ackEmitDuplicate  — OnDuplicateReceived forced an immediate flush
//                       so the sender's retransmit timer clears.
//
// Counted globally across all engines; sum approximates ackEmitCount
// minus on-demand Flush() calls from stream-close paths.
var (
	ackEmitImmediate atomic.Uint64
	ackEmitDelayTimer    atomic.Uint64
	ackEmitDuplicate     atomic.Uint64
)

// AckEmitStats returns global ACK-engine emit counters for surfacing
// via Library MeshMetrics. Distinguishes delay-timer-driven emissions
// (the adaptive ack-delay floor — candidate for RPC latency
// amplification on fast paths) from immediate emissions and
// duplicate-triggered emits.
func AckEmitStats() (immediate, delayTimer, duplicate uint64) {
	return ackEmitImmediate.Load(),
		ackEmitDelayTimer.Load(),
		ackEmitDuplicate.Load()
}

// dbgACK is the debug logger for the ACK engine. Enable with
// DEBUG=aether.reliability.ack (or any ancestor: aether.reliability,
// aether). Used to confirm whether real mesh traffic actually reaches
// OnDataReceived and whether the flush path fires — diagnosing the
// observed fleet-wide "zero ACKs emitted" condition.
var dbgACK = aether.NewDebugLogger("aether.reliability.ack")

// ACKPolicy controls when ACKs are sent.
type ACKPolicy struct {
	MaxPackets int           // ACK every N packets (default: 2)
	MaxDelay   time.Duration // OR every T ms (default: 25ms)
	ImmOnGap   bool          // ACK immediately on gap detection (default: true)
	ImmOnCtrl  bool          // ACK immediately for control streams (default: true)
}

// DefaultACKPolicy returns the default adaptive ACK policy.
func DefaultACKPolicy() ACKPolicy {
	return ACKPolicy{
		MaxPackets: 2,
		MaxDelay:   25 * time.Millisecond,
		ImmOnGap:   true,
		ImmOnCtrl:  true,
	}
}

// ReorderThreshold is the minimum packet number distance before
// declaring a gap as a loss (fast retransmit). Matches QUIC RFC 9002 §6.1.1.
const ReorderThreshold = 3

// ACKEngine manages ACK generation for a single stream.
type ACKEngine struct {
	mu         sync.Mutex
	recvWindow *RecvWindow
	policy     ACKPolicy
	pending    int       // packets received since last ACK
	lastACK    time.Time // when last ACK was sent
	lastIdle   time.Time // last time stream was idle (for ACK-on-first-after-idle)
	bitmapBits int       // current bitmap size (auto-scaled)

	// Loss tracking for LossDensity extension
	lossRing [256]bool // ring buffer: true=received, false=lost
	ringHead uint8     // current position
	received int       // count of received in ring

	// Callback to send the ACK
	sendACK func(ack *aether.CompositeACK)

	// RTT callback for adaptive thresholds (first-after-idle, bitmap sizing)
	rttFn func() time.Duration

	// currentGrantFn returns the stream window's CUMULATIVE grant so the
	// ACK engine can piggyback it on the next CompositeACK via the
	// CACKHasWindowCredit extension. When set AND the returned value is
	// > lastEmittedCredit, the ACK carries the credit and we advance
	// lastEmittedCredit; otherwise the flag is omitted (the peer already
	// got this cumulative value on a previous ACK or WINDOW_UPDATE).
	//
	// Optional: nil means "no piggyback on this engine" — the stream
	// window continues to emit standalone WINDOW_UPDATE frames.
	currentGrantFn     func() int64
	lastEmittedCredit  uint64

	// Delayed ACK timer. time.Timer's own Stop() prevents the AfterFunc
	// from running after teardown; no separate stop channel is needed.
	timerMu sync.Mutex
	timer   *time.Timer
}

// NewACKEngine creates an ACK engine for a stream.
// rttFn returns the current SRTT estimate — used for first-after-idle threshold.
func NewACKEngine(rw *RecvWindow, policy ACKPolicy, sendFn func(*aether.CompositeACK), rttFn func() time.Duration) *ACKEngine {
	e := &ACKEngine{
		recvWindow: rw,
		policy:     policy,
		bitmapBits: 64,
		sendACK:    sendFn,
		rttFn:      rttFn,
	}
	return e
}

// SetWindowCreditFn registers the cumulative-grant getter used to
// piggyback WINDOW_UPDATE credit on CompositeACKs. Pass nil to disable
// piggybacking. Safe to call any time.
func (e *ACKEngine) SetWindowCreditFn(fn func() int64) {
	e.mu.Lock()
	e.currentGrantFn = fn
	e.mu.Unlock()
}

// OnDataReceived is called when a data frame arrives.
// Updates loss tracking and triggers an ACK if policy conditions are met.
func (e *ACKEngine) OnDataReceived(seqNo uint32, isControlStream bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.pending++

	// Diagnostic: confirms real inbound traffic reaches the ACK engine.
	// If this never logs under load, data frames bypass this layer
	// (handleData not reached, or wrong frame type) — see dbgACK.
	dbgACK.Printf("OnDataReceived seq=%d control=%v pending=%d buffered=%d maxPackets=%d",
		seqNo, isControlStream, e.pending, e.recvWindow.BufferedCount(), e.policy.MaxPackets)

	// Track loss in ring buffer
	e.lossRing[e.ringHead] = true
	e.ringHead++
	e.received++

	// Rule 1: Gap detected → immediate ACK
	if e.policy.ImmOnGap && e.recvWindow.BufferedCount() > 0 {
		ackEmitImmediate.Add(1)
		e.flushLocked()
		return
	}

	// Rule 2: Control stream → immediate ACK
	if isControlStream && e.policy.ImmOnCtrl {
		ackEmitImmediate.Add(1)
		e.flushLocked()
		return
	}

	// Rule 3: First packet after idle (idle > 1×SRTT)
	idleThreshold := 100 * time.Millisecond // fallback if no RTT estimate
	if e.rttFn != nil {
		if srtt := e.rttFn(); srtt > 0 {
			idleThreshold = srtt
		}
	}
	if !e.lastIdle.IsZero() && time.Since(e.lastIdle) > idleThreshold {
		ackEmitImmediate.Add(1)
		e.flushLocked()
		e.lastIdle = time.Time{} // clear idle
		return
	}

	// Rule 4: MaxPackets reached
	if e.pending >= e.policy.MaxPackets {
		ackEmitImmediate.Add(1)
		e.flushLocked()
		return
	}

	// Rule 5: Start/reset delayed ACK timer (counter increments in
	// startTimerLocked AfterFunc body so we capture actual timer fires,
	// not just timer arms).
	e.startTimerLocked()
}

// Flush forces an immediate ACK send (used on stream close, etc.).
func (e *ACKEngine) Flush() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.flushLocked()
}

// OnDuplicateReceived is called when a duplicate frame arrives — a
// SeqNo already marked as seen in the per-stream replay window. The
// original was previously delivered + ACKed but the sender retransmitted
// because its ACK was lost / late. We force an immediate ACK back so
// the sender's retransmit timer clears its pending state and stops
// retransmitting. Without this, the sender's RTO/TLP keeps firing and
// the receiver sees duplicate after duplicate, burning bandwidth on
// wasted retransmits and prolonging recovery from one lost ACK to
// O(maxRetries × RTO) instead of one extra round-trip.
//
// Matches TCP's "immediate ACK on duplicate data" behaviour (RFC 5681
// §4.2) and QUIC's equivalent (RFC 9002 §B.7). The pending counter is
// bumped so flushLocked's pending-zero guard does not skip the send;
// buildLocked emits the CURRENT cumulative ACK (which already includes
// this SeqNo from the original receipt), giving the sender fresh
// evidence of delivery.
func (e *ACKEngine) OnDuplicateReceived(seqNo uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pending++
	dbgACK.Printf("OnDuplicateReceived seq=%d — forcing immediate ACK to clear sender retransmit", seqNo)
	ackEmitDuplicate.Add(1)
	e.flushLocked()
}

// MarkIdle records that the stream has been idle (for ACK-on-first-after-idle rule).
func (e *ACKEngine) MarkIdle() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lastIdle = time.Now()
}

// Stop cancels the delayed ACK timer.
func (e *ACKEngine) Stop() {
	e.timerMu.Lock()
	defer e.timerMu.Unlock()
	if e.timer != nil {
		e.timer.Stop()
	}
}

// BuildCompositeACK constructs a CompositeACK from current state.
func (e *ACKEngine) BuildCompositeACK() *aether.CompositeACK {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.buildLocked()
}

// LossRate returns the current loss rate over the last 256 packets (0-10000).
func (e *ACKEngine) LossRate() uint16 {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.received <= 0 {
		return 0
	}
	// Count received in ring
	recv := 0
	for _, r := range e.lossRing {
		if r {
			recv++
		}
	}
	missed := 256 - recv
	return uint16(missed * 10000 / 256)
}

// ────────────────────────────────────────────────────────────────────────────
// Internal
// ────────────────────────────────────────────────────────────────────────────

func (e *ACKEngine) flushLocked() {
	if e.pending == 0 && e.recvWindow.BufferedCount() == 0 {
		dbgACK.Printf("flushLocked skipped — pending=0 buffered=0")
		return
	}
	// Diagnostic: confirms the flush path fires and sendACK is wired.
	// If OnDataReceived logs but this never does, no flush rule (or the
	// 25ms timer) is triggering; if this logs but sendACK_set=false the
	// callback was never registered.
	dbgACK.Printf("flushLocked firing — pending=%d buffered=%d sendACK_set=%v",
		e.pending, e.recvWindow.BufferedCount(), e.sendACK != nil)
	ack := e.buildLocked()
	e.pending = 0
	e.lastACK = time.Now()

	// Cancel pending timer
	e.timerMu.Lock()
	if e.timer != nil {
		e.timer.Stop()
	}
	e.timerMu.Unlock()

	// CRITICAL: release e.mu BEFORE calling sendACK. sendACK ultimately
	// invokes writeFrame → conn.Write which can block up to writeFrame-
	// Deadline (10s). If e.mu were held across that, every subsequent
	// OnDataReceived call would block on the lock — incoming frames pile
	// up, recvCh fills, ACK generation grinds to a halt across the whole
	// session. Symptom of holding the lock here is multi-minute session
	// wedges with the engine mutex pinned by the AfterFunc callback at
	// startTimerLocked().
	//
	// The lock-yield-then-call pattern requires the caller to hold e.mu
	// at function entry — which all flushLocked() call sites do. We
	// release before invoking the callback, then RE-ACQUIRE so the
	// caller's deferred Unlock remains correct.
	sendACK := e.sendACK
	prevACK := e.lastACK
	e.mu.Unlock()
	if sendACK != nil {
		sendACK(ack)
		// Counter-bump per emission. Periodically logged so we can
		// observe ACK production rate at the receiver side. If this
		// counter is incrementing while peers' sendBase still stays
		// at 0, ACKs are being generated but lost in transit (or
		// inbound on peer). If this counter never moves, ACKs aren't
		// being generated at all (engine policy never fires).
		count := ackEmitCount.Add(1)
		baseStr := uint32(0)
		if ack != nil {
			baseStr = ack.BaseACK
		}
		// First ACK after >1s of silence is suspicious — under healthy
		// load this engine fires every 25ms or sooner. Always log it
		// regardless of the 60s sampling window so silent ACK
		// starvation periods aren't diagnostically invisible behind
		// the [ACK-EMIT] sampling cadence.
		now := time.Now()
		if !prevACK.IsZero() && now.Sub(prevACK) > time.Second {
			log.Printf("[ACK-EMIT] resumed after %v silence baseACK=%d cumulative=%d",
				now.Sub(prevACK).Round(time.Millisecond), baseStr, count)
		} else {
			nowNano := now.UnixNano()
			lastNano := lastAckLogAt.Load()
			if nowNano-lastNano > int64(60*time.Second) && lastAckLogAt.CompareAndSwap(lastNano, nowNano) {
				log.Printf("[ACK-EMIT] cumulative=%d sample baseACK=%d", count, baseStr)
			}
		}
	}
	// Re-acquire so the caller's deferred Unlock still pairs with one Lock.
	e.mu.Lock()
}

func (e *ACKEngine) buildLocked() *aether.CompositeACK {
	expected := e.recvWindow.ExpectedSeqNo()
	bitmapBits := e.selectBitmapSize()

	bitmap, ackDelayUs, hasGap := e.recvWindow.GenerateBitmap(bitmapBits)

	// Convert delay from microseconds to 8µs units
	ackDelay := uint16(ackDelayUs / aether.AckDelayGranularity)

	ack := &aether.CompositeACK{
		BaseACK:  expected - 1, // cumulative: last in-order received
		AckDelay: ackDelay,
		Bitmap:   bitmap,
	}

	// Set HasGaps flag
	if hasGap {
		ack.Flags |= aether.CACKHasGaps
	}

	// Extended ranges (beyond bitmap window)
	if bitmapBits > 0 && e.recvWindow.NeedExtendedRanges(bitmapBits) {
		extRanges := e.recvWindow.ExtendedRanges(bitmapBits)
		if len(extRanges) > 0 {
			ack.ExtRanges = extRanges
			ack.Flags |= aether.CACKHasExtRanges
		}
	}

	// Loss density (advisory) — compute inline to avoid deadlock (mu already held)
	recv := 0
	for _, r := range e.lossRing {
		if r {
			recv++
		}
	}
	lossRate := uint16((256 - recv) * 10000 / 256)
	if lossRate > 0 {
		ack.LossRate = lossRate
		ack.Flags |= aether.CACKHasLossDensity
	}

	// Window-credit piggyback. If the stream window has granted new
	// cumulative credit since the last ACK we sent, attach it so the
	// sender's ApplyUpdate can release flow-control credit without a
	// separate WINDOW_UPDATE round-trip. Cumulative semantics mean
	// duplicates (ACK retransmits, reordered ACKs) are safe.
	if e.currentGrantFn != nil {
		if grant := uint64(e.currentGrantFn()); grant > e.lastEmittedCredit {
			ack.WindowCredit = grant
			ack.Flags |= aether.CACKHasWindowCredit
			e.lastEmittedCredit = grant
		}
	}

	return ack
}

// selectBitmapSize chooses the bitmap size based on the SeqNo spread of buffered packets.
// Uses spread (maxSeqNo - expected) not count, so sparse reordering gets a properly sized bitmap.
func (e *ACKEngine) selectBitmapSize() int {
	spread := e.recvWindow.Spread()
	if spread == 0 {
		return 0 // ACK-lite mode — no gaps
	}
	if spread <= 32 {
		return 32
	}
	if spread <= 64 {
		return 64
	}
	if spread <= 128 {
		return 128
	}
	return 256
}

func (e *ACKEngine) startTimerLocked() {
	e.timerMu.Lock()
	defer e.timerMu.Unlock()

	if e.timer != nil {
		e.timer.Stop()
	}
	// Adaptive delayed-ACK timeout: cap at min(MaxDelay, max(SRTT/4, 1ms))
	// so the timer scales with the actual round-trip latency of the path
	// rather than imposing a flat 25ms floor that dominates on fast LANs.
	//
	// Why SRTT/4: RFC 9002 §6.2 warns that a max_ack_delay above the
	// measured RTT impairs the sender's congestion control — the sender's
	// PTO and RTO are computed including the receiver's advertised ack
	// delay, so over-quoting wastes loss-recovery budget. Modern QUIC
	// implementations (quiche, msquic, nginx-quic) use SRTT/4 or
	// SRTT/min_rtt_fraction. SRTT/4 keeps the Nagle-style batching
	// benefit (4 packets per RTT can still coalesce) without bloating
	// RTT estimates on short-RTT paths.
	//
	// Why max(_, 1ms): on jittery paths a sub-millisecond timer
	// pathologically per-packet-acks every frame; 1ms keeps the
	// coalescing floor that matters for throughput. The MaxDelay ceiling
	// (25ms default) still applies as the worst case for high-RTT WAN.
	// Aligns with QUIC RFC 9002 — a flat MaxDelay timer imposes a fixed
	// RTT floor on every flush, amplifying RPC latency on low-RTT paths.
	delay := e.policy.MaxDelay
	if e.rttFn != nil {
		if srtt := e.rttFn(); srtt > 0 {
			adaptive := srtt / 4
			if adaptive < delay {
				delay = adaptive
			}
		}
	}
	if delay < time.Millisecond {
		delay = time.Millisecond
	}
	e.timer = time.AfterFunc(delay, func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		// Only count an actual emit, not the no-op skip path at the top
		// of flushLocked when pending+buffered are both zero (the typical
		// post-flush race where another rule already drained pending).
		willEmit := e.pending > 0 || e.recvWindow.BufferedCount() > 0
		if willEmit {
			ackEmitDelayTimer.Add(1)
		}
		e.flushLocked()
	})
}
