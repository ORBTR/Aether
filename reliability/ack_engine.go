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
	"sync"
	"time"

	"github.com/ORBTR/aether"
)

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

	// Delayed ACK timer
	timerMu   sync.Mutex
	timer     *time.Timer
	timerStop chan struct{}
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
		timerStop:  make(chan struct{}),
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

	// Track loss in ring buffer
	e.lossRing[e.ringHead] = true
	e.ringHead++
	e.received++

	// Rule 1: Gap detected → immediate ACK
	if e.policy.ImmOnGap && e.recvWindow.BufferedCount() > 0 {
		e.flushLocked()
		return
	}

	// Rule 2: Control stream → immediate ACK
	if isControlStream && e.policy.ImmOnCtrl {
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
		e.flushLocked()
		e.lastIdle = time.Time{} // clear idle
		return
	}

	// Rule 4: MaxPackets reached
	if e.pending >= e.policy.MaxPackets {
		e.flushLocked()
		return
	}

	// Rule 5: Start/reset delayed ACK timer
	e.startTimerLocked()
}

// Flush forces an immediate ACK send (used on stream close, etc.).
func (e *ACKEngine) Flush() {
	e.mu.Lock()
	defer e.mu.Unlock()
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
	select {
	case e.timerStop <- struct{}{}:
	default:
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
		return
	}
	ack := e.buildLocked()
	e.pending = 0
	e.lastACK = time.Now()

	// Cancel pending timer
	e.timerMu.Lock()
	if e.timer != nil {
		e.timer.Stop()
	}
	e.timerMu.Unlock()

	if e.sendACK != nil {
		e.sendACK(ack)
	}
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
	e.timer = time.AfterFunc(e.policy.MaxDelay, func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.flushLocked()
	})
}
