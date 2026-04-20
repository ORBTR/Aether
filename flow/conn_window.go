/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package flow

import (
	"fmt"
	"sync"
)

// DefaultConnCredit is the initial connection-level credit (1 MB).
const DefaultConnCredit int64 = 1024 * 1024

// DefaultMaxConnCredit is the maximum connection-level credit (16 MB).
const DefaultMaxConnCredit int64 = 16 * 1024 * 1024

// ConnWindow implements connection-level aggregate flow control.
// Prevents any single stream from starving the connection.
// All stream sends must also consume from the connection window.
//
// Unlike StreamWindow, ConnWindow.Consume does not block: it either
// succeeds or returns an error immediately. TCP-style backpressure at the
// stream level absorbs the wait; the connection window is a coarse safety
// limit, not a pacing mechanism.
//
// WINDOW_UPDATE semantics match StreamWindow: the wire value is the peer's
// CUMULATIVE total granted (grantsEmitted) since the connection began.
// The sender's ApplyUpdate computes the delta against grantsReceived and
// drops stale / duplicate / reordered frames. This makes conn-level grants
// loss-tolerant on unreliable transports.
type ConnWindow struct {
	mu          sync.Mutex
	sendCredit  int64
	initialSize int64
	maxSize     int64

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
	return &ConnWindow{
		sendCredit:  initialCredit,
		recvCredit:  initialCredit,
		initialSize: initialCredit,
		maxSize:     DefaultMaxConnCredit,
	}
}

// Consume decrements connection-level sender credit.
// Small frames (≤ MinGuaranteedWindow) bypass accounting entirely — they
// must always flow to keep WINDOW_UPDATE and control traffic unblocked.
func (w *ConnWindow) Consume(n int64) error {
	if n <= 0 {
		return nil
	}
	if n <= MinGuaranteedWindow {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if n > w.sendCredit {
		return fmt.Errorf("aether flow: insufficient connection credit (need %d, have %d)", n, w.sendCredit)
	}
	w.sendCredit -= n
	return nil
}

// ApplyUpdate processes a connection-level WINDOW_UPDATE where credit is
// the peer's cumulative total. Delta = credit - grantsReceived; stale
// frames (delta ≤ 0) are dropped.
func (w *ConnWindow) ApplyUpdate(credit int64) {
	if credit <= 0 {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if credit <= w.grantsReceived {
		return
	}
	delta := credit - w.grantsReceived
	w.grantsReceived = credit
	w.sendCredit += delta
	if w.sendCredit > w.maxSize {
		w.sendCredit = w.maxSize
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
		if w.recvCredit+grant > w.maxSize {
			grant = w.maxSize - w.recvCredit
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
	return w.sendCredit
}
