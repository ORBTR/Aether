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
type ConnWindow struct {
	mu          sync.Mutex
	sendCredit  int64
	recvCredit  int64
	initialSize int64
	maxSize     int64
	consumed    int64
	lastGrant   int64
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
func (w *ConnWindow) Consume(n int64) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if n > w.sendCredit && n > MinGuaranteedWindow {
		return fmt.Errorf("aether flow: insufficient connection credit (need %d, have %d)", n, w.sendCredit)
	}
	w.sendCredit -= n
	return nil
}

// ApplyUpdate adds credit from a connection-level WINDOW_UPDATE.
func (w *ConnWindow) ApplyUpdate(credit int64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.sendCredit += credit
	if w.sendCredit > w.maxSize {
		w.sendCredit = w.maxSize
	}
}

// ReceiverConsume records receiver consumption and returns grant amount if threshold met.
func (w *ConnWindow) ReceiverConsume(n int64) int64 {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.consumed += n
	sinceLastGrant := w.consumed - w.lastGrant

	threshold := int64(float64(w.initialSize) * AutoGrantThreshold)
	if sinceLastGrant >= threshold {
		grant := sinceLastGrant
		if w.recvCredit+grant > w.maxSize {
			grant = w.maxSize - w.recvCredit
		}
		w.recvCredit += grant
		w.lastGrant = w.consumed
		return grant
	}
	return 0
}

// Available returns the sender's remaining connection credit.
func (w *ConnWindow) Available() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.sendCredit
}
