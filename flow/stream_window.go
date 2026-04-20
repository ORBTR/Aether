/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

// Package flow implements credit-based flow control for Aether streams.
// Used by transports that lack native flow control (TCP, WebSocket, Noise-UDP).
// QUIC and gRPC transports skip this layer.
package flow

import (
	"fmt"
	"sync"
	"time"
)

// DefaultStreamCredit is the initial flow control credit per stream (256 KB).
// Gossip full-sync payloads can reach ~100-150 KB with 11+ nodes and
// namespace-qualified records. Must be large enough for the largest
// single Send() call since flow control currently errors instead of blocking.
const DefaultStreamCredit int64 = 256 * 1024

// DefaultMaxStreamCredit is the maximum credit a stream can accumulate (256 KB).
// Reduced from 1 MB — no single stream needs more than 256 KB outstanding.
const DefaultMaxStreamCredit int64 = 256 * 1024

// AutoGrantThreshold is the fraction of credit consumed before auto-granting.
// When 25% of the initial credit is consumed, a WINDOW_UPDATE is triggered.
// Must be low enough that a single gossip exchange (~100KB) triggers a grant
// before the next exchange starts (gossip interval is 10s).
const AutoGrantThreshold = 0.25

// MinGuaranteedWindow is the escape hatch for flow control deadlock prevention.
// Even when sendCredit == 0, the sender can always send up to this many bytes.
// This ensures WINDOW_UPDATE frames can always flow, preventing both peers from
// blocking simultaneously.
const MinGuaranteedWindow int64 = 1024 // 1KB

// StreamWindow implements per-stream credit-based flow control.
//
// Sender side: consumes credit on each Send. Blocks when credit=0 (up to 10s).
// Receiver side: grants credit via WINDOW_UPDATE after consuming data.
type StreamWindow struct {
	mu          sync.Mutex
	sendCredit  int64 // bytes the sender can still send
	recvCredit  int64 // bytes the receiver has granted
	initialSize int64 // initial credit (for auto-grant calculation)
	maxSize     int64 // maximum credit
	consumed    int64 // total bytes consumed by receiver (for auto-grant)
	lastGrant   int64 // consumed at last WINDOW_UPDATE
}

// NewStreamWindow creates a flow control window with the given initial credit.
func NewStreamWindow(initialCredit int64) *StreamWindow {
	if initialCredit <= 0 {
		initialCredit = DefaultStreamCredit
	}
	// maxSize must be at least as large as initialCredit to prevent
	// the window from being immediately capped below the requested size.
	maxSize := DefaultMaxStreamCredit
	if initialCredit > maxSize {
		maxSize = initialCredit
	}
	return &StreamWindow{
		sendCredit:  initialCredit,
		recvCredit:  initialCredit,
		initialSize: initialCredit,
		maxSize:     maxSize,
	}
}

// Consume decrements sender credit by n bytes.
// Blocks up to 10 seconds waiting for WINDOW_UPDATE if insufficient credit.
// Exception: frames up to MinGuaranteedWindow are always allowed (deadlock prevention).
func (w *StreamWindow) Consume(n int64) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Small frames (control, headers) always pass through but don't
	// decrement below zero — prevents permanent negative credit drain
	// when WINDOW_UPDATEs are lost (e.g., Noise anti-replay drop).
	if n <= MinGuaranteedWindow {
		if w.sendCredit > 0 {
			w.sendCredit -= n
		}
		return nil
	}

	// Poll for credit with short sleep intervals.
	// ApplyUpdate() increases sendCredit when WINDOW_UPDATE arrives.
	// 50ms polling gives <50ms latency after grant with minimal CPU.
	deadline := time.Now().Add(10 * time.Second)
	for w.sendCredit < n {
		if time.Now().After(deadline) {
			return fmt.Errorf("aether flow: insufficient stream credit after 10s (need %d, have %d)", n, w.sendCredit)
		}
		w.mu.Unlock()
		time.Sleep(50 * time.Millisecond)
		w.mu.Lock()
	}

	w.sendCredit -= n
	return nil
}

// ApplyUpdate adds credit from a received WINDOW_UPDATE frame.
// Called on the sender side when the receiver grants more credit.
func (w *StreamWindow) ApplyUpdate(credit int64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.sendCredit += credit
	if w.sendCredit > w.maxSize {
		w.sendCredit = w.maxSize
	}
}

// ReceiverConsume records that the receiver consumed n bytes of received data.
// Returns the credit to grant (for a WINDOW_UPDATE) if the threshold is met.
// Returns 0 if no grant is needed yet.
func (w *StreamWindow) ReceiverConsume(n int64) int64 {
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

// Available returns the sender's remaining credit.
func (w *StreamWindow) Available() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.sendCredit
}

// receiverCredit returns the total credit granted to the sender.
func (w *StreamWindow) receiverCredit() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.recvCredit
}
