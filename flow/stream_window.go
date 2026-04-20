/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

// Package flow implements credit-based flow control for Aether streams.
// Used by transports that lack native flow control (TCP, WebSocket, Noise-UDP).
// QUIC and gRPC transports skip this layer.
package flow

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
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
// Frames at or below this size (control headers, ACKs, keepalive hints) bypass
// credit accounting entirely: they never block waiting for credit and never
// consume it. This guarantees WINDOW_UPDATE and similar in-band control traffic
// can always flow, even when the stream's send window is exhausted.
const MinGuaranteedWindow int64 = 1024 // 1KB

// ConsumeTimeout is how long Consume waits for credit before returning an error.
const ConsumeTimeout = 10 * time.Second

// StreamWindow implements per-stream credit-based flow control.
//
// Sender side: Consume blocks until credit is available (up to ConsumeTimeout)
// using a golang.org/x/sync/semaphore — no busy polling, context-aware
// cancellation. Small frames (≤ MinGuaranteedWindow) bypass the semaphore
// entirely and are never charged: the escape hatch is meant for in-band
// control traffic, not a bandwidth meter.
//
// Receiver side: grants credit via WINDOW_UPDATE once the sender has consumed
// AutoGrantThreshold of the initial window. recvCredit tracks outstanding
// granted-but-not-yet-consumed credit so that grants correctly reset the
// window instead of pinning at maxSize.
//
// NOTE on future work (Level 3): a long-term direction is to drop the
// credit-counter model entirely and gate Send on the write queue depth,
// mirroring QUIC/HTTP/2 stream-level offsets. That's a larger refactor and
// only makes sense if flow control needs further work — the current design
// is correct and efficient with the semaphore.
type StreamWindow struct {
	mu sync.Mutex

	// Send-side: credit is tracked inside the semaphore. Capacity is maxSize.
	//
	//   - initialDeficit: permanently acquired at construction when
	//     initialCredit < maxSize. Enforces the initial-credit cap without
	//     ever being released.
	//   - dataOutstanding: data bytes acquired by Consume but not yet released
	//     by an incoming WINDOW_UPDATE. Grants cap at this value so we never
	//     release past the actual in-flight amount.
	//
	// Effective send credit = maxSize - initialDeficit - dataOutstanding.
	sem             *semaphore.Weighted
	maxSize         int64
	initialDeficit  int64
	dataOutstanding int64

	// Receive-side accounting — drives auto-grant decisions.
	// recvCredit represents credit we have extended to the sender but that has
	// not yet been consumed by the data arriving at us. It decreases as we
	// receive data (we're consuming the credit we previously granted) and
	// increases when we emit a new WINDOW_UPDATE.
	initialSize int64
	recvCredit  int64
	consumed    int64
	lastGrant   int64
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

	// The semaphore starts with maxSize capacity fully available. If the caller
	// wants initialCredit < maxSize, pre-acquire the deficit so the effective
	// send window matches initialCredit. The deficit is tracked in
	// initialDeficit and never released — it encodes the configured initial
	// credit as a permanent reservation. Grants only release the data-in-flight
	// portion (dataOutstanding), so the effective window never grows past
	// initialCredit's restoration point.
	sem := semaphore.NewWeighted(maxSize)
	var deficit int64
	if initialCredit < maxSize {
		deficit = maxSize - initialCredit
		// Safe: fresh semaphore has full capacity, cannot block.
		_ = sem.Acquire(context.Background(), deficit)
	}

	return &StreamWindow{
		sem:            sem,
		maxSize:        maxSize,
		initialDeficit: deficit,
		initialSize:    initialCredit,
		recvCredit:     initialCredit,
	}
}

// Consume reserves n bytes of sender credit before a Send.
//
// Small frames (≤ MinGuaranteedWindow) are NOT metered — they bypass the
// semaphore entirely. See MinGuaranteedWindow's doc for rationale.
//
// Larger frames block waiting for credit, honouring ctx cancellation. After
// ConsumeTimeout with no credit the call fails; higher layers (gossip)
// surface this as "insufficient stream credit after 10s".
func (w *StreamWindow) Consume(ctx context.Context, n int64) error {
	if n <= 0 {
		return nil
	}
	if n <= MinGuaranteedWindow {
		// Escape hatch — small frames always pass, no metering. This prevents
		// deadlocks where WINDOW_UPDATE and other control traffic would be
		// stuck behind a drained data window.
		return nil
	}

	acquireCtx, cancel := context.WithTimeout(ctx, ConsumeTimeout)
	defer cancel()

	if err := w.sem.Acquire(acquireCtx, n); err != nil {
		return fmt.Errorf("aether flow: insufficient stream credit after %s (need %d, have %d): %w",
			ConsumeTimeout, n, w.Available(), err)
	}

	w.mu.Lock()
	w.dataOutstanding += n
	w.mu.Unlock()
	return nil
}

// ApplyUpdate adds credit from a received WINDOW_UPDATE frame.
// Called on the sender side when the receiver grants more credit.
// Grants beyond the currently in-flight data (dataOutstanding) are silently
// dropped — we never release past what Consume actually acquired, so the
// effective window never grows above initialCredit's restoration point and
// the semaphore is never released past its capacity.
func (w *StreamWindow) ApplyUpdate(credit int64) {
	if credit <= 0 {
		return
	}
	w.mu.Lock()
	if credit > w.dataOutstanding {
		credit = w.dataOutstanding
	}
	w.dataOutstanding -= credit
	w.mu.Unlock()
	if credit > 0 {
		w.sem.Release(credit)
	}
}

// ReceiverConsume records that the receiver consumed n bytes of received data.
// Returns the credit to grant (for a WINDOW_UPDATE) if the threshold is met.
// Returns 0 if no grant is needed yet.
//
// BUG FIX: recvCredit is decremented by n so that the subsequent cap check
// reflects the truly-outstanding window. The previous implementation never
// decremented recvCredit; in production where initialCredit == maxSize it
// pinned at maxSize and every grant became 0 — the receiver never emitted
// a single WINDOW_UPDATE, causing sender-side starvation.
func (w *StreamWindow) ReceiverConsume(n int64) int64 {
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
		return grant
	}
	return 0
}

// Available returns the sender's remaining credit.
func (w *StreamWindow) Available() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.maxSize - w.initialDeficit - w.dataOutstanding
}

// receiverCredit returns the credit currently outstanding with the sender
// (total granted minus data already received). Exported only for tests.
func (w *StreamWindow) receiverCredit() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.recvCredit
}
