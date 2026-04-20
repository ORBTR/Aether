/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package flow

import (
	"context"
	"testing"
	"time"
)

// Use sizes strictly above MinGuaranteedWindow so the metered path is exercised.
// Small frames (≤ MinGuaranteedWindow) bypass accounting by design.
const testCredit = 16 * 1024 // 16 KB — comfortably above the 1 KB escape hatch

func TestStreamWindow_ConsumeAndAvailable(t *testing.T) {
	w := NewStreamWindow(testCredit)
	ctx := context.Background()

	if w.Available() != testCredit {
		t.Errorf("initial: got %d, want %d", w.Available(), testCredit)
	}

	if err := w.Consume(ctx, testCredit/2); err != nil {
		t.Fatalf("consume half: %v", err)
	}
	if w.Available() != testCredit/2 {
		t.Errorf("after half: got %d, want %d", w.Available(), testCredit/2)
	}

	// Exhaust
	if err := w.Consume(ctx, testCredit/2); err != nil {
		t.Fatalf("consume remaining: %v", err)
	}
	if w.Available() != 0 {
		t.Errorf("after exhaust: got %d, want 0", w.Available())
	}

	// Small frames within MinGuaranteedWindow are always allowed (escape hatch,
	// NOT metered — so they don't change Available()).
	avail := w.Available()
	if err := w.Consume(ctx, MinGuaranteedWindow); err != nil {
		t.Errorf("escape-hatch frame should always succeed: %v", err)
	}
	if w.Available() != avail {
		t.Errorf("escape-hatch frame should not consume credit: got %d, want %d", w.Available(), avail)
	}

	// Large over-consume beyond MinGuaranteedWindow must time out. Give it a
	// tight deadline so the test is fast; we don't care about the exact
	// wording, only that it errors.
	tctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if err := w.Consume(tctx, testCredit); err == nil {
		t.Error("should error on overconsume beyond MinGuaranteedWindow")
	}
}

func TestStreamWindow_ApplyUpdate(t *testing.T) {
	w := NewStreamWindow(testCredit)
	ctx := context.Background()

	if err := w.Consume(ctx, testCredit); err != nil {
		t.Fatalf("consume exhaust: %v", err)
	}
	if w.Available() != 0 {
		t.Fatalf("after exhaust: got %d, want 0", w.Available())
	}

	// Cumulative semantics: ApplyUpdate(credit) treats credit as the peer's
	// total-ever-granted. Delta = credit - grantsReceived. Grant exactly
	// testCredit cumulative (== testCredit delta since we've seen 0 before).
	w.ApplyUpdate(testCredit)
	if got := w.Available(); got != testCredit {
		t.Errorf("after full grant: got %d, want %d", got, testCredit)
	}
}

func TestStreamWindow_ApplyUpdate_Idempotent(t *testing.T) {
	w := NewStreamWindow(testCredit)
	ctx := context.Background()

	if err := w.Consume(ctx, testCredit); err != nil {
		t.Fatalf("consume: %v", err)
	}

	// Cumulative grant of testCredit — should fully restore.
	w.ApplyUpdate(testCredit)
	if got := w.Available(); got != testCredit {
		t.Fatalf("first apply: got %d, want %d", got, testCredit)
	}

	// Consume again and expose the idempotency of a stale retransmit.
	if err := w.Consume(ctx, testCredit); err != nil {
		t.Fatalf("re-consume: %v", err)
	}
	// Re-applying the SAME cumulative value must be a no-op (delta <= 0).
	// This is the core property that makes the grant channel tolerant of
	// duplicate/reordered WINDOW_UPDATE frames on lossy Noise-UDP.
	w.ApplyUpdate(testCredit)
	if got := w.Available(); got != 0 {
		t.Errorf("stale re-apply should be no-op: got %d, want 0", got)
	}

	// A new cumulative value does advance.
	w.ApplyUpdate(2 * testCredit)
	if got := w.Available(); got != testCredit {
		t.Errorf("after advance: got %d, want %d", got, testCredit)
	}
}

func TestStreamWindow_ApplyUpdate_LossRecovery(t *testing.T) {
	// Simulates the loss scenario on Noise-UDP: receiver emits several
	// cumulative grants, only the final one arrives. The sender should still
	// recover to the same state as if all grants had been delivered.
	w := NewStreamWindow(testCredit)
	ctx := context.Background()
	if err := w.Consume(ctx, testCredit); err != nil {
		t.Fatalf("consume: %v", err)
	}

	// Grants 1 and 2 "lost" — sender only receives grant 3 (cumulative testCredit).
	w.ApplyUpdate(testCredit)
	if got := w.Available(); got != testCredit {
		t.Errorf("loss-recovery: got %d, want %d (final grant must recover all)", got, testCredit)
	}
}

func TestStreamWindow_ApplyUpdate_Capped(t *testing.T) {
	w := NewStreamWindow(testCredit)
	// Cumulative grant far larger than what's outstanding; the release must
	// cap at dataOutstanding (which is 0 here) so Available stays == initial.
	w.ApplyUpdate(DefaultMaxStreamCredit + 1000)
	if w.Available() > DefaultMaxStreamCredit {
		t.Errorf("should cap at outstanding: got %d", w.Available())
	}
}

func TestStreamWindow_ReceiverAutoGrant(t *testing.T) {
	w := NewStreamWindow(testCredit)

	// Consume less than threshold — no grant.
	grant := w.ReceiverConsume(100)
	if grant != 0 {
		t.Errorf("small consume: got grant %d, want 0", grant)
	}

	// Threshold = testCredit * 0.25. Consume past it — the returned value is
	// the CUMULATIVE total granted (always > 0 on first successful grant).
	threshold := int64(float64(testCredit) * AutoGrantThreshold)
	grant = w.ReceiverConsume(threshold + 100)
	if grant == 0 {
		t.Error("should grant after exceeding threshold")
	}
	firstGrant := grant

	// Next receive that crosses the threshold again bumps the cumulative.
	grant2 := w.ReceiverConsume(threshold + 100)
	if grant2 == 0 {
		t.Error("second grant should fire")
	}
	if grant2 <= firstGrant {
		t.Errorf("cumulative counter must increase: first=%d second=%d", firstGrant, grant2)
	}
}

// Regression test for Bug A: in production, NewStreamWindow is called with
// DefaultStreamCredit (256 KB), which equals DefaultMaxStreamCredit. The
// earlier implementation pinned recvCredit at maxSize from construction, so
// ReceiverConsume always returned 0 — no WINDOW_UPDATEs ever flowed.
func TestStreamWindow_ReceiverAutoGrant_ProductionConfig(t *testing.T) {
	w := NewStreamWindow(DefaultStreamCredit) // initial == max (the real-world case)

	threshold := int64(float64(DefaultStreamCredit) * AutoGrantThreshold)
	// Simulate enough receive activity to cross the threshold.
	grant := w.ReceiverConsume(threshold + 1024)
	if grant == 0 {
		t.Fatal("Bug A regression: receiver returned 0 grant when initialCredit == maxSize — sender would never get WINDOW_UPDATE")
	}

	// Further receipts should also produce grants, not drift to 0.
	grant2 := w.ReceiverConsume(threshold + 1024)
	if grant2 == 0 {
		t.Error("second grant also returned 0 — recvCredit not tracking outstanding correctly")
	}
}

func TestConnWindow_ConsumeAndAvailable(t *testing.T) {
	w := NewConnWindow(4096)

	if err := w.Consume(2048); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if w.Available() != 2048 {
		t.Errorf("after consume: got %d, want 2048", w.Available())
	}

	if err := w.Consume(3000); err == nil {
		t.Error("should error on overconsume")
	}

	// Escape hatch: tiny frames always pass without metering.
	avail := w.Available()
	if err := w.Consume(MinGuaranteedWindow); err != nil {
		t.Errorf("escape-hatch frame should succeed: %v", err)
	}
	if w.Available() != avail {
		t.Errorf("escape-hatch frame should not consume credit: got %d, want %d", w.Available(), avail)
	}
}

func TestConnWindow_ReceiverAutoGrant(t *testing.T) {
	w := NewConnWindow(4096)

	// Consume past 25% threshold (1024).
	grant := w.ReceiverConsume(3000)
	if grant == 0 {
		t.Error("should grant after exceeding threshold")
	}
}

// Regression test for Bug A at the connection level: when receive flow is
// sustained, grants must continue to emit — they must not pin at zero once
// recvCredit has aggregated to maxSize.
func TestConnWindow_SustainedGrants(t *testing.T) {
	w := NewConnWindow(DefaultConnCredit)

	// Drive enough receive volume that the old bug (recvCredit never
	// decremented) would cause grants to become 0 after the first few rounds.
	// Here we expect grants to keep flowing as long as data keeps arriving.
	total := int64(0)
	for i := 0; i < 20; i++ {
		g := w.ReceiverConsume(DefaultConnCredit / 2) // 512 KB per step
		total += g
	}
	if total == 0 {
		t.Fatal("Bug A regression: no grants emitted over 20 large-receive iterations")
	}
}
