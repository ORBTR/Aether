//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

package adapter

import (
	"context"
	"testing"

	"github.com/ORBTR/aether/flow"
)

// TestConsumeDrivenGrants_SlowConsumerBackpressuresSender proves the core
// backpressure invariant of the receiver-side grant path: sender credit is
// refilled ONLY in proportion to what the application has actually consumed
// (grantDebouncer.Record → StreamWindow.ReceiverConsume), never ahead of it.
// A consumer that has read fewer bytes therefore leaves the sender with less
// credit — which is exactly what application-level backpressure means. If
// grants emitted on frame arrival instead of application read, a slow
// consumer would signal nothing to the sender and the recv buffer would
// overflow after credit had already been advertised.
//
// This is asserted structurally, with no wall-clock timing and no racing
// goroutines. The earlier form of this test compared the elapsed refill time
// of a fast (0-delay) consumer against a slow (10 ms/read) one; that raced
// two timed goroutines and flaked under CI CPU starvation (the "fast"
// measurement inflated toward the "slow" one when goroutines were starved).
// The property under test — refill tracks consumption — is captured here
// directly and deterministically from the window's own accounting:
//
//   - On a non-growing window, grantLocked computes grant = currentWindow −
//     recvCredit and recvCredit == initialCredit − consumed + granted, so the
//     cumulative grant can never exceed cumulative consumed. Hence at every
//     step Available() ≤ post-consume-floor + bytes-recorded-so-far.
//   - The sender therefore cannot reach the half-window credit mark until it
//     has consumed at least (halfWindow − floor) bytes of real application
//     reads — credit strictly cannot precede consumption.
func TestConsumeDrivenGrants_SlowConsumerBackpressuresSender(t *testing.T) {
	const (
		window      = 4 * 1024 * 1024
		payloadSize = 128 * 1024
		payloads    = 20 // 2.5 MB total — drains most of the 4 MB window
	)

	w := flow.NewStreamWindow(window)
	// send applies each cumulative grant back to the window, exactly as the
	// real WINDOW_UPDATE path does, so Available() tracks true refill. It is
	// called synchronously from Flush() below on this same goroutine, so no
	// locking is needed.
	var appliedCumulative int64
	send := func(_ uint64, credit uint64) {
		appliedCumulative = int64(credit)
		w.ApplyUpdate(int64(credit))
	}
	d := newGrantDebouncer(w, send, 42, int64(float64(window)*GrantImmediateFraction))
	defer d.Close()

	// Sender drains the workload up front: Available drops to a floor below
	// the half-window mark.
	if err := w.Consume(context.Background(), payloadSize*payloads); err != nil {
		t.Fatalf("consume: %v", err)
	}
	floor := w.Available()
	halfWindow := int64(window / 2)
	if floor >= halfWindow {
		t.Fatalf("workload did not drain below half-window: Available=%d halfWindow=%d — test premise broken",
			floor, halfWindow)
	}

	// Invariant 1: with zero application reads, credit does NOT refill. Frames
	// merely being dispatched (the workload) grant nothing on their own; only
	// Record() (application consumption) can move credit.
	if got := w.Available(); got != floor {
		t.Fatalf("credit refilled with zero application reads: floor=%d now=%d", floor, got)
	}

	// Drive consumption one payload at a time, forcing a synchronous Flush so
	// emission is deterministic (never left to the 5 ms coalesce timer or the
	// 500 ms watchdog). Track monotonicity, the consumption bound, and the
	// first read at which Available reaches the half-window mark.
	prev := floor
	crossedAt := -1
	for i := 0; i < payloads; i++ {
		d.Record(payloadSize)
		d.Flush()
		cur := w.Available()

		if cur < prev {
			t.Fatalf("Available regressed on read %d: %d < %d", i+1, cur, prev)
		}
		recorded := int64(i+1) * payloadSize
		if cur > floor+recorded {
			t.Fatalf("read %d: credit outran consumption — Available=%d > floor(%d)+recorded(%d); grants are not consume-driven",
				i+1, cur, floor, recorded)
		}
		if crossedAt < 0 && cur >= halfWindow {
			crossedAt = i + 1
		}
		prev = cur
	}

	// By the end (all bytes consumed) the sender must have reached half-window
	// credit — but NOT before it had consumed enough real reads to cover the
	// floor→halfWindow gap. That lower bound is the backpressure guarantee.
	if crossedAt < 0 {
		t.Fatalf("Available never reached half-window after all %d reads: Available=%d appliedCumulative=%d",
			payloads, w.Available(), appliedCumulative)
	}
	minReads := int((halfWindow - floor + payloadSize - 1) / payloadSize) // ceil
	if crossedAt < minReads {
		t.Errorf("reached half-window after only %d reads; refill outran consumption (need ≥ %d)",
			crossedAt, minReads)
	}
	t.Logf("consume-driven refill: floor=%d, crossed half-window after %d/%d reads (min %d), appliedCumulative=%d",
		floor, crossedAt, payloads, minReads, appliedCumulative)
}
