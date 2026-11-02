/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package flow

import (
	"context"
	"errors"
	"testing"
	"time"
)

const testCredit = 16 * 1024 // 16 KB — comfortably above MinGuaranteedWindow

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

	// An exhausted window admits nothing, however small: the failure is the
	// typed backpressure, and a tight deadline keeps the test fast.
	for _, n := range []int64{1, MinGuaranteedWindow, testCredit} {
		tctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		err := w.Consume(tctx, n)
		cancel()
		if !errors.Is(err, ErrCreditExhausted) {
			t.Errorf("consume %d on an exhausted window: %v, want ErrCreditExhausted", n, err)
		}
	}
}

// A frame under MinGuaranteedWindow is charged like any other, on both
// windows and through TryConsume.
func TestWindows_ChargeSmallFrames(t *testing.T) {
	ctx := context.Background()
	w := NewStreamWindow(testCredit)
	if err := w.Consume(ctx, 512); err != nil {
		t.Fatalf("stream consume: %v", err)
	}
	if !w.TryConsume(512) {
		t.Fatal("stream TryConsume refused with credit left")
	}
	if got := w.Available(); got != testCredit-1024 {
		t.Errorf("stream Available %d, want %d", got, testCredit-1024)
	}
	c := NewConnWindow(testCredit)
	if err := c.Consume(ctx, 512); err != nil {
		t.Fatalf("conn consume: %v", err)
	}
	if got := c.Available(); got != testCredit-512 {
		t.Errorf("conn Available %d, want %d", got, testCredit-512)
	}
}

// A window holds at least MinGuaranteedWindow however it is built or shrunk,
// so one small message can always be admitted after the peer has consumed
// what is outstanding.
func TestStreamWindow_HoldsAtLeastMinGuaranteedWindow(t *testing.T) {
	w := NewStreamWindow(16)
	if got := w.CurrentWindow(); got != MinGuaranteedWindow {
		t.Errorf("built with 16: CurrentWindow %d, want %d", got, MinGuaranteedWindow)
	}
	w = NewStreamWindow(testCredit)
	if got := w.ShrinkWindow(testCredit); got != testCredit-MinGuaranteedWindow {
		t.Errorf("ShrinkWindow returned %d, want %d", got, testCredit-MinGuaranteedWindow)
	}
	if got := w.CurrentWindow(); got != MinGuaranteedWindow {
		t.Errorf("after shrink: CurrentWindow %d, want %d", got, MinGuaranteedWindow)
	}
	if got := w.ShrinkWindow(1); got != 0 {
		t.Errorf("ShrinkWindow at the floor returned %d, want 0", got)
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

// Regression test: NewStreamWindow called with DefaultStreamCredit
// (which equals DefaultMaxStreamCredit) must still produce grants. A
// receiver that pinned recvCredit at maxSize from construction would
// make ReceiverConsume return 0 forever, so no WINDOW_UPDATEs would
// flow and the sender would stall after initial credit exhausts.
func TestStreamWindow_ReceiverAutoGrant_ProductionConfig(t *testing.T) {
	w := NewStreamWindow(DefaultStreamCredit) // initial == max (the real-world case)

	threshold := int64(float64(DefaultStreamCredit) * AutoGrantThreshold)
	// Simulate enough receive activity to cross the threshold.
	grant := w.ReceiverConsume(threshold + 1024)
	if grant == 0 {
		t.Fatal("receiver returned 0 grant when initialCredit == maxSize — sender would never get WINDOW_UPDATE")
	}

	// Further receipts should also produce grants, not drift to 0.
	grant2 := w.ReceiverConsume(threshold + 1024)
	if grant2 == 0 {
		t.Error("second grant also returned 0 — recvCredit not tracking outstanding correctly")
	}
}

func TestConnWindow_ConsumeAndAvailable(t *testing.T) {
	w := NewConnWindow(4096)
	ctx := context.Background()

	if err := w.Consume(ctx, 2048); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if w.Available() != 2048 {
		t.Errorf("after consume: got %d, want 2048", w.Available())
	}

	// 3000 > 2048 remaining, but not larger than the growth ceiling, so
	// Consume blocks up to ConsumeTimeout. Give it a tight deadline so the
	// test is fast; we only need to prove it errors on sustained exhaustion.
	tctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if err := w.Consume(tctx, 3000); !errors.Is(err, ErrCreditExhausted) {
		t.Errorf("sustained overconsume: %v, want ErrCreditExhausted", err)
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

// Regression test at the connection level: when receive flow is
// sustained, grants must continue to emit — they must not pin at zero once
// recvCredit has aggregated to maxSize.
func TestConnWindow_SustainedGrants(t *testing.T) {
	w := NewConnWindow(DefaultConnCredit)

	// Drive enough receive volume that a receiver which never decremented
	// recvCredit would have grants decay to 0 after the first few rounds.
	// We expect grants to keep flowing as long as data keeps arriving.
	total := int64(0)
	for i := 0; i < 20; i++ {
		g := w.ReceiverConsume(DefaultConnCredit / 2) // 512 KB per step
		total += g
	}
	if total == 0 {
		t.Fatal("no grants emitted over 20 large-receive iterations")
	}
}

// Regression test for the TIMED (4th) grant trigger.
//
// Scenario that motivated it: a gossip stream with InitialCredit = 4 MB
// processing 70 KB payloads at ~10 s gossip intervals. The other three
// triggers have size floors that don't fire for small payloads on a big
// window:
//   - THRESHOLD: sinceLastGrant >= 25% × 4 MB = 1 MB → needs ~15 payloads
//   - EAGER: single payload >= 50% × 1 MB = 512 KB → never fires at 70 KB
//   - WATERMARK: recvCredit < 25% × 4 MB = 1 MB → needs ~42 payloads consumed
//
// With the TIMED trigger (GrantMaxInterval = 1 s), a grant fires at most
// 1 s after any consumed byte regardless of payload size or window size.
// The sender can never stall for longer than GrantMaxInterval purely due
// to small-payload/large-window mismatch.
func TestStreamWindow_TimedTrigger_LargeWindow_SmallPayload(t *testing.T) {
	const (
		bigWindow    = 4 * 1024 * 1024 // 4 MB — production gossip config
		smallPayload = 70 * 1024       // 70 KB — observed gossip exchange size
		payloadsFed  = 3               // <15 needed for THRESHOLD, <42 for WATERMARK
		waitForTimed = GrantMaxInterval + 100*time.Millisecond
	)

	w := NewStreamWindow(bigWindow)

	// Feed a few payloads — none of THRESHOLD / EAGER / WATERMARK should fire.
	// Small payloads on a big window: none of the size-based triggers hit.
	for i := 0; i < payloadsFed; i++ {
		if grant := w.ReceiverConsume(smallPayload); grant != 0 {
			t.Fatalf("payload %d: expected no immediate grant (size-based triggers shouldn't fire), got %d", i, grant)
		}
	}

	// Confirm Stats show zero grants via any trigger so far.
	stats := w.Stats()
	if g := stats.ThresholdGrants + stats.EagerGrants + stats.WatermarkGrants + stats.TimedGrants; g != 0 {
		t.Fatalf("expected 0 grants before GrantMaxInterval elapsed, got threshold=%d eager=%d watermark=%d timed=%d",
			stats.ThresholdGrants, stats.EagerGrants, stats.WatermarkGrants, stats.TimedGrants)
	}

	// Wait past GrantMaxInterval. The next ReceiverConsume should fire
	// the TIMED trigger because sinceLastGrant > 0 AND the wall-clock
	// gap has crossed the threshold.
	time.Sleep(waitForTimed)

	grant := w.ReceiverConsume(smallPayload)
	if grant == 0 {
		t.Fatal("TIMED trigger did not fire after GrantMaxInterval elapsed with data consumed")
	}

	stats = w.Stats()
	if stats.TimedGrants != 1 {
		t.Errorf("TimedGrants counter: got %d, want 1", stats.TimedGrants)
	}
	// Other counters should remain zero — this scenario exclusively
	// exercises the TIMED path.
	if stats.ThresholdGrants != 0 || stats.EagerGrants != 0 || stats.WatermarkGrants != 0 {
		t.Errorf("unexpected non-TIMED grant: threshold=%d eager=%d watermark=%d",
			stats.ThresholdGrants, stats.EagerGrants, stats.WatermarkGrants)
	}
}

// Negative test: TIMED must NOT fire when no bytes have been consumed
// since the last grant, even if GrantMaxInterval has elapsed. This
// prevents an empty-stream from emitting redundant no-op grants
// forever in the background.
func TestStreamWindow_TimedTrigger_NoConsumeNoGrant(t *testing.T) {
	w := NewStreamWindow(DefaultStreamCredit)

	// Wait past the interval without any ReceiverConsume calls.
	time.Sleep(GrantMaxInterval + 100*time.Millisecond)

	// A zero-byte consume must not trigger anything.
	if grant := w.ReceiverConsume(0); grant != 0 {
		t.Errorf("zero-byte consume fired a grant: %d", grant)
	}
	if g := w.Stats().TimedGrants; g != 0 {
		t.Errorf("TimedGrants counter: got %d, want 0 (no consumption happened)", g)
	}
}

// TIMED trigger on ConnWindow mirrors the stream-level behaviour. Same
// rationale: small per-stream payloads aggregating at the conn level can
// still leave the conn-level sinceLastGrant below the THRESHOLD floor
// under bursty-but-low-volume traffic.
func TestConnWindow_TimedTrigger_Fires(t *testing.T) {
	w := NewConnWindow(DefaultConnCredit)

	// Feed small payloads — DefaultConnCredit is 4 MB, threshold = 1 MB,
	// so 3 × 70 KB (210 KB total) stays well under all size-based triggers.
	for i := 0; i < 3; i++ {
		if grant := w.ReceiverConsume(70 * 1024); grant != 0 {
			t.Fatalf("payload %d: unexpected immediate grant %d", i, grant)
		}
	}

	// Wait past GrantMaxInterval.
	time.Sleep(GrantMaxInterval + 100*time.Millisecond)

	grant := w.ReceiverConsume(70 * 1024)
	if grant == 0 {
		t.Fatal("conn-level TIMED trigger did not fire")
	}
	if g := w.Stats().TimedGrants; g != 1 {
		t.Errorf("ConnWindow TimedGrants: got %d, want 1", g)
	}
}

// TestStreamWindow_ReleaseUnsent: bytes Consume acquired that never reached the
// wire go back to the window through ReleaseUnsent alone. The peer never received
// them, so no grant (WINDOW_UPDATE or the CompositeACK piggyback) will ever return
// them; noiseStream.Send calls ReleaseUnsent when a step after the stream
// window's Consume fails (the stream left while Send waited, the connection
// window's Consume, fragmentation, the frame send), and without it each failed Send would shrink the stream's window
// by its payload for good.
func TestStreamWindow_ReleaseUnsent(t *testing.T) {
	w := NewStreamWindow(testCredit)
	ctx := context.Background()

	if err := w.Consume(ctx, testCredit/2); err != nil {
		t.Fatalf("consume half: %v", err)
	}
	if got := w.Available(); got != testCredit/2 {
		t.Errorf("after consume half: avail=%d, want %d", got, testCredit/2)
	}

	w.ReleaseUnsent(testCredit / 2)
	if got := w.Available(); got != testCredit {
		t.Errorf("after ReleaseUnsent: avail=%d, want %d (full)", got, testCredit)
	}

	// Releasing more than is outstanding caps at outstanding.
	w.ReleaseUnsent(testCredit) // double-release attempt
	if got := w.Available(); got != testCredit {
		t.Errorf("over-release: avail=%d, want %d (still capped)", got, testCredit)
	}

	// Re-consume the freed credit to confirm the semaphore actually got
	// the bytes back (not just bookkeeping).
	if err := w.Consume(ctx, testCredit/2); err != nil {
		t.Fatalf("consume after release: %v", err)
	}
}

// TestStreamWindow_FailedSendCreditLeak: twenty 76 KiB Consumes on a 1 MiB
// window, each followed by a failed send that no grant answers (no ApplyUpdate)
// and by ReleaseUnsent as Send's failure paths call it, leave the window full
// after every cycle; thirteen such Consumes left charged would drain it below
// one payload (the next test).
func TestStreamWindow_FailedSendCreditLeak(t *testing.T) {
	const (
		initialCredit = 1 * 1024 * 1024 // 1 MiB
		payload       = 76 * 1024       // 76 KiB: thirteen fit in the window, fourteen do not
	)
	w := NewStreamWindow(initialCredit)
	ctx := context.Background()

	// 20 cycles of "send failed after Consume": more than the window holds
	// if a cycle's bytes stayed charged.
	for i := 0; i < 20; i++ {
		if err := w.Consume(ctx, payload); err != nil {
			t.Fatalf("cycle %d Consume: %v", i, err)
		}
		// A step after Consume refused the bytes (the connection window's
		// Consume, or sendSingleFrame): give back what was acquired and not sent.
		w.ReleaseUnsent(payload)

		if avail := w.Available(); avail != initialCredit {
			t.Fatalf("cycle %d: credit leaked. avail=%d, want %d (full)",
				i, avail, initialCredit)
		}
	}
}

// TestStreamWindow_FailedSendWithoutFix_Demonstrates_The_Leak shows what
// ReleaseUnsent prevents: after thirteen 76 KiB Consumes that nothing releases
// or grants back, a 1 MiB window holds less than one payload (36 KiB), so the
// next Consume of that size waits ConsumeTimeout for a grant that will never
// come and fails with ErrCreditExhausted. It exercises the window alone and
// calls no Send.
func TestStreamWindow_FailedSendWithoutFix_Demonstrates_The_Leak(t *testing.T) {
	const (
		initialCredit = 1 * 1024 * 1024
		payload       = 76 * 1024
	)
	w := NewStreamWindow(initialCredit)
	ctx := context.Background()

	for i := 0; i < 13; i++ {
		if err := w.Consume(ctx, payload); err != nil {
			t.Fatalf("cycle %d Consume: %v (window already drained — leak too fast?)", i, err)
		}
		// No ReleaseUnsent: the bytes stay charged.
	}

	avail := w.Available()
	if avail >= payload {
		t.Errorf("expected window drained below payload size; got avail=%d (>= %d)",
			avail, payload)
	}
	t.Logf("after 13 unreleased Consumes: avail=%d", avail)
}
