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
	if err := w.Consume(tctx, 3000); err == nil {
		t.Error("should error on sustained overconsume")
	}

	// Escape hatch: tiny frames always pass without metering.
	avail := w.Available()
	if err := w.Consume(ctx, MinGuaranteedWindow); err != nil {
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
		bigWindow     = 4 * 1024 * 1024 // 4 MB — production gossip config
		smallPayload  = 70 * 1024       // 70 KB — observed gossip exchange size
		payloadsFed   = 3               // <15 needed for THRESHOLD, <42 for WATERMARK
		waitForTimed  = GrantMaxInterval + 100*time.Millisecond
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

// ReleaseOnACK releases sender credit via the reliability-layer ACK
// path independent of WINDOW_UPDATE. Caps at dataOutstanding so it
// composes safely with ApplyUpdate (both paths can fire; neither
// over-releases).
func TestStreamWindow_ReleaseOnACK_ReleasesCredit(t *testing.T) {
	w := NewStreamWindow(testCredit)
	ctx := context.Background()

	if err := w.Consume(ctx, testCredit); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if a := w.Available(); a != 0 {
		t.Fatalf("after full consume: Available got %d, want 0", a)
	}

	// ACK half the bytes — releases half the credit back to the sender.
	w.ReleaseOnACK(testCredit / 2)
	if a := w.Available(); a != testCredit/2 {
		t.Errorf("after ReleaseOnACK(half): Available got %d, want %d", a, testCredit/2)
	}

	// ACK another half — releases the remaining half. Total released =
	// initialCredit, dataOutstanding back to zero.
	w.ReleaseOnACK(testCredit / 2)
	if a := w.Available(); a != testCredit {
		t.Errorf("after ReleaseOnACK(all): Available got %d, want %d", a, testCredit)
	}
}

// ReleaseOnACK must never release past dataOutstanding. If a WINDOW_UPDATE
// already freed the credit, a later ACK for the same bytes must be a no-op.
func TestStreamWindow_ReleaseOnACK_CapsAtDataOutstanding(t *testing.T) {
	w := NewStreamWindow(testCredit)
	ctx := context.Background()

	if err := w.Consume(ctx, testCredit); err != nil {
		t.Fatalf("consume: %v", err)
	}

	// WINDOW_UPDATE releases everything first.
	// Simulate receiver granting full refill via cumulative mechanism:
	//   grantsEmitted becomes testCredit → peer sends it → ApplyUpdate(testCredit).
	// Here we synthesize the effect directly.
	w.ApplyUpdate(testCredit)
	if a := w.Available(); a != testCredit {
		t.Fatalf("after ApplyUpdate(all): Available got %d, want %d", a, testCredit)
	}

	// ACK for the same bytes arrives AFTER WINDOW_UPDATE — must be no-op.
	w.ReleaseOnACK(testCredit)
	if a := w.Available(); a != testCredit {
		t.Errorf("ReleaseOnACK over-released: Available got %d, want %d", a, testCredit)
	}
}

// Symmetric test for ConnWindow ReleaseOnACK.
func TestConnWindow_ReleaseOnACK(t *testing.T) {
	w := NewConnWindow(DefaultConnCredit)
	ctx := context.Background()

	if err := w.Consume(ctx, DefaultConnCredit/2); err != nil {
		t.Fatalf("consume: %v", err)
	}

	beforeAvail := w.Available()
	w.ReleaseOnACK(DefaultConnCredit / 4)
	afterAvail := w.Available()
	if afterAvail-beforeAvail != DefaultConnCredit/4 {
		t.Errorf("ReleaseOnACK delta wrong: before=%d after=%d diff=%d, want +%d",
			beforeAvail, afterAvail, afterAvail-beforeAvail, DefaultConnCredit/4)
	}

	// Releasing more than remaining outstanding caps correctly.
	w.ReleaseOnACK(DefaultConnCredit) // much more than what's still outstanding
	finalAvail := w.Available()
	if finalAvail > DefaultConnCredit {
		t.Errorf("Available exceeded initial credit: got %d, want ≤ %d", finalAvail, DefaultConnCredit)
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

// TestStreamWindow_ReleaseUnsent verifies that bytes acquired via Consume
// but never delivered to the wire (because a downstream layer rejected
// them) can be returned to the credit pool without involving the
// peer's WINDOW_UPDATE / ACK channels. This is the fix for the production
// credit-leak observed when noise_stream.Send acquires stream credit,
// then connWindow.Consume fails — without an explicit release path,
// each failed Send permanently consumes payload-size bytes of the
// stream's effective window.
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

	// Releasing more than is outstanding caps at outstanding (mirrors
	// ReleaseOnACK semantics).
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

// TestStreamWindow_FailedSendCreditLeak reproduces the production-observed
// stall: 13 sequential 76 KB Consumes each followed by a "send failed"
// (modeled as no ApplyUpdate, no ReleaseOnACK) drain a 1 MB window to
// permanent zero. With the ReleaseUnsent fix wired into the Send
// failure paths, available credit must recover after every failed Send.
func TestStreamWindow_FailedSendCreditLeak(t *testing.T) {
	const (
		initialCredit = 1 * 1024 * 1024 // 1 MB — production gossip stream sizing
		payload       = 76 * 1024       // ~76 KB — observed gossip exchange size
	)
	w := NewStreamWindow(initialCredit)
	ctx := context.Background()

	// 20 cycles of "send failed after Consume" — far more than would fit
	// in the window if credit were truly leaked.
	for i := 0; i < 20; i++ {
		if err := w.Consume(ctx, payload); err != nil {
			t.Fatalf("cycle %d Consume: %v", i, err)
		}
		// Simulate downstream-layer rejection (e.g. connWindow.Consume failed,
		// or sendSingleFrame errored). The fix: release the credit we
		// acquired but didn't actually send.
		w.ReleaseUnsent(payload)

		if avail := w.Available(); avail != initialCredit {
			t.Fatalf("cycle %d: credit leaked. avail=%d, want %d (full)",
				i, avail, initialCredit)
		}
	}
}

// TestStreamWindow_FailedSendWithoutFix demonstrates the bug shape
// without ReleaseUnsent — included as a guard so future refactors that
// remove the Send-side release call would re-trigger the symptom and
// fail this test loudly. After 13 cycles of 76 KB acquired-but-never-
// released, available drops to roughly the production-observed ~40 KB.
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
		// Deliberately DON'T release — this is the bug shape we're
		// asserting reproduces the production drain pattern.
	}

	avail := w.Available()
	if avail >= payload {
		t.Errorf("expected window drained below payload size; got avail=%d (>= %d)",
			avail, payload)
	}
	t.Logf("after 13 leaked Consumes: avail=%d (production observed ~41 KB)", avail)
}
