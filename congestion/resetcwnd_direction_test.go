/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package congestion

import (
	"testing"
	"time"
)

// Characterisation of ResetCWND's DIRECTION, for both controllers.
//
// MEASURED IN PRODUCTION (the owner's 2,346,166-line / 8-node / 90-minute
// capture): 84 `cwnd=X→Y` transitions — RAISED 0, LOWERED 83, UNCHANGED 1.
// Largest cuts 10485760→14000 (748×), 10091378→14000 (720×), 9300927→14000
// (664×). A function whose doc says it "restores" has never once restored on
// this fleet; it applies a 600–750× cut every time it fires.
//
// WHY THAT HAPPENS: ResetCWND assigns initialCWND unconditionally. Its only
// non-test caller is the STALL-DETECT false-positive branch, which fires on any
// session that went a threshold without progress and still answers a Ping —
// including healthy high-throughput ones that never collapsed. There is nothing
// to "restore" on those, and the assignment is a pure reduction.
//
// ⚠ THESE TESTS ASSERT THE DEFECT, NOT THE DESIRED BEHAVIOUR. They pass today.
// They exist so the fix has a "before" in code rather than only in a log sample,
// and they are deliberately PLACEMENT-INDEPENDENT: they characterise the callee's
// direction, which is a fact whether the eventual remedy guards the callee or
// stops the caller from invoking it on a healthy window.
//
// 🛑 WHEN THESE FAIL, THAT IS THE FIX LANDING. Replace each assertion with its
// mirror — a healthy window must be left UNCHANGED, and a genuinely collapsed one
// must still be RAISED to initialCWND (that raise is the production acceptance
// check: one `cwnd=X→Y` with Y>X, against a baseline of 84 samples with zero).
// Do not simply delete the file: the collapsed-window case is the behaviour the
// function is actually for, and it needs to keep working.

// grow drives a controller up to a window well above initialCWND using only its
// public ACK surface, so the "healthy" precondition is produced the way real
// traffic produces it rather than by poking fields.
func growAboveInitial(t *testing.T, c Controller) int64 {
	t.Helper()
	for i := 0; i < 4000; i++ {
		c.OnAck(64*1024, 20*time.Millisecond)
		if c.CWND() > int64(initialCWND)*4 {
			break
		}
	}
	got := c.CWND()
	if got <= int64(initialCWND) {
		t.Fatalf("precondition not met: cwnd %d did not grow above initialCWND %d — "+
			"these tests characterise what ResetCWND does to a HEALTHY window and "+
			"cannot say anything if the window never became healthy", got, initialCWND)
	}
	return got
}

// TestCUBICResetCWND_LowersAHealthyWindow is the CUBIC half of the finding.
func TestCUBICResetCWND_LowersAHealthyWindow(t *testing.T) {
	c := NewCUBICController()
	before := growAboveInitial(t, c)

	c.ResetCWND()
	after := c.CWND()

	if after >= before {
		t.Errorf("ResetCWND did NOT lower a healthy window (%d → %d). If a guard was "+
			"added, THIS IS THE FIX — replace this assertion with its mirror (healthy "+
			"window UNCHANGED) and add one proving a COLLAPSED window is still raised "+
			"to initialCWND", before, after)
		return
	}
	if after != int64(initialCWND) {
		t.Errorf("expected the unconditional assignment to land exactly on initialCWND "+
			"%d, got %d — the assignment changed and the production reading (every cut "+
			"terminating at 14000) needs re-measuring", initialCWND, after)
	}
	t.Logf("CUBIC: cwnd %d → %d (%.0f× reduction) — matches the production signature",
		before, after, float64(before)/float64(after))
}

// TestBBRResetCWND_IsStateIndependent is the BBR half, and it characterises the
// defect in the form BBR actually takes — which is NOT the form CUBIC takes.
//
// 🙋 A CORRECTION TO AN EARLIER CLAIM OF MINE, recorded here because the code is
// where it will be re-read: I reported that BBR "assigns initialCWND, no guard",
// implying a 14000 outcome like CUBIC's. MEASURED, that is wrong. BBR's ResetCWND
// does assign initialCWND — and then calls recomputeOutputs(), which immediately
// recomputes cwnd from btlBwResetDefault × rtPropResetDefault. The effective
// post-reset window is ~314571, i.e. ~22× LARGER than CUBIC's. Reading the
// assignment without the recompute two lines later gets the magnitude wrong.
//
// So BBR is not "CUBIC but worse" on window size. It is worse on a DIFFERENT axis:
// it discards the measured path model (btlBw, rtProp) that its window is derived
// from, and lands on a fixed default regardless of what the path was.
//
// That is what this test pins, and it needs no growth: drive two controllers to
// DIFFERENT states and assert ResetCWND collapses both to the SAME window. A reset
// that ignores prior state is exactly a reset that discards measurement.
func TestBBRResetCWND_IsStateIndependent(t *testing.T) {
	quiet := NewBBRController()

	busy := NewBBRController()
	for i := 0; i < 2000; i++ {
		busy.OnAck(64*1024, 20*time.Millisecond)
	}
	if busy.CWND() == quiet.CWND() {
		t.Fatalf("precondition not met: the two controllers are in the same state "+
			"(both cwnd=%d), so this test cannot show state-independence", busy.CWND())
	}

	quiet.ResetCWND()
	busy.ResetCWND()

	if quiet.CWND() != busy.CWND() {
		t.Errorf("BBR ResetCWND is now STATE-DEPENDENT (fresh=%d, exercised=%d). If a "+
			"guard was added that preserves a measured path, THIS IS THE FIX — replace "+
			"this assertion with one bounding what it preserves", quiet.CWND(), busy.CWND())
		return
	}
	t.Logf("BBR: two different path states both reset to cwnd=%d — the measured "+
		"btlBw/rtProp are discarded and the window is recomputed from defaults",
		busy.CWND())
}

// TestResetCWND_PostResetWindowDiffersPerImplementation is the POSITIVE CONTROL
// that makes the pair above a completeness claim rather than two observations —
// and it pins the per-implementation values so a partial fix is visible.
//
// The defect lives behind an interface with two implementations, so a fix applied
// to one is silently partial. This asserts each one's ACTUAL post-reset window
// rather than assuming both land on initialCWND — which is the mistake that
// produced the correction documented above.
func TestResetCWND_PostResetWindowDiffersPerImplementation(t *testing.T) {
	cubic := NewCUBICController()
	cubic.ResetCWND()
	if got := cubic.CWND(); got != int64(initialCWND) {
		t.Errorf("CUBIC post-reset cwnd = %d, want initialCWND %d — CUBIC assigns it "+
			"directly with no recompute, so a change here means the assignment itself "+
			"changed", got, initialCWND)
	}

	bbr := NewBBRController()
	bbr.ResetCWND()
	bbrAfter := bbr.CWND()
	if bbrAfter == int64(initialCWND) {
		t.Errorf("BBR post-reset cwnd = initialCWND (%d). That contradicts the measured "+
			"behaviour: recomputeOutputs() overwrites the assignment from btlBw/rtProp "+
			"defaults. If recomputeOutputs no longer runs, BBR's reset semantics "+
			"changed and this file's rationale needs re-measuring", initialCWND)
	}
	if bbrAfter <= 0 {
		t.Errorf("BBR post-reset cwnd = %d, which is not a usable window", bbrAfter)
	}

	t.Logf("post-reset windows differ by implementation: CUBIC=%d BBR=%d (%.0f× apart) "+
		"— a CUBIC-only fix leaves BBR resetting to a fixed default that ignores the "+
		"measured path", cubic.CWND(), bbrAfter, float64(bbrAfter)/float64(cubic.CWND()))
}
