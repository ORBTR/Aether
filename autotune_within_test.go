/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package aether

import (
	"testing"
	"time"

	"github.com/ORBTR/aether/flow"
)

// TestAutoTuneWindowWithin_GrowthStopsAtTheCeiling: two windows in the same
// state, three quarters of their credit outstanding with an RTT known, where
// the suggestion is to grow. AutoTuneWindow grows one; AutoTuneWindowWithin,
// given the window's own credit as the ceiling, leaves the other at that
// credit, and given a ceiling between the two, grows it to the ceiling only.
func TestAutoTuneWindowWithin_GrowthStopsAtTheCeiling(t *testing.T) {
	const credit = 64 * 1024
	fresh := func() *flow.StreamWindow {
		w := flow.NewStreamWindowWithCap(credit, 0)
		if !w.TryConsume(credit * 3 / 4) {
			t.Fatal("premise wrong: three quarters of the credit not admitted")
		}
		return w
	}

	free := fresh()
	if res := AutoTuneWindow(free, 50*time.Millisecond); res.Action != "grow" || free.CurrentWindow() <= credit {
		t.Fatalf("premise wrong: the unbounded step did %q and left the window at %d", res.Action, free.CurrentWindow())
	}

	held := fresh()
	if res := AutoTuneWindowWithin(held, 50*time.Millisecond, credit); res.Applied != 0 || held.CurrentWindow() != credit {
		t.Fatalf("at a ceiling of its own credit the step did %q by %d and left the window at %d, want %d",
			res.Action, res.Applied, held.CurrentWindow(), credit)
	}

	part := fresh()
	const ceiling = credit + 4096
	AutoTuneWindowWithin(part, 50*time.Millisecond, ceiling)
	if got := part.CurrentWindow(); got != ceiling {
		t.Fatalf("with a ceiling %d above the credit the window went to %d", ceiling, got)
	}
}
