/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"testing"

	"github.com/ORBTR/aether"
)

// The three class budgets are the class frame size minus the fixed 66-byte
// per-frame overhead (Aether header 50 + Noise AEAD tag 16) that MSSToMaxPayload
// owns. A caller binds each encoded message to these so a valid message never
// fragments; if any class frame size, the Aether header, or the AEAD tag width
// changes, these pins fail here before a consumer ships a budget that no longer
// fits one frame.
func TestMaxAppMessageBudgetPinsPerClass(t *testing.T) {
	for _, tc := range []struct {
		class aether.TransportClass
		want  int
	}{
		{aether.ClassRAW, 1334},     // 1400 - 66
		{aether.ClassPROXY, 32702},  // 32768 - 66
		{aether.ClassSTREAM, 65470}, // 65536 - 66
	} {
		if got := MaxAppMessageBudget(tc.class); got != tc.want {
			t.Errorf("MaxAppMessageBudget(%v) = %d, want %d — a class frame size, the "+
				"Aether header, or the AEAD tag width moved and a caller would now emit "+
				"a message the frame cannot carry", tc.class, got, tc.want)
		}
	}
}

// An unrecognised class resolves to the ClassSTREAM budget, matching
// DefaultsForClass's default arm. This pins that COMPATIBILITY behaviour only —
// it is NOT a safety guarantee. The ClassSTREAM budget (65470) exceeds the
// ClassRAW frame (1334), so an unknown value that actually rides a ClassRAW
// path returns a budget the frame cannot carry; the accessor cannot make an
// unknown class safe. A caller must validate the eligible class set and take
// the ClassRAW minimum. This test asserts only that the fallback IS STREAM, not
// that the fallback is usable as transport eligibility.
func TestMaxAppMessageBudgetUnknownClassFallsToStream(t *testing.T) {
	unknown := aether.TransportClass(250) // outside the defined RAW/STREAM/PROXY set
	got := MaxAppMessageBudget(unknown)
	want := MaxAppMessageBudget(aether.ClassSTREAM)
	if got != want {
		t.Errorf("MaxAppMessageBudget(unknown class) = %d, want the ClassSTREAM "+
			"compatibility fallback %d — the default arm changed; this fallback is "+
			"NOT fail-closed and callers must validate class eligibility, not rely on it",
			got, want)
	}
}

// The ClassRAW budget is the smallest of the three and is the ceiling a caller
// compares against on the preferred path. It is an INCLUSIVE ceiling: a message
// of exactly the budget is admissible, one byte more is not. This pins the
// boundary so a caller's `encoded <= budget` comparison admits 1334 and rejects
// 1335.
func TestClassRAWBudgetBoundaryIsInclusive(t *testing.T) {
	budget := MaxAppMessageBudget(aether.ClassRAW)
	if budget != 1334 {
		t.Fatalf("ClassRAW budget = %d, want 1334", budget)
	}
	if !(1334 <= budget) {
		t.Error("a 1334-byte encoded message must be admissible at the ClassRAW budget")
	}
	if 1335 <= budget {
		t.Error("a 1335-byte encoded message must exceed the ClassRAW budget")
	}
}
