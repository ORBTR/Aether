/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package adapter

import (
	"errors"
	"testing"

	"github.com/ORBTR/aether"
)

// An empty class set, a duplicate class, and an unknown class must all fail
// closed. The unknown-class case is load-bearing: MaxAppMessageBudget resolves an
// unknown class to the ClassSTREAM budget (65469), which exceeds the ClassRAW
// frame, so if the constructor did not gate eligibility a caller could obtain a
// budget larger than the frame it actually rides. This is the fail-open that
// FrameBudgetEvidence exists to close.
func TestNewFrameBudgetEvidenceFailsClosed(t *testing.T) {
	if _, err := NewFrameBudgetEvidence(); !errors.Is(err, ErrFrameBudgetEvidence) {
		t.Errorf("empty class set: err=%v, want ErrFrameBudgetEvidence", err)
	}
	if _, err := NewFrameBudgetEvidence(aether.ClassRAW, aether.ClassRAW); !errors.Is(err, ErrFrameBudgetEvidence) {
		t.Errorf("duplicate class: err=%v, want ErrFrameBudgetEvidence", err)
	}
	unknown := aether.TransportClass(250) // outside RAW/STREAM/PROXY
	if _, err := NewFrameBudgetEvidence(unknown); !errors.Is(err, ErrFrameBudgetEvidence) {
		t.Errorf("unknown class: err=%v, want ErrFrameBudgetEvidence (MaxAppMessageBudget would fail open to STREAM)", err)
	}
	// A valid class mixed with an unknown one still fails closed — one bad class
	// rejects the whole evidence.
	if _, err := NewFrameBudgetEvidence(aether.ClassRAW, unknown); !errors.Is(err, ErrFrameBudgetEvidence) {
		t.Errorf("valid+unknown: err=%v, want ErrFrameBudgetEvidence", err)
	}
}

// Each single-class evidence carries exactly that class's post-Aether budget, and
// those budgets are the pinned RAW/PROXY/STREAM values (frame size minus the
// 67-byte full frame header and AEAD tag). If a frame size or the overhead moves, these
// fail here.
func TestFrameBudgetEvidencePerClassBudget(t *testing.T) {
	for _, tc := range []struct {
		class aether.TransportClass
		want  int
	}{
		{aether.ClassRAW, 1333},
		{aether.ClassPROXY, 32701},
		{aether.ClassSTREAM, 65469},
	} {
		e, err := NewFrameBudgetEvidence(tc.class)
		if err != nil {
			t.Fatalf("class %v: %v", tc.class, err)
		}
		if got := e.Minimum(); got != tc.want {
			t.Errorf("class %v: Minimum()=%d, want %d", tc.class, got, tc.want)
		}
		if got, ok := e.Budget(tc.class); !ok || got != tc.want {
			t.Errorf("class %v: Budget()=%d,%v, want %d,true", tc.class, got, ok, tc.want)
		}
	}
}

// Over an eligible set, Minimum is the smallest class budget — ClassRAW when the
// set includes it — so a bounded encoder that uses Minimum() fits every eligible
// frame, including the smallest. This is the whole point of carrying the set
// rather than one class: a stream that may fail over between classes is bounded
// by the tightest of them.
func TestFrameBudgetEvidenceMinimumIsSmallest(t *testing.T) {
	all, err := NewFrameBudgetEvidence(aether.ClassRAW, aether.ClassPROXY, aether.ClassSTREAM)
	if err != nil {
		t.Fatal(err)
	}
	if got := all.Minimum(); got != 1333 {
		t.Errorf("Minimum over {RAW,PROXY,STREAM}=%d, want 1333 (RAW is smallest)", got)
	}
	// Order of arguments must not change the minimum.
	reordered, err := NewFrameBudgetEvidence(aether.ClassSTREAM, aether.ClassRAW, aether.ClassPROXY)
	if err != nil {
		t.Fatal(err)
	}
	if got := reordered.Minimum(); got != 1333 {
		t.Errorf("Minimum is order-dependent: %d, want 1333", got)
	}
	// A set without RAW takes the next-smallest (PROXY).
	noRaw, err := NewFrameBudgetEvidence(aether.ClassPROXY, aether.ClassSTREAM)
	if err != nil {
		t.Fatal(err)
	}
	if got := noRaw.Minimum(); got != 32701 {
		t.Errorf("Minimum over {PROXY,STREAM}=%d, want 32701", got)
	}
}

// Budget reports presence, and Classes lists exactly the eligible set in
// ascending order. A class not in the evidence is absent, not defaulted.
func TestFrameBudgetEvidencePresenceAndClasses(t *testing.T) {
	e, err := NewFrameBudgetEvidence(aether.ClassSTREAM, aether.ClassRAW)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := e.Budget(aether.ClassPROXY); ok {
		t.Error("ClassPROXY not in the set must report absent, not a defaulted budget")
	}
	got := e.Classes()
	if len(got) != 2 || got[0] != aether.ClassRAW || got[1] != aether.ClassSTREAM {
		t.Errorf("Classes()=%v, want [RAW STREAM] ascending", got)
	}
}
