/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package adapter

import (
	"errors"
	"fmt"
	"sort"

	"github.com/ORBTR/aether"
)

// ErrFrameBudgetEvidence is returned by NewFrameBudgetEvidence for an empty
// class set, a duplicate class, or a class outside the defined transport set. A
// bounded-message encoder consumes only a constructed FrameBudgetEvidence, so
// this sentinel makes an unqualified integer, a single-class literal, or an
// unknown class unrepresentable as a budget rather than silently admitted.
var ErrFrameBudgetEvidence = errors.New("aether/adapter: invalid frame-budget evidence")

// FrameBudgetEvidence is a validated, transport-class-qualified statement of the
// application-message budgets a message may ride. It carries every eligible
// transport class, each class's already-post-Aether application budget from
// MaxAppMessageBudget (the class frame size minus the Aether header and Noise
// AEAD tag), and their frozen minimum. A bounded encoder consumes Minimum() so a
// message fits the SMALLEST eligible frame without reaching SplitMessage.
//
// The only constructor validates the eligible class set, so a consumer cannot
// fabricate a budget from a raw integer or a class-confused value: an unknown
// class is rejected here rather than resolved to the ClassSTREAM budget the way
// MaxAppMessageBudget and DefaultsForClass do (they fail open to STREAM, which is
// larger than the ClassRAW frame and would overflow it). The carried budgets are
// already post-Aether, so a consumer must not subtract the Aether header/AEAD
// overhead a second time.
type FrameBudgetEvidence struct {
	budgets map[aether.TransportClass]int
	min     int
}

// isKnownClass reports whether c is one of the defined transport classes. It is
// the eligible-set gate FrameBudgetEvidence needs before trusting a budget:
// MaxAppMessageBudget and DefaultsForClass both resolve an unknown class to the
// ClassSTREAM budget, so eligibility is checked here, not there.
func isKnownClass(c aether.TransportClass) bool {
	switch c {
	case aether.ClassRAW, aether.ClassSTREAM, aether.ClassPROXY:
		return true
	default:
		return false
	}
}

// NewFrameBudgetEvidence constructs evidence over the eligible classes. It fails
// closed on an empty set, a duplicate class, or an unknown class, and computes
// each class's post-Aether application budget via MaxAppMessageBudget and their
// minimum. The minimum is the value a bounded encoder must use so a message fits
// every eligible frame.
func NewFrameBudgetEvidence(classes ...aether.TransportClass) (FrameBudgetEvidence, error) {
	if len(classes) == 0 {
		return FrameBudgetEvidence{}, fmt.Errorf("%w: no eligible classes", ErrFrameBudgetEvidence)
	}
	budgets := make(map[aether.TransportClass]int, len(classes))
	min := -1
	for _, c := range classes {
		if !isKnownClass(c) {
			return FrameBudgetEvidence{}, fmt.Errorf("%w: unknown class %v", ErrFrameBudgetEvidence, c)
		}
		if _, dup := budgets[c]; dup {
			return FrameBudgetEvidence{}, fmt.Errorf("%w: duplicate class %v", ErrFrameBudgetEvidence, c)
		}
		b := MaxAppMessageBudget(c)
		budgets[c] = b
		if min == -1 || b < min {
			min = b
		}
	}
	return FrameBudgetEvidence{budgets: budgets, min: min}, nil
}

// Minimum returns the smallest eligible post-Aether application budget. A bounded
// encoder uses exactly this so every emitted message fits the smallest eligible
// frame; it is frozen at construction.
func (e FrameBudgetEvidence) Minimum() int { return e.min }

// Budget returns the post-Aether application budget for one class and whether
// that class is present in the evidence.
func (e FrameBudgetEvidence) Budget(c aether.TransportClass) (int, bool) {
	b, ok := e.budgets[c]
	return b, ok
}

// Classes returns the eligible transport classes in ascending order. It is empty
// for a zero-value FrameBudgetEvidence, which no constructor produces and whose
// Minimum of zero a bounded encoder rejects.
func (e FrameBudgetEvidence) Classes() []aether.TransportClass {
	out := make([]aether.TransportClass, 0, len(e.budgets))
	for c := range e.budgets {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
