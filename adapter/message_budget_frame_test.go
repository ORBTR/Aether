/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"bytes"
	"testing"

	"github.com/ORBTR/aether"
)

// A payload sized at or below MaxAppMessageBudget for a class must NOT fragment
// when SplitMessage is given that same budget: MaxAppMessageBudget is exactly
// the largest message that fits one frame, and SplitMessage returns no
// fragments for a payload that fits. This pins the invariant a bounded-message
// caller relies on — if a payload at the budget ever fragmented, the caller
// would silently invoke SplitMessage, which is meant to be anomaly defence, not
// the routine path.
func TestPayloadAtBudgetDoesNotFragment(t *testing.T) {
	budget := MaxAppMessageBudget(aether.ClassRAW) // 1400 frame - 66 overhead = 1334
	for _, n := range []int{1, budget - 1, budget} {
		data := bytes.Repeat([]byte{'a'}, n)
		frags, err := SplitMessage(fxBinding(), 1, data, budget)
		if err != nil {
			t.Fatalf("SplitMessage(len=%d, budget=%d) errored: %v", n, budget, err)
		}
		if frags != nil {
			t.Errorf("SplitMessage(len=%d, budget=%d) produced %d fragments; a payload "+
				"<= budget must not fragment", n, budget, len(frags))
		}
	}
}

// One byte over the budget must cross into fragmentation. This pins that the
// budget is the exact inclusive single-frame ceiling, so a caller comparing
// encoded length `<= budget` has the real boundary and not an approximation.
func TestPayloadOverBudgetFragments(t *testing.T) {
	budget := MaxAppMessageBudget(aether.ClassRAW)
	data := bytes.Repeat([]byte{'a'}, budget+1)
	frags, err := SplitMessage(fxBinding(), 1, data, budget)
	if err != nil {
		t.Fatalf("SplitMessage(budget+1) errored: %v", err)
	}
	if len(frags) < 2 {
		t.Errorf("SplitMessage(len=%d, budget=%d) = %d fragments; budget+1 must fragment",
			budget+1, budget, len(frags))
	}
}

// A payload needing more than MaxFragments frames must FAIL CLOSED, never
// truncate. This is the ceiling that makes line-aligned delivery relying on
// transport fragmentation infeasible for a large message: a payload above
// MaxFragments frames' worth cannot be sent at all, so bounded chunking must
// live above the transport, not depend on SplitMessage to carve oversized data.
func TestOversizePayloadFailsClosed(t *testing.T) {
	budget := MaxAppMessageBudget(aether.ClassRAW)
	perFragment := budget - FragmentEnvelopeSize // data carried per fragment after its envelope
	data := bytes.Repeat([]byte{'a'}, MaxFragments*perFragment+1)
	if _, err := SplitMessage(fxBinding(), 1, data, budget); err == nil {
		t.Errorf("SplitMessage of a payload one byte past %d full fragments returned no "+
			"error; it must fail closed above MaxFragments", MaxFragments)
	}
}

// The ClassRAW budget must be strictly the smallest, and a payload sized to a
// larger class's budget must fragment on the RAW frame. This is a non-relative
// discriminator: unlike the same-budget tests above (which size their payload
// from the returned budget and so pass under any uniform budget), this fails if
// the accessor ever returns a wider class's budget for ClassRAW — the exact
// class-confusion a bounded caller on the preferred RAW path cannot survive.
func TestRAWBudgetIsStrictlySmallestAndForcesFragmentation(t *testing.T) {
	raw := MaxAppMessageBudget(aether.ClassRAW)
	proxy := MaxAppMessageBudget(aether.ClassPROXY)
	stream := MaxAppMessageBudget(aether.ClassSTREAM)
	if !(raw < proxy && proxy < stream) {
		t.Fatalf("class budgets not strictly ordered RAW<PROXY<STREAM: %d, %d, %d", raw, proxy, stream)
	}
	// A STREAM-budget-sized payload must fragment when carved to the RAW frame.
	data := bytes.Repeat([]byte{'a'}, stream)
	frags, err := SplitMessage(fxBinding(), 1, data, raw)
	if err != nil {
		t.Fatalf("SplitMessage(stream-sized, raw budget) errored: %v", err)
	}
	if frags == nil {
		t.Errorf("a STREAM-budget payload (%d) did not fragment on the RAW frame (budget "+
			"%d); RAW must be the smaller ceiling", stream, raw)
	}
}

// Byte parity across classes: fragmenting a payload and concatenating the
// fragment data portions in order must reproduce the exact input, identically
// for every transport class's budget. A class-dependent parity break would
// corrupt a reassembled stream on one mesh path but not another, which the
// bounded-chunk contract cannot tolerate because a stream may fail over between
// classes.
func TestFragmentByteParityAcrossClasses(t *testing.T) {
	// ~200 KB fragments on every class (RAW ~151 frames < MaxFragments, PROXY
	// and STREAM far fewer) without hitting the fail-closed ceiling on RAW.
	data := bytes.Repeat([]byte("orbtr-frame-parity-"), 10500)
	for _, class := range []aether.TransportClass{aether.ClassRAW, aether.ClassPROXY, aether.ClassSTREAM} {
		budget := MaxAppMessageBudget(class)
		frags, err := SplitMessage(fxBinding(), 1, data, budget)
		if err != nil {
			t.Fatalf("class %v: SplitMessage errored on a %d-byte payload: %v", class, len(data), err)
		}
		if frags == nil {
			t.Fatalf("class %v: expected fragmentation of a %d-byte payload, got none", class, len(data))
		}
		var got []byte
		for _, f := range frags {
			got = append(got, f[FragmentEnvelopeSize:]...)
		}
		if !bytes.Equal(got, data) {
			t.Errorf("class %v: reassembled bytes differ from input (%d vs %d)", class, len(got), len(data))
		}
	}
}
