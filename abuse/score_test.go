/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package abuse

import (
	"testing"
	"time"
)

// TestRecord_BlacklistsAtThreshold pins the threshold ARITHMETIC with decay
// held negligible.
//
// The previous form used DefaultConfig() and asserted that the 4th weight-25
// record crosses the 100 threshold. That is true only in exact arithmetic:
// decayLocked applies exponential decay for ANY elapsed>0 between calls, so
// the running total lands fractionally UNDER 100 (measured: 99.99999996880838)
// and `score >= Threshold` is false. It passed only where the platform clock
// was coarse enough that consecutive Record() calls read the SAME instant
// (Windows' default timer granularity); on a nanosecond clock it fails every
// time. That is a property of the test, not a defect in Score — the real
// system needs a 5th trip with realistic spacing, as measured in #M-108.
//
// Fixed by removing decay ENTIRELY rather than loosening the assertion. Note
// that merely lengthening the half-life is NOT sufficient: decayLocked
// multiplies by pow2neg(elapsed/halfLife) for any elapsed>0, and that product
// is always < 1.0 in float64, so the total lands just under the threshold no
// matter how large the half-life (a 24h half-life still measured
// 99.99999999989109). The only decay-free path is decayLocked's own guard,
// `s.cfg.HalfLife <= 0`. New() coerces a non-positive HalfLife to the default,
// so the field is set afterwards — legitimate white-box access, this test is
// in package abuse. TestRecord_CrossesThresholdUnderRealSpacing covers the
// production-config behaviour separately.
func TestRecord_BlacklistsAtThreshold(t *testing.T) {
	cfg := DefaultConfig()
	s := New[string](cfg)
	// Disable decay outright so this test measures the threshold arithmetic and
	// nothing else. Must be set post-New: New() replaces a <=0 HalfLife with
	// DefaultHalfLife. TestScoreDecays covers the decay path itself.
	s.cfg.HalfLife = 0

	// 4 ACK-validation hits = 4 x 25 = 100 = Threshold.
	for i := 0; i < 3; i++ {
		_, exceeded := s.Record("peer-1", ReasonACKValidation)
		if exceeded {
			t.Fatalf("blacklisted too early at iteration %d", i)
		}
	}
	score, exceeded := s.Record("peer-1", ReasonACKValidation)
	if !exceeded {
		t.Fatalf("should have exceeded at score %v (threshold %v)", score, cfg.Threshold)
	}
	if !s.IsBlacklisted("peer-1") {
		t.Fatal("peer should be blacklisted")
	}
}

// TestRecord_CrossesThresholdUnderRealSpacing pins the PRODUCTION behaviour:
// with DefaultConfig() and genuine wall-clock spacing between records, decay
// means the 4th trip does not cross and a further trip is required. This is
// the behaviour measured in #M-108 ("4 trips = 88.5, no crossing") and it is
// what the fleet actually experiences; asserting it here stops the arithmetic
// test above from being mistaken for a claim about production timing.
//
// Deliberately asserts "crosses within a small bounded number of extra trips"
// rather than a hard count: the exact trip depends on real elapsed time, and
// pinning an exact number would re-introduce the platform dependence this
// pair exists to remove.
func TestRecord_CrossesThresholdUnderRealSpacing(t *testing.T) {
	s := New[string](DefaultConfig())

	crossedAt := -1
	for i := 1; i <= 8; i++ {
		if _, exceeded := s.Record("peer-1", ReasonACKValidation); exceeded {
			crossedAt = i
			break
		}
	}
	if crossedAt < 0 {
		t.Fatalf("never crossed threshold in 8 weight-25 records (score %v)", s.Current("peer-1"))
	}
	// 4 is the decay-free ideal; decay can only ever DELAY the crossing, so a
	// crossing before 4 would mean the weights or threshold changed.
	if crossedAt < 4 {
		t.Fatalf("crossed too early at trip %d — weight/threshold regression?", crossedAt)
	}
	if !s.IsBlacklisted("peer-1") {
		t.Fatal("peer should be blacklisted after crossing")
	}
}

func TestForgive_ClearsScoreAndBlacklist(t *testing.T) {
	s := New[string](DefaultConfig())
	for i := 0; i < 5; i++ {
		s.Record("peer-1", ReasonACKValidation)
	}
	if !s.IsBlacklisted("peer-1") {
		t.Fatal("peer should be blacklisted before Forgive")
	}
	s.Forgive("peer-1")
	if s.IsBlacklisted("peer-1") {
		t.Fatal("peer should be cleared after Forgive")
	}
	if cur := s.Current("peer-1"); cur != 0 {
		t.Errorf("score after Forgive: %v, want 0", cur)
	}
}

func TestScoreDecays(t *testing.T) {
	cfg := DefaultConfig()
	cfg.HalfLife = 10 * time.Millisecond
	s := New[string](cfg)
	s.Record("peer-1", ReasonACKValidation) // +25
	initial := s.Current("peer-1")
	if initial < 24 || initial > 26 {
		t.Fatalf("initial score out of bounds: %v", initial)
	}
	time.Sleep(30 * time.Millisecond) // ~3 half-lives → ~3.1
	after := s.Current("peer-1")
	if after >= initial/2 {
		t.Errorf("score did not decay enough: initial=%v after=%v", initial, after)
	}
}

func TestPrune_RemovesQuietPeers(t *testing.T) {
	cfg := DefaultConfig()
	cfg.HalfLife = 1 * time.Millisecond
	s := New[string](cfg)
	s.Record("peer-1", ReasonStreamRefused) // small, decays fast
	time.Sleep(50 * time.Millisecond)
	s.Prune(10 * time.Millisecond)
	if cur := s.Current("peer-1"); cur != 0 {
		t.Errorf("pruned peer should have 0 score, got %v", cur)
	}
}
