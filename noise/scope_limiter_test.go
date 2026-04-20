//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package noise

import (
	"testing"
)

func testLimiterConfig() ScopeLimiterConfig {
	return ScopeLimiterConfig{
		Enabled:       true,
		MaxSessions:   3,
		MaxRelayRate:  100,
		MaxRelayPairs: 2,
	}
}

func TestTenantRelayLimiter_SessionLimit(t *testing.T) {
	limiter := NewTenantRelayLimiter(testLimiterConfig())

	// Under limit
	if err := limiter.CheckSessionLimit("scope-1", 2); err != nil {
		t.Errorf("Expected allow at 2/3 sessions, got: %v", err)
	}

	// At limit
	if err := limiter.CheckSessionLimit("scope-1", 3); err != ErrTenantSessionLimit {
		t.Errorf("Expected ErrTenantSessionLimit at 3/3, got: %v", err)
	}

	// Over limit
	if err := limiter.CheckSessionLimit("scope-1", 5); err != ErrTenantSessionLimit {
		t.Errorf("Expected ErrTenantSessionLimit at 5/3, got: %v", err)
	}

	// Different scope is independent
	if err := limiter.CheckSessionLimit("scope-2", 0); err != nil {
		t.Errorf("Expected allow for different scope, got: %v", err)
	}
}

func TestTenantRelayLimiter_SessionLimit_DedicatedMode(t *testing.T) {
	limiter := NewTenantRelayLimiter(testLimiterConfig())

	// Empty scope (dedicated mode) bypasses limits
	if err := limiter.CheckSessionLimit("", 9999); err != nil {
		t.Errorf("Dedicated mode should bypass session limit, got: %v", err)
	}
}

func TestTenantRelayLimiter_RelayRate(t *testing.T) {
	limiter := NewTenantRelayLimiter(testLimiterConfig())

	// Should allow up to MaxRelayRate packets (burst)
	for i := 0; i < 100; i++ {
		if err := limiter.AllowRelay("scope-1"); err != nil {
			t.Errorf("Relay should be allowed at packet %d, got: %v", i, err)
		}
	}

	// Next one should be rate limited (bucket empty)
	if err := limiter.AllowRelay("scope-1"); err != ErrTenantRelayLimit {
		t.Errorf("Expected ErrTenantRelayLimit after burst, got: %v", err)
	}

	// Different scope is independent
	if err := limiter.AllowRelay("scope-2"); err != nil {
		t.Errorf("Different scope should be allowed, got: %v", err)
	}
}

func TestTenantRelayLimiter_RelayRate_DedicatedMode(t *testing.T) {
	limiter := NewTenantRelayLimiter(testLimiterConfig())

	// Empty scope bypasses relay rate
	for i := 0; i < 200; i++ {
		if err := limiter.AllowRelay(""); err != nil {
			t.Errorf("Dedicated mode should bypass relay rate at %d, got: %v", i, err)
		}
	}
}

func TestTenantRelayLimiter_RelayPairLimit(t *testing.T) {
	limiter := NewTenantRelayLimiter(testLimiterConfig())

	// First two pairs allowed (cap is 2 in testLimiterConfig)
	if err := limiter.CheckRelayPair("scope-1", "A→B"); err != nil {
		t.Errorf("First pair should be allowed: %v", err)
	}
	limiter.TrackRelayPair("scope-1", "A→B")

	if err := limiter.CheckRelayPair("scope-1", "C→D"); err != nil {
		t.Errorf("Second pair should be allowed: %v", err)
	}
	limiter.TrackRelayPair("scope-1", "C→D")

	// Third pair triggers LRU eviction (S9): the oldest pair (A→B) is
	// dropped to make room. CheckRelayPair returns nil — the policy is
	// preemption rather than rejection.
	if err := limiter.CheckRelayPair("scope-1", "E→F"); err != nil {
		t.Errorf("Third pair should be allowed via LRU eviction: %v", err)
	}
	limiter.TrackRelayPair("scope-1", "E→F")
	if got := limiter.PairsEvictedCount(); got != 1 {
		t.Errorf("PairsEvictedCount = %d, want 1", got)
	}
	// A→B should now be gone; C→D and E→F remain.
	if limiter.RelayPairCount("scope-1") != 2 {
		t.Errorf("RelayPairCount = %d, want 2", limiter.RelayPairCount("scope-1"))
	}

	// Existing pair is always re-allowed (and refreshes its LRU stamp).
	if err := limiter.CheckRelayPair("scope-1", "C→D"); err != nil {
		t.Errorf("Existing pair should always be allowed: %v", err)
	}

	// Remove a pair, then a new pair fits without eviction.
	limiter.RemoveRelayPair("scope-1", "C→D")
	prevEvicted := limiter.PairsEvictedCount()
	if err := limiter.CheckRelayPair("scope-1", "G→H"); err != nil {
		t.Errorf("After removal, new pair should be allowed: %v", err)
	}
	if got := limiter.PairsEvictedCount(); got != prevEvicted {
		t.Errorf("Pair under cap should not evict; PairsEvictedCount jumped to %d", got)
	}
}

func TestTenantRelayLimiter_UpdateConfig(t *testing.T) {
	cfg := testLimiterConfig()
	limiter := NewTenantRelayLimiter(cfg)

	// Initially MaxSessions = 3
	if err := limiter.CheckSessionLimit("scope-1", 3); err != ErrTenantSessionLimit {
		t.Fatalf("Expected limit at 3, got: %v", err)
	}

	// Increase limit
	cfg.MaxSessions = 10
	limiter.UpdateConfig(cfg)

	if err := limiter.CheckSessionLimit("scope-1", 3); err != nil {
		t.Errorf("After config update to 10, should allow 3: %v", err)
	}

	// Read back config
	got := limiter.Config()
	if got.MaxSessions != 10 {
		t.Errorf("Config().MaxSessions = %d, want 10", got.MaxSessions)
	}
}

func TestTenantRelayLimiter_Cleanup(t *testing.T) {
	limiter := NewTenantRelayLimiter(testLimiterConfig())

	// Create state for two tenants
	limiter.TrackRelayPair("scope-1", "A→B")
	limiter.AllowRelay("scope-2") // creates state via getOrCreate

	// scope-2 has no pairs, scope-1 has one
	limiter.Cleanup()

	// scope-2 state should be cleaned up
	if limiter.RelayPairCount("scope-2") != 0 {
		t.Error("scope-2 should have been cleaned up")
	}

	// scope-1 state should survive
	if limiter.RelayPairCount("scope-1") != 1 {
		t.Errorf("scope-1 should still have 1 pair, got %d", limiter.RelayPairCount("scope-1"))
	}
}

func TestTenantRelayLimiter_Disabled(t *testing.T) {
	cfg := testLimiterConfig()
	cfg.Enabled = false
	limiter := NewTenantRelayLimiter(cfg)

	// All checks pass when disabled
	if err := limiter.CheckSessionLimit("scope-1", 9999); err != nil {
		t.Errorf("Disabled limiter should allow sessions: %v", err)
	}
	if err := limiter.AllowRelay("scope-1"); err != nil {
		t.Errorf("Disabled limiter should allow relay: %v", err)
	}
	if err := limiter.CheckRelayPair("scope-1", "X→Y"); err != nil {
		t.Errorf("Disabled limiter should allow pairs: %v", err)
	}
}

func TestDefaultTenantLimiterConfig(t *testing.T) {
	cfg := DefaultTenantLimiterConfig()

	if cfg.Enabled {
		t.Error("Should be disabled by default")
	}
	if cfg.MaxSessions <= 0 {
		t.Error("MaxSessions should be > 0")
	}
	if cfg.MaxRelayRate <= 0 {
		t.Error("MaxRelayRate should be > 0")
	}
	if cfg.MaxRelayPairs <= 0 {
		t.Error("MaxRelayPairs should be > 0")
	}
}

// TestTenantRelayLimiter_CrossScopeWFQ verifies S9 cross-scope fair
// queueing: when the global MaxTotalPairs is reached, the busiest scope
// (highest count/weight ratio) yields a slot to the incoming request.
func TestTenantRelayLimiter_CrossScopeWFQ(t *testing.T) {
	cfg := ScopeLimiterConfig{
		Enabled:       true,
		MaxRelayPairs: 10, // generous per-scope so we hit global cap first
		MaxTotalPairs: 4,
		ScopeWeights: map[string]int{
			"heavy": 1,
			"light": 1,
		},
	}
	l := NewTenantRelayLimiter(cfg)

	// "heavy" installs 3 pairs; "light" installs 1. Total = 4 = cap.
	for _, k := range []string{"h1", "h2", "h3"} {
		if err := l.CheckRelayPair("heavy", k); err != nil {
			t.Fatalf("CheckRelayPair heavy/%s: %v", k, err)
		}
		l.TrackRelayPair("heavy", k)
	}
	if err := l.CheckRelayPair("light", "l1"); err != nil {
		t.Fatalf("CheckRelayPair light/l1: %v", err)
	}
	l.TrackRelayPair("light", "l1")

	if l.RelayEvictions() != 0 {
		t.Errorf("RelayEvictions before WFQ preemption = %d, want 0", l.RelayEvictions())
	}

	// New admission on "light" → global cap reached → WFQ must evict a
	// pair from "heavy" (ratio 3/1 > 1/1).
	if err := l.CheckRelayPair("light", "l2"); err != nil {
		t.Fatalf("CheckRelayPair light/l2 (WFQ): %v", err)
	}
	l.TrackRelayPair("light", "l2")

	if got := l.RelayEvictions(); got != 1 {
		t.Errorf("RelayEvictions after WFQ preemption = %d, want 1", got)
	}
	if got := l.RelayPairCount("heavy"); got != 2 {
		t.Errorf("heavy pair count after WFQ = %d, want 2", got)
	}
	if got := l.RelayPairCount("light"); got != 2 {
		t.Errorf("light pair count after WFQ = %d, want 2", got)
	}
}

// TestTenantRelayLimiter_WFQRespectsWeights verifies that scope weights
// skew the "busiest" selection. A scope with 3 pairs and weight=3 should
// be considered less busy than a scope with 2 pairs and weight=1.
func TestTenantRelayLimiter_WFQRespectsWeights(t *testing.T) {
	cfg := ScopeLimiterConfig{
		Enabled:       true,
		MaxRelayPairs: 10,
		MaxTotalPairs: 5,
		ScopeWeights: map[string]int{
			"big":  3, // expected share 3/5 ≈ 3 pairs
			"tiny": 1, // expected share 1/5 ≈ 1 pair
		},
	}
	l := NewTenantRelayLimiter(cfg)

	// "big" has 3 pairs (ratio 3/3 = 1.0 — on target for its weight).
	// "tiny" has 2 pairs (ratio 2/1 = 2.0 — 2× over its fair share).
	// Total = 5 = cap. Next admission should evict from "tiny".
	for _, k := range []string{"b1", "b2", "b3"} {
		l.CheckRelayPair("big", k)
		l.TrackRelayPair("big", k)
	}
	for _, k := range []string{"t1", "t2"} {
		l.CheckRelayPair("tiny", k)
		l.TrackRelayPair("tiny", k)
	}

	// "other" (weight=1) wants a slot → WFQ preempts from "tiny" (ratio 2.0
	// > 1.0), not from "big".
	if err := l.CheckRelayPair("other", "o1"); err != nil {
		t.Fatalf("CheckRelayPair other/o1: %v", err)
	}
	l.TrackRelayPair("other", "o1")

	if got := l.RelayPairCount("big"); got != 3 {
		t.Errorf("big pair count after weighted WFQ = %d, want 3 (weight protected)", got)
	}
	if got := l.RelayPairCount("tiny"); got != 1 {
		t.Errorf("tiny pair count after weighted WFQ = %d, want 1 (over its weight share)", got)
	}
	if got := l.RelayEvictions(); got != 1 {
		t.Errorf("RelayEvictions = %d, want 1", got)
	}
}
