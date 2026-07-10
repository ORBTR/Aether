//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package noise

import (
	"testing"
)

// TestAEL10_GlobalCapDominantScope is the regression test for AE-L-10.
//
// When a single dominant tenant is the globally busiest scope but sits far
// below its own MaxRelayPairs, step (2) self-churn never fires (it only
// evicts at the per-scope cap). Before the fix, step (3)'s busiest==self
// branch self-evicted only when MaxRelayPairs<=0, so a below-cap dominant
// tenant admitted new pairs without eviction and pushed the global count
// past MaxTotalPairs — the "hard cap" was not a real ceiling.
//
// The fix drops that guard so the busiest==self branch self-evicts the
// scope's LRU pair unconditionally (control only reaches it while total is
// still >= MaxTotalPairs), keeping the global count pinned at the cap.
func TestAEL10_GlobalCapDominantScope(t *testing.T) {
	cfg := ScopeLimiterConfig{
		Enabled:       true,
		MaxRelayPairs: 5000, // far above the global cap so step (2) never fires
		MaxTotalPairs: 3,    // the hard ceiling under test
		// no weights: the sole scope "dom" is always the busiest
	}
	l := NewTenantRelayLimiter(cfg)

	const scope = "dom"

	// Fill the global cap with three pairs on the dominant scope.
	for _, k := range []string{"p1", "p2", "p3"} {
		if err := l.CheckRelayPair(scope, k); err != nil {
			t.Fatalf("CheckRelayPair %s/%s: %v", scope, k, err)
		}
		l.TrackRelayPair(scope, k)
	}
	if got := l.RelayPairCount(scope); got != cfg.MaxTotalPairs {
		t.Fatalf("after fill: RelayPairCount(%q) = %d, want %d", scope, got, cfg.MaxTotalPairs)
	}

	// Every subsequent admission on the SAME dominant scope must self-evict
	// so the global count never exceeds the hard cap. Pre-fix, the first
	// over-cap admission (ael10p4) trips this assertion.
	overCap := []string{"ael10p4", "ael10p5", "ael10p6", "ael10p7"}
	for _, k := range overCap {
		if err := l.CheckRelayPair(scope, k); err != nil {
			t.Fatalf("CheckRelayPair %s/%s (over cap): %v", scope, k, err)
		}
		l.TrackRelayPair(scope, k)
		if got := l.RelayPairCount(scope); got > cfg.MaxTotalPairs {
			t.Fatalf("after admitting %s: RelayPairCount(%q) = %d exceeds hard cap %d",
				k, scope, got, cfg.MaxTotalPairs)
		}
	}

	// The count is pinned at the hard cap and each over-cap admission drove
	// exactly one self-eviction (busiest==self credits pairsEvicted, not
	// relayEvictions since there is only one scope).
	if got := l.RelayPairCount(scope); got != cfg.MaxTotalPairs {
		t.Errorf("final RelayPairCount(%q) = %d, want %d", scope, got, cfg.MaxTotalPairs)
	}
	if got, want := l.PairsEvictedCount(), uint64(len(overCap)); got != want {
		t.Errorf("PairsEvictedCount = %d, want %d (one self-evict per over-cap admission)", got, want)
	}
	if got := l.RelayEvictions(); got != 0 {
		t.Errorf("RelayEvictions = %d, want 0 (single scope → no cross-scope WFQ)", got)
	}
}
