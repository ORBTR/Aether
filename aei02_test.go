/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import (
	"sort"
	"sync"
	"testing"
	"time"
)

// TestAEI02_ExemptsWellKnownStreamsBelowBoundary pins the sweep() exemption
// boundary to StreamGCExemptBelow so the code and the type/const docs cannot
// drift (AE-I-02). Streams with ID < StreamGCExemptBelow are well-known
// protocol streams (gossip, RPC, keepalive, control) and must never be
// idle-reset; dynamic streams at or above the boundary must be reclaimed.
func TestAEI02_ExemptsWellKnownStreamsBelowBoundary(t *testing.T) {
	// Boundary-lock: a future silent narrowing of the exemption (e.g. to < 4)
	// would re-expose live low-ID upload streams to GC. Fail loudly if changed.
	if StreamGCExemptBelow != 10 {
		t.Fatalf("AE-I-02: StreamGCExemptBelow expected 10, got %d — exemption window must not be narrowed", StreamGCExemptBelow)
	}

	var aei02Mu sync.Mutex
	var aei02Reset []uint64
	resetFn := func(streamID uint64) {
		aei02Mu.Lock()
		aei02Reset = append(aei02Reset, streamID)
		aei02Mu.Unlock()
	}

	g := NewStreamGC(50*time.Millisecond, resetFn)

	// Spread across the boundary: exempt {0,3,4,9}, non-exempt {10,12,50}.
	// 9 is the max exempt edge; 10 is the min non-exempt edge.
	aei02Exempt := []uint64{0, 3, 4, 9}
	aei02NonExempt := []uint64{10, 12, 50}
	for _, id := range aei02Exempt {
		g.Register(id)
	}
	for _, id := range aei02NonExempt {
		g.Register(id)
	}

	// Force every tracked stream well past the idle timeout.
	g.mu.Lock()
	stale := time.Now().Add(-time.Hour)
	for id := range g.lastActivity {
		g.lastActivity[id] = stale
	}
	g.mu.Unlock()

	// Deterministic sweep — no ticker/goroutine needed.
	g.sweep()

	aei02Mu.Lock()
	got := append([]uint64(nil), aei02Reset...)
	aei02Mu.Unlock()
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })

	want := []uint64{10, 12, 50}
	if len(got) != len(want) {
		t.Fatalf("AE-I-02: reset set = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("AE-I-02: reset set = %v, want %v", got, want)
		}
	}

	// Exempt streams must survive as tracker keys; non-exempt must be deleted.
	g.mu.Lock()
	for _, id := range aei02Exempt {
		if _, ok := g.lastActivity[id]; !ok {
			t.Errorf("AE-I-02: exempt stream %d was reclaimed but must survive", id)
		}
	}
	for _, id := range aei02NonExempt {
		if _, ok := g.lastActivity[id]; ok {
			t.Errorf("AE-I-02: non-exempt stream %d should have been GC'd", id)
		}
	}
	g.mu.Unlock()

	if c := g.TrackedCount(); c != len(aei02Exempt) {
		t.Fatalf("AE-I-02: TrackedCount = %d, want %d (only exempt streams remain)", c, len(aei02Exempt))
	}
}
