/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import (
	"sync"
	"testing"

	"github.com/ORBTR/aether/abuse"
)

// AE-P-01 regression coverage: AbuseTracker.SetRegistry used to swap a
// plain *abuse.Score[NodeID] pointer field with no synchronization while
// Report/PeerScore read it on the per-session hot path — a -race-detectable
// data race reachable via the exported SetAbuseScoreRegistry surface. The
// field is now an atomic.Pointer loaded once per call. These tests prove
// the swap is race-free AND that the swapped-in registry is what subsequent
// reads observe.

const aep01Remote NodeID = "aep01-peer"

func aep01NewRegistry() *abuse.Score[NodeID] {
	return abuse.New[NodeID](abuse.Config{})
}

// TestAEP01_ConcurrentSwapAndRead hammers Report/PeerScore in one goroutine
// while another repeatedly swaps in fresh registries via SetRegistry. Under
// `go test -race` this reports a data race on the score field before the
// atomic.Pointer fix and runs clean after it.
func TestAEP01_ConcurrentSwapAndRead(t *testing.T) {
	tracker := NewAbuseTracker(aep01NewRegistry(), aep01Remote, nil, nil, nil)

	const iterations = 50000
	var wg sync.WaitGroup
	wg.Add(2)

	// Reader/reporter — the hot path.
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			tracker.Report(abuse.ReasonMalformedFrame)
			_, _ = tracker.PeerScore()
		}
	}()

	// Swapper — SetAbuseScoreRegistry cross-session dashboard path.
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			tracker.SetRegistry(aep01NewRegistry())
		}
	}()

	wg.Wait()
}

// TestAEP01_SwapRedirectsReads proves the atomic swap actually takes effect:
// after SetRegistry, reports land on the new registry and the old one is
// left untouched.
func TestAEP01_SwapRedirectsReads(t *testing.T) {
	oldReg := aep01NewRegistry()
	newReg := aep01NewRegistry()
	tracker := NewAbuseTracker(oldReg, aep01Remote, nil, nil, nil)

	if !tracker.SetRegistry(newReg) {
		t.Fatalf("AE-P-01: SetRegistry(*abuse.Score) returned false, want true")
	}
	// The swap must publish exactly the new registry pointer (in-package
	// identity check — no float-equality flakiness).
	if got := tracker.score.Load(); got != newReg {
		t.Fatalf("AE-P-01: score.Load() did not observe the swapped-in registry")
	}

	// Record a few events; they must accrue on newReg, not oldReg.
	for i := 0; i < 3; i++ {
		tracker.Report(abuse.ReasonMalformedFrame)
	}

	if got := newReg.Current(aep01Remote); got <= 0 {
		t.Fatalf("AE-P-01: new registry score = %v, want > 0 (reports did not follow the swap)", got)
	}
	// oldReg never saw a Record for this peer, so Current returns 0 (map
	// miss, no decay applied) — an exact 0 is safe to assert here.
	if got := oldReg.Current(aep01Remote); got != 0 {
		t.Fatalf("AE-P-01: old registry score = %v, want 0 (reports leaked to the pre-swap registry)", got)
	}

	if _, ok := tracker.PeerScore(); !ok {
		t.Fatalf("AE-P-01: PeerScore ok = false, want true after swap")
	}
}

// TestAEP01_BadTypeSwapNoOp confirms a wrong-typed SetRegistry is rejected
// and leaves the active registry (and its accrued score) unchanged.
func TestAEP01_BadTypeSwapNoOp(t *testing.T) {
	reg := aep01NewRegistry()
	tracker := NewAbuseTracker(reg, aep01Remote, nil, nil, nil)

	tracker.Report(abuse.ReasonMalformedFrame)
	before, ok := tracker.PeerScore()
	if !ok || before <= 0 {
		t.Fatalf("AE-P-01: precondition failed, score=%v ok=%v", before, ok)
	}

	if tracker.SetRegistry(interface{}("not-a-registry")) {
		t.Fatalf("AE-P-01: SetRegistry(string) returned true, want false")
	}

	// The active registry pointer must be untouched by the rejected swap
	// (identity check avoids exponential-decay float flakiness across reads).
	if got := tracker.score.Load(); got != reg {
		t.Fatalf("AE-P-01: rejected swap replaced the active registry pointer")
	}
	if _, ok := tracker.PeerScore(); !ok {
		t.Fatalf("AE-P-01: PeerScore ok = false after rejected swap, want true")
	}
}
