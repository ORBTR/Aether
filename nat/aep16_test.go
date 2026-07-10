/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package nat

import (
	"net"
	"runtime"
	"testing"
)

// aep16Seeds builds n distinct, routable UDP addresses. Distinct IPs keep
// PunchCandidates from collapsing them (it does not dedupe), and a
// mid-range port lets every seed's ±128 prediction window stay in bounds.
func aep16Seeds(n int) []net.UDPAddr {
	out := make([]net.UDPAddr, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, net.UDPAddr{
			IP:   net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)),
			Port: 40000,
		})
	}
	return out
}

// TestAEP16_CapsBeforePrediction is the AE-P-16 regression: a
// PunchPortPrediction offer must yield at most MaxPunchCandidates
// candidates no matter how many seeds the peer supplies, and the pre-cap
// added before PredictPorts must not change that ceiling.
func TestAEP16_CapsBeforePrediction(t *testing.T) {
	for _, n := range []int{1, 64, 10000} {
		offer := &PunchOffer{Method: PunchPortPrediction, LocalAddrs: aep16Seeds(n)}
		got := PunchCandidates(offer)
		if len(got) > MaxPunchCandidates {
			t.Fatalf("n=%d: PunchCandidates returned %d, exceeding cap %d", n, len(got), MaxPunchCandidates)
		}
		// One seed alone expands to 257 predicted ports, so any n>=1 fills
		// the cap exactly.
		if len(got) != MaxPunchCandidates {
			t.Fatalf("n=%d: PunchCandidates returned %d, want %d", n, len(got), MaxPunchCandidates)
		}
	}
}

// TestAEP16_BehaviorPreserved proves the pre-expansion seed cap does not
// alter the returned candidate set: PredictPorts emits seeds in input
// order and the leading seed already overflows the final cap, so the
// result computed from all 10000 seeds is identical to the result from
// only the first MaxPunchCandidates seeds.
func TestAEP16_BehaviorPreserved(t *testing.T) {
	full := aep16Seeds(10000)
	truncated := append([]net.UDPAddr(nil), full[:MaxPunchCandidates]...)

	gotFull := PunchCandidates(&PunchOffer{Method: PunchPortPrediction, LocalAddrs: full})
	gotTrunc := PunchCandidates(&PunchOffer{Method: PunchPortPrediction, LocalAddrs: truncated})

	if len(gotFull) != len(gotTrunc) {
		t.Fatalf("length differs: full=%d truncated=%d", len(gotFull), len(gotTrunc))
	}
	for i := range gotFull {
		if gotFull[i].String() != gotTrunc[i].String() {
			t.Fatalf("candidate %d differs: full=%s truncated=%s", i, gotFull[i].String(), gotTrunc[i].String())
		}
	}
}

// TestAEP16_AllocationBounded is the amplification regression: with the
// pre-expansion cap, PredictPorts sees at most MaxPunchCandidates seeds, so
// a 50k-seed PunchPortPrediction offer allocates a bounded amount of memory
// (linear in the input plus a fixed 64*257 predicted set) instead of the
// 257*len(seeds) backing array the bug materialized. The buggy path would
// allocate hundreds of MB for this input; the ceiling cleanly separates the
// two. TotalAlloc is cumulative and unaffected by GC, so the delta measures
// bytes allocated by the single call regardless of collection timing.
func TestAEP16_AllocationBounded(t *testing.T) {
	const seeds = 50000
	const ceiling = 32 << 20 // 32 MiB; fixed path is a few MiB, buggy path ~600 MiB

	offer := &PunchOffer{Method: PunchPortPrediction, LocalAddrs: aep16Seeds(seeds)}

	runtime.GC()
	var m0 runtime.MemStats
	runtime.ReadMemStats(&m0)

	got := PunchCandidates(offer)

	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	if len(got) != MaxPunchCandidates {
		t.Fatalf("PunchCandidates returned %d, want %d", len(got), MaxPunchCandidates)
	}
	alloc := m1.TotalAlloc - m0.TotalAlloc
	if alloc > ceiling {
		t.Fatalf("PunchCandidates allocated %d bytes for %d seeds, exceeding ceiling %d (amplification regression)", alloc, seeds, ceiling)
	}
}

// TestAEP16_DirectPathUnaffected confirms the non-prediction path is
// unchanged: a PunchDirect offer with more than MaxPunchCandidates
// addresses still returns exactly MaxPunchCandidates.
func TestAEP16_DirectPathUnaffected(t *testing.T) {
	offer := &PunchOffer{Method: PunchDirect, LocalAddrs: aep16Seeds(100)}
	got := PunchCandidates(offer)
	if len(got) != MaxPunchCandidates {
		t.Fatalf("PunchDirect with 100 addrs returned %d, want %d", len(got), MaxPunchCandidates)
	}
}
