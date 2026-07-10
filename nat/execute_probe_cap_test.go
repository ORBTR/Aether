/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package nat

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestExecuteProbeCapsFanOut is the AE-H-06 regression: req.LocalAddrs is
// peer-controlled and unsigned, so ExecuteProbe must not spawn one
// goroutine + UDP burst per address. A request carrying ~300 addresses
// (plus duplicates and unroutable entries) must probe at most
// MaxPunchCandidates distinct, routable targets.
func TestExecuteProbeCapsFanOut(t *testing.T) {
	const oversized = 300

	// Unroutable entries that must never be probed. Placed first so they
	// would fall inside the cap window if filtering were absent.
	unspecified := net.UDPAddr{IP: net.IPv4zero, Port: 41641}
	zeroPort := net.UDPAddr{IP: net.IPv4(9, 9, 9, 9), Port: 0}

	addrs := []net.UDPAddr{unspecified, zeroPort}
	for i := 0; i < oversized; i++ {
		addrs = append(addrs, net.UDPAddr{IP: net.IPv4(10, 1, 1, 1), Port: 40000 + i})
	}
	// A handful of exact duplicates of early valid entries.
	addrs = append(addrs,
		net.UDPAddr{IP: net.IPv4(10, 1, 1, 1), Port: 40000},
		net.UDPAddr{IP: net.IPv4(10, 1, 1, 1), Port: 40001},
		net.UDPAddr{IP: net.IPv4(10, 1, 1, 1), Port: 40000},
	)

	req := &PunchRequest{LocalAddrs: addrs}

	var count atomic.Int64
	var probed sync.Map // addr.String() -> bool
	var dupSeen atomic.Bool
	ExecuteProbe(context.Background(), req, time.Now(), func(ctx context.Context, addr net.UDPAddr) error {
		count.Add(1)
		if _, loaded := probed.LoadOrStore(addr.String(), true); loaded {
			dupSeen.Store(true)
		}
		return nil
	})

	if got := count.Load(); got > MaxPunchCandidates {
		t.Fatalf("ExecuteProbe fanned out to %d probes, exceeding cap %d", got, MaxPunchCandidates)
	}
	if count.Load() == 0 {
		t.Fatal("ExecuteProbe probed nothing; valid candidates were dropped")
	}
	if dupSeen.Load() {
		t.Fatal("an address was probed more than once; dedupe failed")
	}
	if _, ok := probed.Load(unspecified.String()); ok {
		t.Fatalf("unspecified target %s was probed; it must be filtered", unspecified.String())
	}
	if _, ok := probed.Load(zeroPort.String()); ok {
		t.Fatalf("zero-port target %s was probed; it must be filtered", zeroPort.String())
	}
}

// TestProbeCandidates exercises the AE-H-06 helper directly: it caps
// oversized input at MaxPunchCandidates, collapses duplicates, and drops
// unroutable targets.
func TestProbeCandidates(t *testing.T) {
	// Oversized: 200 distinct valid addrs must cap at MaxPunchCandidates.
	big := make([]net.UDPAddr, 0, 200)
	for i := 0; i < 200; i++ {
		big = append(big, net.UDPAddr{IP: net.IPv4(172, 16, 0, 1), Port: 30000 + i})
	}
	if got := ProbeCandidates(&PunchRequest{LocalAddrs: big}); len(got) != MaxPunchCandidates {
		t.Fatalf("oversized input yielded %d candidates, want %d", len(got), MaxPunchCandidates)
	}

	// Dedupe: three copies of two addresses collapse to two.
	a := net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 41641}
	b := net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 51820}
	dupIn := []net.UDPAddr{a, a, b, a, b}
	if got := ProbeCandidates(&PunchRequest{LocalAddrs: dupIn}); len(got) != 2 {
		t.Fatalf("duplicated input yielded %d candidates, want 2", len(got))
	}

	// Invalid targets are filtered: nil IP, unspecified, zero/negative/
	// out-of-range port.
	invalidIn := []net.UDPAddr{
		{IP: nil, Port: 41641},
		{IP: net.IPv4zero, Port: 41641},
		{IP: net.IPv4(1, 2, 3, 4), Port: 0},
		{IP: net.IPv4(1, 2, 3, 4), Port: -1},
		{IP: net.IPv4(1, 2, 3, 4), Port: 65536},
		{IP: net.IPv4(1, 2, 3, 4), Port: 41641}, // the one valid entry
	}
	got := ProbeCandidates(&PunchRequest{LocalAddrs: invalidIn})
	if len(got) != 1 {
		t.Fatalf("filtered input yielded %d candidates, want 1", len(got))
	}
	want := net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 41641}
	if got[0].String() != want.String() {
		t.Fatalf("unexpected surviving candidate %s", got[0].String())
	}
}
