/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package nat

import (
	"context"
	"net"
	"testing"
	"time"

	aether "github.com/ORBTR/aether"
)

// aep17FakeConn is a minimal aether.Connection for the within-bound punch
// test; the interface is embedded (nil) so only the returned value matters.
type aep17FakeConn struct {
	aether.Connection // nil embedded; no method is exercised
}

// TestAEP17_ExecutePunchRejectsFarFutureT0 is the AE-P-17 regression: a T0
// more than MaxPunchWait in the future (reachable via the peer-controlled,
// unfreshened PunchRequest.Timestamp) must be refused immediately rather
// than parking a timer for that whole duration.
func TestAEP17_ExecutePunchRejectsFarFutureT0(t *testing.T) {
	offer := &PunchOffer{
		Method:     PunchDirect,
		LocalAddrs: []net.UDPAddr{{IP: net.IPv4(5, 6, 7, 8), Port: 41641}},
	}
	dialed := false
	dial := func(context.Context, net.UDPAddr) (aether.Connection, error) {
		dialed = true
		t.Error("dial must not run for a far-future T0")
		return nil, nil
	}

	t0 := time.Now().Add(MaxPunchWait + time.Second)
	start := time.Now()
	res, err := ExecutePunch(context.Background(), offer, t0, dial)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("ExecutePunch must return an error for a T0 past MaxPunchWait")
	}
	if res.Conn != nil {
		t.Fatal("ExecutePunch must not return a connection for a far-future T0")
	}
	if dialed {
		t.Fatal("ExecutePunch dialed despite a far-future T0")
	}
	if elapsed > time.Second {
		t.Fatalf("ExecutePunch parked %v; must reject a far-future T0 promptly", elapsed)
	}
}

// TestAEP17_ExecuteProbeRejectsFarFutureT0 is the responder-half mirror: a
// far-future T0 must return promptly without probing any target.
func TestAEP17_ExecuteProbeRejectsFarFutureT0(t *testing.T) {
	req := &PunchRequest{
		LocalAddrs: []net.UDPAddr{
			{IP: net.IPv4(1, 2, 3, 4), Port: 41641},
			{IP: net.IPv4(2, 3, 4, 5), Port: 51820},
		},
	}
	probed := false
	probe := func(context.Context, net.UDPAddr) error {
		probed = true
		t.Error("probe must not run for a far-future T0")
		return nil
	}

	t0 := time.Now().Add(MaxPunchWait + time.Second)
	start := time.Now()
	ExecuteProbe(context.Background(), req, t0, probe)
	elapsed := time.Since(start)

	if probed {
		t.Fatal("ExecuteProbe probed despite a far-future T0")
	}
	if elapsed > time.Second {
		t.Fatalf("ExecuteProbe parked %v; must reject a far-future T0 promptly", elapsed)
	}
}

// TestAEP17_ExecutePunchWithinBoundStillFires is the capability guard: a
// near-future T0 well under MaxPunchWait must still block until T0 and then
// dial, so the bound never costs a legitimate punch.
func TestAEP17_ExecutePunchWithinBoundStillFires(t *testing.T) {
	offer := &PunchOffer{
		Method:     PunchDirect,
		LocalAddrs: []net.UDPAddr{{IP: net.IPv4(5, 6, 7, 8), Port: 41641}},
	}
	dial := func(context.Context, net.UDPAddr) (aether.Connection, error) {
		return &aep17FakeConn{}, nil
	}

	t0 := time.Now().Add(50 * time.Millisecond)
	start := time.Now()
	res, err := ExecutePunch(context.Background(), offer, t0, dial)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("ExecutePunch errored on an in-bound T0: %v", err)
	}
	if res.Conn == nil {
		t.Fatal("ExecutePunch returned no connection for an in-bound near-future T0")
	}
	if elapsed < 40*time.Millisecond {
		t.Fatalf("ExecutePunch fired after %v; it must wait until T0", elapsed)
	}
}
