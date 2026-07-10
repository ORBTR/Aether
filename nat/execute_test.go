/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package nat

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	aether "github.com/ORBTR/aether"
)

// TestExecutePunchDirect verifies ExecutePunch waits until T0 and then
// dials every offered candidate.
func TestExecutePunchDirect(t *testing.T) {
	candidates := []net.UDPAddr{
		{IP: net.IPv4(5, 6, 7, 8), Port: 41641},
		{IP: net.IPv4(9, 10, 11, 12), Port: 51820},
	}
	offer := &PunchOffer{Method: PunchDirect, LocalAddrs: candidates}
	t0 := time.Now().Add(120 * time.Millisecond)

	var mu sync.Mutex
	dialed := map[string]bool{}
	var firstDialAt time.Time
	dial := func(ctx context.Context, addr net.UDPAddr) (aether.Connection, error) {
		mu.Lock()
		if firstDialAt.IsZero() {
			firstDialAt = time.Now()
		}
		dialed[addr.String()] = true
		mu.Unlock()
		return nil, errors.New("test: no socket")
	}

	res, err := ExecutePunch(context.Background(), offer, t0, dial)
	if err == nil {
		t.Fatal("ExecutePunch should fail when every candidate dial fails")
	}
	if res.NotViable {
		t.Fatal("PunchDirect must not be reported NotViable")
	}
	if firstDialAt.Before(t0) {
		t.Fatalf("dial fired at %v, before T0 %v", firstDialAt, t0)
	}
	for _, c := range candidates {
		if !dialed[c.String()] {
			t.Fatalf("candidate %s was never dialed", c.String())
		}
	}
}

// TestExecutePunchRelayNotViable verifies a PunchRelay offer yields a
// NotViable result without dialing.
func TestExecutePunchRelayNotViable(t *testing.T) {
	offer := &PunchOffer{
		Method:     PunchRelay,
		LocalAddrs: []net.UDPAddr{{IP: net.IPv4(5, 6, 7, 8), Port: 41641}},
	}
	dialed := false
	dial := func(context.Context, net.UDPAddr) (aether.Connection, error) {
		dialed = true
		return nil, nil
	}
	res, err := ExecutePunch(context.Background(), offer, time.Now(), dial)
	if err != nil {
		t.Fatalf("ExecutePunch errored on a relay offer: %v", err)
	}
	if !res.NotViable {
		t.Fatal("PunchRelay must yield a NotViable result")
	}
	if dialed {
		t.Fatal("PunchRelay must not dial any candidate")
	}
}

// TestExecuteProbe verifies the responder half waits until T0 and probes
// every requester candidate.
func TestExecuteProbe(t *testing.T) {
	req := &PunchRequest{
		LocalAddrs: []net.UDPAddr{
			{IP: net.IPv4(1, 2, 3, 4), Port: 41641},
			{IP: net.IPv4(2, 3, 4, 5), Port: 51820},
		},
	}
	t0 := time.Now().Add(120 * time.Millisecond)

	var mu sync.Mutex
	probed := map[string]bool{}
	var firstProbeAt time.Time
	ExecuteProbe(context.Background(), req, t0, func(ctx context.Context, addr net.UDPAddr) error {
		mu.Lock()
		if firstProbeAt.IsZero() {
			firstProbeAt = time.Now()
		}
		probed[addr.String()] = true
		mu.Unlock()
		return nil
	})
	if firstProbeAt.Before(t0) {
		t.Fatalf("probe fired at %v, before T0 %v", firstProbeAt, t0)
	}
	for _, c := range req.LocalAddrs {
		if !probed[c.String()] {
			t.Fatalf("requester candidate %s was never probed", c.String())
		}
	}
	// A nil probe func must be a safe no-op.
	ExecuteProbe(context.Background(), req, time.Now(), nil)
}
