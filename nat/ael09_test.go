/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package nat

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	aether "github.com/ORBTR/aether"
)

// ael09CountingConn is a minimal aether.Connection whose only exercised
// method is Close(); it records the close via onClose. The interface is
// embedded (nil) so unused methods satisfy the type without implementation.
type ael09CountingConn struct {
	aether.Connection // nil embedded; only Close() is exercised
	onClose           func()
}

func (c *ael09CountingConn) Close() error {
	if c.onClose != nil {
		c.onClose()
	}
	return nil
}

// TestAEL09_ClosesExtraWinners is the AE-L-09 regression: when several
// candidate handshakes succeed in a simultaneous open, ExecutePunch must
// return exactly one conn and Close() every other rather than leak it.
func TestAEL09_ClosesExtraWinners(t *testing.T) {
	candidates := []net.UDPAddr{
		{IP: net.IPv4(5, 6, 7, 8), Port: 41641},
		{IP: net.IPv4(9, 10, 11, 12), Port: 51820},
		{IP: net.IPv4(13, 14, 15, 16), Port: 51821},
	}
	offer := &PunchOffer{Method: PunchDirect, LocalAddrs: candidates}

	var mu sync.Mutex
	var closed []aether.Connection
	// dial ignores ctx so every candidate yields a live conn regardless of
	// the winner's cancel() — the multi-success case the leak needs.
	dial := func(ctx context.Context, addr net.UDPAddr) (aether.Connection, error) {
		c := &ael09CountingConn{}
		c.onClose = func() { mu.Lock(); closed = append(closed, c); mu.Unlock() }
		return c, nil
	}

	res, err := ExecutePunch(context.Background(), offer, time.Now(), dial)
	if err != nil {
		t.Fatalf("ExecutePunch errored: %v", err)
	}
	if res.Conn == nil {
		t.Fatal("no winning conn returned")
	}

	// The drain runs in a background goroutine; wait for it to close the losers.
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(closed)
		mu.Unlock()
		if n == len(candidates)-1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected %d losing conns closed, got %d", len(candidates)-1, n)
		}
		time.Sleep(5 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, c := range closed {
		if c == res.Conn {
			t.Fatal("closed the conn returned as winner")
		}
	}
}
