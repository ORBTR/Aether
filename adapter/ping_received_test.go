//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package adapter

import (
	"context"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// pingsReceived is the count the session states for the PINGs its peer sent it, in
// SessionMetrics and in its health.Monitor, which must agree.
func pingsReceived(t *testing.T, s aether.Session) uint64 {
	t.Helper()
	m := s.Metrics().PingsReceived
	if h := s.Health().PingsReceived(); h != m {
		t.Fatalf("SessionMetrics.PingsReceived %d, health.Monitor.PingsReceived %d", m, h)
	}
	return m
}

// TestSession_CountsThePingsItsPeerSends: on every session type a PING from the peer
// is counted on the side that answers it, and a PONG to this side's own PING is not,
// so a holder can tell that its peer's keepalive reaches it from a session whose only
// traffic is its own probing.
func TestSession_CountsThePingsItsPeerSends(t *testing.T) {
	pairs := map[string]func(t *testing.T) (pinger, answerer aether.Session){
		"noise": func(t *testing.T) (aether.Session, aether.Session) {
			c, s := noisePairWithRealms(t, nil, nil)
			return c, s
		},
		"tcp": func(t *testing.T) (aether.Session, aether.Session) {
			return byteStreamPair(t, aether.ProtoTCP, nil, nil)
		},
		"websocket": func(t *testing.T) (aether.Session, aether.Session) {
			return byteStreamPair(t, aether.ProtoWebSocket, nil, nil)
		},
		"quic": func(t *testing.T) (aether.Session, aether.Session) {
			c, s := quicLoopback(t)
			t.Cleanup(func() { _ = c.Close(); _ = s.Close() })
			return c, s
		},
	}
	for name, pair := range pairs {
		t.Run(name, func(t *testing.T) {
			pinger, answerer := pair(t)
			before, ownBefore := pingsReceived(t, answerer), pingsReceived(t, pinger)
			const n = 3
			for i := 0; i < n; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				_, err := pinger.Ping(ctx)
				cancel()
				if err != nil {
					t.Fatalf("ping %d: %v", i, err)
				}
			}
			if got := pingsReceived(t, answerer) - before; got < n {
				t.Fatalf("the answering side counted %d of the %d PINGs its peer sent", got, n)
			}
			if got := pingsReceived(t, pinger) - ownBefore; got != 0 {
				t.Fatalf("the pinging side counted %d PINGs for the PONGs it received", got)
			}
		})
	}
}
