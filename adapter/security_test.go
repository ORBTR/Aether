//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package adapter

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// ─── S5 — MaxConcurrentStreams admission ──────────────────────────────
// Addresses _SECURITY.md §3.12. A peer must not be able to fill memory
// by opening unbounded streams against the local session.

// TestS5_TCPSessionRefusesOverCap opens the TCPSession stream cap +1
// streams from a client and verifies the server refuses the last one.
func TestS5_TCPSessionRefusesOverCap(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	client := NewTCPSession(clientConn, "vl1_client", "vl1_server", aether.ProtoTCP, aether.DefaultSessionOptions())
	server := NewTCPSession(serverConn, "vl1_server", "vl1_client", aether.ProtoTCP, aether.DefaultSessionOptions())
	defer client.Close()
	defer server.Close()

	// Set a small cap so the test is fast.
	server.opts.MaxConcurrentStreams = 3

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Open 3 streams (should all succeed).
	for i := 0; i < 3; i++ {
		_, err := client.OpenStream(ctx, aether.StreamConfig{
			StreamID:    uint64(100 + i),
			Reliability: aether.ReliableOrdered,
			Priority:    128,
		})
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
	}
	// Drain accepts so the server-side map is populated.
	for i := 0; i < 3; i++ {
		if _, err := server.AcceptStream(ctx); err != nil {
			t.Fatalf("accept %d: %v", i, err)
		}
	}

	// The 4th open should be refused by the server; the server sends
	// RESET back — we don't care about propagation here, only that
	// the server's streamRefused counter incremented.
	_, _ = client.OpenStream(ctx, aether.StreamConfig{
		StreamID:    200,
		Reliability: aether.ReliableOrdered,
		Priority:    128,
	})

	// Give the server a moment to process the OPEN and send RESET.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if server.StreamRefusedCount() >= 1 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if got := server.StreamRefusedCount(); got < 1 {
		t.Errorf("StreamRefusedCount = %d, want >= 1", got)
	}
	// Metrics plumbing sanity-check.
	if m := server.Metrics(); m.StreamRefused < 1 {
		t.Errorf("SessionMetrics.StreamRefused = %d, want >= 1", m.StreamRefused)
	}
}
