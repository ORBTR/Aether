//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package adapter

import (
	"context"
	"errors"
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

// TestS5_LocalOpenStreamCapHitReturnsTypedError — A1 audit follow-up
// 2026-06-02. Verifies that locally-initiated OpenStream calls that
// hit the MaxConcurrentStreams cap return aether.ErrStreamCapExhausted
// (detectable via errors.Is) AND increment the streamRefused counter.
// Library callers (mesh_connection.go, StreamPool.Fill) rely on this
// typed error to back off without closing the entire session — a
// stringly-typed error caused callers to misinterpret the transient
// cap-hit as a session-fatal transport failure.
func TestS5_LocalOpenStreamCapHitReturnsTypedError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	client := NewTCPSession(clientConn, "vl1_client", "vl1_server", aether.ProtoTCP, aether.DefaultSessionOptions())
	server := NewTCPSession(serverConn, "vl1_server", "vl1_client", aether.ProtoTCP, aether.DefaultSessionOptions())
	defer client.Close()
	defer server.Close()

	// Cap the LOCAL side this time so the typed error fires on the
	// client.OpenStream path (the audit-fix surface) rather than the
	// peer-side reset path the original S5 test covers.
	client.opts.MaxConcurrentStreams = 2

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Open up to the cap — these should all succeed.
	for i := 0; i < 2; i++ {
		_, err := client.OpenStream(ctx, aether.StreamConfig{
			StreamID:    uint64(100 + i),
			Reliability: aether.ReliableOrdered,
			Priority:    128,
		})
		if err != nil {
			t.Fatalf("open %d unexpectedly failed: %v", i, err)
		}
	}

	// The cap+1 open MUST return aether.ErrStreamCapExhausted (wrapped).
	_, err := client.OpenStream(ctx, aether.StreamConfig{
		StreamID:    200,
		Reliability: aether.ReliableOrdered,
		Priority:    128,
	})
	if err == nil {
		t.Fatal("OpenStream past cap returned nil error, want ErrStreamCapExhausted")
	}
	if !errors.Is(err, aether.ErrStreamCapExhausted) {
		t.Errorf("err = %v; want errors.Is(err, ErrStreamCapExhausted) == true", err)
	}

	// Local streamRefused counter must reflect the rejection.
	if got := client.StreamRefusedCount(); got < 1 {
		t.Errorf("local StreamRefusedCount = %d, want >= 1", got)
	}
	if m := client.Metrics(); m.StreamRefused < 1 {
		t.Errorf("local SessionMetrics.StreamRefused = %d, want >= 1", m.StreamRefused)
	}
}
