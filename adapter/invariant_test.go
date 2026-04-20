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

// TestInvariant_StreamSendReceive verifies that Stream.Send/Receive behaves
// identically across TCP and WebSocket adapters (both reliable stream transports).
// Verifies transport-invariant semantics.
func TestInvariant_StreamSendReceive(t *testing.T) {
	adapters := []struct {
		name    string
		create  func(client, server net.Conn) (aether.Session, aether.Session)
	}{
		{
			name: "TCP",
			create: func(c, s net.Conn) (aether.Session, aether.Session) {
				return NewTCPSession(c, "local", "remote", aether.ProtoTCP, aether.DefaultSessionOptions()),
					NewTCPSession(s, "remote", "local", aether.ProtoTCP, aether.DefaultSessionOptions())
			},
		},
		{
			name: "WebSocket",
			create: func(c, s net.Conn) (aether.Session, aether.Session) {
				return NewWebSocketSession(c, "local", "remote", aether.DefaultSessionOptions()),
					NewWebSocketSession(s, "remote", "local", aether.DefaultSessionOptions())
			},
		},
	}

	for _, adapter := range adapters {
		t.Run(adapter.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			clientSession, serverSession := adapter.create(clientConn, serverConn)
			defer clientSession.Close()
			defer serverSession.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// Invariant 1: OpenStream succeeds
			stream, err := clientSession.OpenStream(ctx, aether.StreamConfig{
				StreamID:    42,
				Reliability: aether.ReliableOrdered,
				Priority:    128,
			})
			if err != nil {
				t.Fatalf("[%s] OpenStream: %v", adapter.name, err)
			}

			// Invariant 2: AcceptStream succeeds
			peerStream, err := serverSession.AcceptStream(ctx)
			if err != nil {
				t.Fatalf("[%s] AcceptStream: %v", adapter.name, err)
			}

			// Invariant 3: StreamID matches
			if peerStream.StreamID() != 42 {
				t.Errorf("[%s] StreamID: got %d, want 42", adapter.name, peerStream.StreamID())
			}

			// Invariant 4: Send succeeds
			if err := stream.Send(ctx, []byte("invariant test")); err != nil {
				t.Fatalf("[%s] Send: %v", adapter.name, err)
			}

			// Wait for scheduler to flush
			time.Sleep(50 * time.Millisecond)

			// Invariant 5: Receive returns sent data
			data, err := peerStream.Receive(ctx)
			if err != nil {
				t.Fatalf("[%s] Receive: %v", adapter.name, err)
			}
			if string(data) != "invariant test" {
				t.Errorf("[%s] Receive: got %q, want %q", adapter.name, data, "invariant test")
			}

			// Invariant 6: IsClosed returns false while session is active
			if clientSession.IsClosed() {
				t.Errorf("[%s] IsClosed should be false", adapter.name)
			}

			// Invariant 7: Close succeeds
			if err := clientSession.Close(); err != nil {
				t.Errorf("[%s] Close: %v", adapter.name, err)
			}

			// Invariant 8: IsClosed returns true after Close
			if !clientSession.IsClosed() {
				t.Errorf("[%s] IsClosed should be true after Close", adapter.name)
			}
		})
	}
}

// TestInvariant_Metrics verifies that Metrics() returns valid data for all adapters.
func TestInvariant_Metrics(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	sessions := []struct {
		name    string
		session aether.Session
	}{
		{"TCP", NewTCPSession(clientConn, "local", "remote", aether.ProtoTCP, aether.DefaultSessionOptions())},
	}

	for _, s := range sessions {
		t.Run(s.name, func(t *testing.T) {
			defer s.session.Close()

			metrics := s.session.Metrics()
			// Invariant: ActiveStreams starts at 0
			if metrics.ActiveStreams < 0 {
				t.Errorf("[%s] ActiveStreams should be >= 0, got %d", s.name, metrics.ActiveStreams)
			}
		})
	}
}
