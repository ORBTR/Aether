//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package adapter

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// aer099NewPair builds a paired client/server TCPSession over net.Pipe.
// Uniquely named to avoid cross-agent symbol collisions in package adapter.
func aer099NewPair(t *testing.T) (client, server *TCPSession, cleanup func()) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	client = NewTCPSession(clientConn, "vl1_aer099_client_node_abcdef", "vl1_aer099_server_node_ghijkl", aether.ProtoTCP, aether.DefaultSessionOptions())
	server = NewTCPSession(serverConn, "vl1_aer099_server_node_ghijkl", "vl1_aer099_client_node_abcdef", aether.ProtoTCP, aether.DefaultSessionOptions())
	cleanup = func() {
		if err := client.Close(); err != nil {
			t.Errorf("client.Close: %v", err)
		}
		if err := server.Close(); err != nil {
			t.Errorf("server.Close: %v", err)
		}
		if err := clientConn.Close(); err != nil {
			t.Errorf("clientConn.Close: %v", err)
		}
		if err := serverConn.Close(); err != nil {
			t.Errorf("serverConn.Close: %v", err)
		}
	}
	return client, server, cleanup
}

// TestAER099_LargeMessageRoundTripsAsOneReceive: a
// message larger than MaxFrameSize MUST arrive as a SINGLE Receive() call with
// byte-identical content, not as a truncated head followed by extra Receive()
// results — a silent message-boundary violation.
func TestAER099_LargeMessageRoundTripsAsOneReceive(t *testing.T) {
	client, server, cleanup := aer099NewPair(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cs, err := client.OpenStream(ctx, aether.StreamConfig{
		StreamID: 9, Reliability: aether.ReliableOrdered, Priority: 128,
	})
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	ss, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept stream: %v", err)
	}

	// 200 KB — comfortably above any class MaxFrameSize.
	msg := make([]byte, 200_000)
	for i := range msg {
		msg[i] = byte(i*31 + 7)
	}

	if err := cs.Send(ctx, msg); err != nil {
		t.Fatalf("send: %v", err)
	}

	got, err := ss.Receive(ctx)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if len(got) != len(msg) {
		t.Fatalf("message boundary not restored: got %d bytes in one Receive, want %d", len(got), len(msg))
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("reassembled bytes differ from sent message")
	}
}

// TestAER099_MagicPrefixedSmallPayloadRoundTrips: over TCP a SMALL payload that
// starts with the bytes "FR" is ordinary data and must round-trip intact — not
// be read as a fragment header and lost or corrupted.
func TestAER099_MagicPrefixedSmallPayloadRoundTrips(t *testing.T) {
	client, server, cleanup := aer099NewPair(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cs, err := client.OpenStream(ctx, aether.StreamConfig{
		StreamID: 3, Reliability: aether.ReliableOrdered, Priority: 128,
	})
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	ss, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept stream: %v", err)
	}

	msg := append([]byte{0x46, 0x52}, []byte("small payload that starts with the FR magic")...)
	if err := cs.Send(ctx, msg); err != nil {
		t.Fatalf("send: %v", err)
	}

	got, err := ss.Receive(ctx)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("magic-prefixed payload corrupted: got %q, want %q", got, msg)
	}
}
