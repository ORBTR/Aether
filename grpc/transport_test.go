//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package grpc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

func TestGrpcTransportConfig(t *testing.T) {
	cfg := GrpcTransportConfig{
		LocalNode:  "test-node-id",
		PrivateKey: make([]byte, 64),
		ListenAddr: ":9000",
	}

	gt, err := NewGrpcTransport(cfg)
	if err != nil {
		t.Fatalf("NewGrpcTransport returned error: %v", err)
	}
	if gt == nil {
		t.Fatal("NewGrpcTransport returned nil")
	}
	if gt.localNode != cfg.LocalNode {
		t.Errorf("localNode mismatch: got %s, want %s", gt.localNode, cfg.LocalNode)
	}
	if gt.listenAddr != cfg.ListenAddr {
		t.Errorf("listenAddr mismatch: got %s, want %s", gt.listenAddr, cfg.ListenAddr)
	}
	if gt.incoming == nil {
		t.Error("incoming channel should be initialized")
	}
}

func TestGrpcMetadataConstants(t *testing.T) {
	// Verify metadata constants are set correctly
	if MetadataNodeID == "" {
		t.Error("MetadataNodeID should not be empty")
	}
	if MetadataSignature == "" {
		t.Error("MetadataSignature should not be empty")
	}
	// Verify they follow gRPC metadata naming convention (lowercase)
	if MetadataNodeID != "x-orbtr-nodeid" {
		t.Errorf("MetadataNodeID should be lowercase, got %s", MetadataNodeID)
	}
}

func TestGrpcSessionInterface(t *testing.T) {
	// Verify GrpcSession implements aether.Connection
	var _ aether.Connection = (*GrpcSession)(nil)
}

func TestGrpcListenerInterface(t *testing.T) {
	// Verify GrpcListener implements aether.Listener
	var _ aether.Listener = (*GrpcListener)(nil)
}

func TestNewGrpcTransportDefaults(t *testing.T) {
	cfg := GrpcTransportConfig{
		LocalNode: "node-1",
	}

	gt, err := NewGrpcTransport(cfg)
	if err != nil {
		t.Fatalf("NewGrpcTransport returned error: %v", err)
	}

	// Empty listen addr should be handled
	if gt.listenAddr != "" {
		t.Errorf("Default listenAddr should be empty, got %s", gt.listenAddr)
	}

	// Incoming channel should have buffer
	if cap(gt.incoming) != 32 {
		t.Errorf("incoming channel capacity should be 32, got %d", cap(gt.incoming))
	}
}

// grpcTestTransport is a transport whose NodeID is its own key's, as the
// server's auth interceptor requires of a dialing peer.
func grpcTestTransport(t *testing.T, listenAddr string) (*GrpcTransport, aether.NodeID) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	node, err := aether.NewNodeID(pub)
	if err != nil {
		t.Fatalf("NewNodeID: %v", err)
	}
	tr, err := NewGrpcTransport(GrpcTransportConfig{LocalNode: node, PrivateKey: priv, ListenAddr: listenAddr})
	if err != nil {
		t.Fatalf("NewGrpcTransport: %v", err)
	}
	return tr, node
}

// Dial returns a session only once the connection is ready, so the session
// reaches the listener's Accept with the dialer's NodeID.
func TestGrpcTransportDialReachesTheListener(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv, srvNode := grpcTestTransport(t, "127.0.0.1:0")
	ln, err := srv.Listen(ctx)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() {
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("listener Close: %v", err)
		}
	}()
	cli, cliNode := grpcTestTransport(t, "")
	conn, err := cli.Dial(ctx, aether.Target{NodeID: srvNode, Address: ln.Addr().String()})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Errorf("dialed session Close: %v", err)
		}
	}()
	acc, err := ln.Accept(ctx)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if got := acc.RemoteNodeID(); got != cliNode {
		t.Errorf("accepted session from %s, want the dialer %s", got, cliNode)
	}
	if err := acc.Close(); err != nil {
		t.Errorf("accepted session Close: %v", err)
	}
}

// Dial to an address nothing listens on fails when its context ends, instead
// of returning a session over a client that never connects.
func TestGrpcTransportDialFailsWhenNothingListens(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := lis.Addr().String()
	if err := lis.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	cli, _ := grpcTestTransport(t, "")
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	conn, err := cli.Dial(ctx, aether.Target{NodeID: "vl1_nobody", Address: addr})
	if err == nil {
		_ = conn.Close()
		t.Fatal("Dial to a closed port returned a session")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Dial to a closed port: %v, want the context's deadline", err)
	}
}
