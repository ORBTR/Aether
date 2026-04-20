/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package websocket

import (
	"testing"

	"github.com/ORBTR/aether"
)

func TestWebsocketHeaderConstants(t *testing.T) {
	// Verify header constants are set correctly
	if NodeIDHeader == "" {
		t.Error("NodeIDHeader should not be empty")
	}
	if SignatureHeader == "" {
		t.Error("SignatureHeader should not be empty")
	}
	if NonceHeader == "" {
		t.Error("NonceHeader should not be empty")
	}

	// Verify they follow HTTP header naming convention
	expectedHeaders := map[string]string{
		"NodeIDHeader":    "X-HSTLES-NodeID",
		"SignatureHeader": "X-HSTLES-Signature",
		"NonceHeader":     "X-HSTLES-Nonce",
	}

	if NodeIDHeader != expectedHeaders["NodeIDHeader"] {
		t.Errorf("NodeIDHeader should be %s, got %s", expectedHeaders["NodeIDHeader"], NodeIDHeader)
	}
	if SignatureHeader != expectedHeaders["SignatureHeader"] {
		t.Errorf("SignatureHeader should be %s, got %s", expectedHeaders["SignatureHeader"], SignatureHeader)
	}
	if NonceHeader != expectedHeaders["NonceHeader"] {
		t.Errorf("NonceHeader should be %s, got %s", expectedHeaders["NonceHeader"], NonceHeader)
	}
}

func TestNewWebsocketTransport(t *testing.T) {
	cfg := WebsocketTransportConfig{
		LocalNode:  "test-node-id",
		PrivateKey: make([]byte, 64),
		ListenAddr: ":8080",
	}

	wt, err := NewWebsocketTransport(cfg)
	if err != nil {
		t.Fatalf("NewWebsocketTransport failed: %v", err)
	}
	if wt == nil {
		t.Fatal("NewWebsocketTransport returned nil")
	}
	if wt.localNode != cfg.LocalNode {
		t.Errorf("localNode mismatch: got %s, want %s", wt.localNode, cfg.LocalNode)
	}
	if wt.listenAddr != cfg.ListenAddr {
		t.Errorf("listenAddr mismatch: got %s, want %s", wt.listenAddr, cfg.ListenAddr)
	}
}

func TestWebsocketTransportConfigDefaults(t *testing.T) {
	cfg := WebsocketTransportConfig{
		LocalNode: "node-1",
		// Empty private key and listen addr
	}

	wt, err := NewWebsocketTransport(cfg)
	if err != nil {
		t.Fatalf("NewWebsocketTransport should not fail with minimal config: %v", err)
	}

	if wt.listenAddr != "" {
		t.Errorf("Default listenAddr should be empty, got %s", wt.listenAddr)
	}
}

func TestWebsocketListenerInterface(t *testing.T) {
	// Verify WebsocketListener implements aether.Listener
	var _ aether.Listener = (*WebsocketListener)(nil)
}
