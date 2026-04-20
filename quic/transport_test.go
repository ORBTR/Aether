//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package quic

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// generateTestKey creates a valid Ed25519 key pair for testing
func generateTestKey(t *testing.T) ed25519.PrivateKey {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}
	return priv
}

func TestQuicTransportConfigValidation(t *testing.T) {
	validKey := generateTestKey(t)

	tests := []struct {
		name      string
		cfg       QuicTransportConfig
		expectErr bool
	}{
		{
			name: "valid_config",
			cfg: QuicTransportConfig{
				LocalNode:  "test-node-id",
				PrivateKey: validKey,
				KeepAlive:  30 * time.Second,
				ListenAddr: ":8443",
			},
			expectErr: false,
		},
		{
			name: "invalid_key_short",
			cfg: QuicTransportConfig{
				LocalNode:  "test-node-id",
				PrivateKey: make([]byte, 32), // Too short
				KeepAlive:  30 * time.Second,
			},
			expectErr: true,
		},
		{
			name: "invalid_key_empty",
			cfg: QuicTransportConfig{
				LocalNode:  "test-node-id",
				PrivateKey: []byte{},
				KeepAlive:  30 * time.Second,
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewQuicTransport(tt.cfg)
			if tt.expectErr && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestQuicSessionInterface(t *testing.T) {
	// Verify QuicSession implements aether.Connection
	var _ aether.Connection = (*QuicSession)(nil)
}

func TestQuicListenerInterface(t *testing.T) {
	// Verify QuicListener implements aether.Listener
	var _ aether.Listener = (*QuicListener)(nil)
}

func TestQuicTransportInterface(t *testing.T) {
	// Verify QuicTransport implements the expected interface
	cfg := QuicTransportConfig{
		LocalNode:  "test-node",
		PrivateKey: generateTestKey(t),
	}
	qt, err := NewQuicTransport(cfg)
	if err != nil {
		t.Fatalf("NewQuicTransport failed: %v", err)
	}

	// Verify Close doesn't panic
	if err := qt.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}
}
