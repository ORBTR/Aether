//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package quic

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/quality"
)

// generateTestKey creates a valid Ed25519 key pair for testing
func generateTestKey(t *testing.T) ed25519.PrivateKey {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}
	return priv
}

// TestConnectionConfig_ComesFromTheKeepalivePlan: Dial and Listen's quic-go keepalive is
// the plan's Interval for a path with nothing measured, and the idle timeout is the
// longest DeadPeerBound any plan can hold: no plan the session keepalive derives from its
// own round trips, loss and stability is cut short by the connection going idle first,
// and the timeout is no longer than the longest of them.
func TestConnectionConfig_ComesFromTheKeepalivePlan(t *testing.T) {
	tr, err := NewQuicTransport(QuicTransportConfig{
		LocalNode:  "test-node-id",
		PrivateKey: generateTestKey(t),
	})
	if err != nil {
		t.Fatalf("new transport: %v", err)
	}
	plan := quality.Keepalive(quality.KeepaliveInputs{})
	got := tr.connectionConfig()
	if got.KeepAlivePeriod != plan.Interval {
		t.Fatalf("KeepAlivePeriod %v, want the plan's Interval %v", got.KeepAlivePeriod, plan.Interval)
	}
	var longest time.Duration
	for _, path := range []quality.KeepaliveInputs{
		{},
		{SRTT: time.Millisecond, RTO: 200 * time.Millisecond, Samples: 8},
		{SRTT: 4 * time.Second, RTO: 2 * time.Second, Samples: 20},
		{SRTT: time.Hour, RTO: time.Hour, Samples: 100},
	} {
		for step := 0; step <= 20; step++ {
			for _, instability := range []float64{0, 0.5, 1} {
				in := path
				in.Loss, in.Instability = float64(step)/20, instability
				bound := quality.Keepalive(in).DeadPeerBound()
				if got.MaxIdleTimeout < bound {
					t.Fatalf("MaxIdleTimeout %v ends a session whose plan (inputs %+v) holds its peer for %v", got.MaxIdleTimeout, in, bound)
				}
				if bound > longest {
					longest = bound
				}
			}
		}
	}
	if got.MaxIdleTimeout != longest {
		t.Fatalf("MaxIdleTimeout %v, want the longest DeadPeerBound a plan holds, %v", got.MaxIdleTimeout, longest)
	}
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
				ListenAddr: ":8443",
			},
			expectErr: false,
		},
		{
			name: "invalid_key_short",
			cfg: QuicTransportConfig{
				LocalNode:  "test-node-id",
				PrivateKey: make([]byte, 32), // Too short
			},
			expectErr: true,
		},
		{
			name: "invalid_key_empty",
			cfg: QuicTransportConfig{
				LocalNode:  "test-node-id",
				PrivateKey: []byte{},
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
