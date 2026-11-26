/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package aether

import (
	"crypto/ed25519"
	"crypto/tls"
	"time"
)

// Config aggregates all transport protocol configurations.
// Nil sub-configs mean the protocol is disabled.
type Config struct {
	// Identity (required)
	NodeID     NodeID
	PrivateKey ed25519.PrivateKey

	// Protocol-specific configs (nil = disabled)
	Noise     *NoiseConfig
	QUIC      *QUICConfig
	WebSocket *WebSocketConfig
	GRPC      *GRPCConfig

	// Shared services
	STUN    STUNConfig
	Tickets *TicketConfig

	// Platform
	BindResolver BindAddressResolver // nil = use OS default bind addresses

	// WireVersions are the application's entries of the wire version offer
	// the transports built from this Config send in their handshakes, beside
	// aether's own (LocalWireVersions). noise.NewNoiseTransportFromConfig
	// passes them to the Noise transport.
	WireVersions WireVersions
}

// NoiseConfig configures the Noise VL1 transport.
type NoiseConfig struct {
	ListenAddr       string
	HandshakeTimeout time.Duration
	MaxPacketSize    int
	UDPReadBuffer    int
	UDPWriteBuffer   int
	NonceWindowSize  int
	HealthEMAAlpha   float64
	RekeyAfterBytes  uint64
	RekeyAfterDur    time.Duration
	RateLimitBurst   int
	RateLimitRate    int
	InboxSize        int // Per-session decrypted-packet inbox depth (default 128)
}

// QUICConfig configures the QUIC transport.
type QUICConfig struct {
	ListenAddr string
	Allow0RTT  bool
}

// WebSocketConfig configures the WebSocket transport. Its ping interval is the
// websocket package's own (pingInterval), and its pong deadline the keepalive plan
// the connection derives from its pings.
type WebSocketConfig struct {
	ListenAddr string
}

// GRPCConfig configures the gRPC transport.
// TLSConfig is optional; when nil, insecure credentials are used (dev/test only).
type GRPCConfig struct {
	ListenAddr string
	TLSConfig  *tls.Config
}

// TicketConfig configures session ticket resumption.
type TicketConfig struct {
	Enabled bool
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Noise: &NoiseConfig{
			ListenAddr:       ":41641",
			HandshakeTimeout: 5 * time.Second,
			MaxPacketSize:    64 * 1024,
			UDPReadBuffer:    4 * 1024 * 1024,
			UDPWriteBuffer:   2 * 1024 * 1024,
			NonceWindowSize:  64,
			HealthEMAAlpha:   0.2,
			RekeyAfterBytes:  1 << 30,
			RekeyAfterDur:    10 * time.Minute,
			RateLimitBurst:   100,
			RateLimitRate:    1000,
		},
		QUIC: &QUICConfig{
			// 0-RTT is off by default. The generic Connection.Send path
			// writes arbitrary caller payload as QUIC early data, which TLS
			// 0-RTT semantics allow an attacker to replay — unsafe for
			// non-idempotent RPC. Opt in explicitly only for idempotent early
			// data.
			Allow0RTT: false,
		},
		WebSocket: &WebSocketConfig{},
		GRPC:      &GRPCConfig{},
		STUN:      DefaultSTUNConfig(),
	}
}
