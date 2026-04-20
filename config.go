/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
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
	Noise *NoiseConfig
	QUIC      *QUICConfig
	WebSocket *WebSocketConfig
	GRPC      *GRPCConfig

	// Shared services
	STUN    STUNConfig
	Health  HealthConfig
	Tickets *TicketConfig

	// Platform
	BindResolver BindAddressResolver // nil = use OS default bind addresses
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
	KeepAlive  time.Duration
	Allow0RTT  bool
}

// WebSocketConfig configures the WebSocket transport.
type WebSocketConfig struct {
	ListenAddr   string
	PingInterval time.Duration
}

// GRPCConfig configures the gRPC transport.
// TLSConfig is optional; when nil, insecure credentials are used (dev/test only).
type GRPCConfig struct {
	ListenAddr string
	TLSConfig  *tls.Config
}

// HealthConfig configures session health monitoring.
type HealthConfig struct {
	PingInterval   time.Duration
	SuspectTimeout time.Duration
	DeadTimeout    time.Duration
	MaxMissedPings int
	EMAAlpha       float64
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
			KeepAlive: 15 * time.Second,
			Allow0RTT: true,
		},
		WebSocket: &WebSocketConfig{
			PingInterval: 10 * time.Second,
		},
		GRPC: &GRPCConfig{},
		STUN: DefaultSTUNConfig(),
		Health: HealthConfig{
			PingInterval:   5 * time.Second,
			SuspectTimeout: 10 * time.Second,
			DeadTimeout:    20 * time.Second,
			MaxMissedPings: 3,
			EMAAlpha:       0.2,
		},
	}
}
