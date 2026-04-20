/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package aether

import (
	"fmt"
	"strings"
)

// Capabilities is a bitfield describing what a transport natively provides.
// Aether adapters use this to skip redundant protocol layers.
// For example, QUIC provides native reliability, flow control, and congestion control —
// the Aether reliability engine is not used over QUIC.
type Capabilities uint32

const (
	// CapNativeReliability means the transport guarantees delivery (TCP, QUIC, WS).
	// When set, the Aether reliability engine (retransmit, SACK) is skipped.
	CapNativeReliability Capabilities = 1 << 0

	// CapNativeFlowControl means the transport provides flow control (QUIC, gRPC).
	// When set, Aether WINDOW_UPDATE frames are not used.
	CapNativeFlowControl Capabilities = 1 << 1

	// CapNativeCongestion means the transport provides congestion control (TCP, QUIC).
	// When set, Aether CUBIC/BBR is not used.
	CapNativeCongestion Capabilities = 1 << 2

	// CapNativeEncryption means the transport encrypts data (Noise, TLS, QUIC).
	// When set, the ENCRYPTED flag in Aether frames is not needed (unless relaying).
	CapNativeEncryption Capabilities = 1 << 3

	// CapNativeMux means the transport provides native stream multiplexing (QUIC, gRPC).
	// When set, Aether maps streams to native streams instead of framing over a single conn.
	CapNativeMux Capabilities = 1 << 4

	// CapNativeOrdering means the transport guarantees in-order delivery (TCP, QUIC streams).
	// When set, the Aether reorder buffer is not used.
	CapNativeOrdering Capabilities = 1 << 5

	// CapNativeIdentity means the transport authenticates peers (Noise static key, TLS certs).
	// When set, SenderID/ReceiverID in Aether frames are informational, not for auth.
	CapNativeIdentity Capabilities = 1 << 6

	// CapFEC means FEC is enabled for this session (typically Noise-UDP only).
	CapFEC Capabilities = 1 << 7

	// CapCompression means DEFLATE compression is available.
	CapCompression Capabilities = 1 << 8

	// CapMigration means connection migration is supported (QUIC natively, others via Aether).
	CapMigration Capabilities = 1 << 9
)

// Has returns true if the capability is set.
func (c Capabilities) Has(cap Capabilities) bool {
	return c&cap != 0
}

// String returns a human-readable list of capabilities.
func (c Capabilities) String() string {
	var parts []string
	names := []struct {
		cap  Capabilities
		name string
	}{
		{CapNativeReliability, "reliability"},
		{CapNativeFlowControl, "flow-control"},
		{CapNativeCongestion, "congestion"},
		{CapNativeEncryption, "encryption"},
		{CapNativeMux, "mux"},
		{CapNativeOrdering, "ordering"},
		{CapNativeIdentity, "identity"},
		{CapFEC, "fec"},
		{CapCompression, "compression"},
		{CapMigration, "migration"},
	}
	for _, n := range names {
		if c.Has(n.cap) {
			parts = append(parts, n.name)
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return fmt.Sprintf("[%s]", strings.Join(parts, ", "))
}

// CapabilitiesForProtocol returns the native capabilities for a given transport protocol.
// This determines which Aether layers are activated vs skipped for each
func CapabilitiesForProtocol(proto Protocol) Capabilities {
	switch proto {
	case ProtoNoise:
		// Noise-UDP: encryption + identity only. Everything else is Aether's job.
		return CapNativeEncryption | CapNativeIdentity | CapFEC | CapCompression

	case ProtoQUIC:
		// QUIC: everything native except FEC and Aether-level encryption for relay.
		return CapNativeReliability | CapNativeFlowControl | CapNativeCongestion |
			CapNativeEncryption | CapNativeMux | CapNativeOrdering |
			CapNativeIdentity | CapCompression | CapMigration

	case ProtoWebSocket, ProtoTCP:
		// WebSocket / TCP+TLS: reliability + ordering from TCP. Encryption from TLS.
		// No native mux, flow control, or congestion control.
		return CapNativeReliability | CapNativeOrdering | CapNativeEncryption |
			CapNativeIdentity | CapCompression

	case ProtoGRPC:
		// gRPC: full native stack via HTTP/2.
		return CapNativeReliability | CapNativeFlowControl | CapNativeCongestion |
			CapNativeEncryption | CapNativeMux | CapNativeOrdering |
			CapNativeIdentity | CapCompression

	default:
		return 0
	}
}
