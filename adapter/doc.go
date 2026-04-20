/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

// Package adapter provides transport-specific implementations of the Aether
// session interface. Each adapter maps Aether semantics to a transport's native
// capabilities:
//
//   - TCP/TLS: Full Aether framing over a single net.Conn (reliability, flow control, mux)
//   - WebSocket: Aether frames as WS binary messages (reliability from TCP, Aether mux)
//   - QUIC: Aether streams mapped to native QUIC streams (skip reliability/flow/mux)
//   - gRPC: Aether streams mapped to bidi gRPC streams (skip reliability/flow/mux)
//   - Noise-UDP: Full Aether stack (reliability, FEC, congestion, flow control, mux)
//
// Bridge adapters integrate Aether with existing consumers:
//   - StreamConn: Bridges an Aether Stream to net.Conn for consumers requiring net.Conn interface.
package adapter
