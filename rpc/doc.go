/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
// Package rpc provides RPC-over-VL1 transport using protobuf serialization.
//
// Protobuf-encoded RPC with length-prefixed framing.
//   - Faster serialization (2-5x vs JSON)
//   - Smaller payloads (50-70% reduction)
//   - Lower latency over VL1 (UDP + Noise)
//   - Connection multiplexing support
//
// Architecture:
//
//	External Clients (HTTP+JSON) → HTTP Bridge → Protobuf → Handler
//	Internal Clients (gRPC+Protobuf) → VL1 Direct → Protobuf → Handler
//
// The RPCServer handles incoming sessions via streams
// (ServeAetherStream), routing requests through HandlerRegistry with
// intelligent load-aware forwarding.
//
// Wire Protocol:
//
//	[4-byte length (BigEndian)][protobuf bytes]
//
// Usage (Client — direct-dial fallback):
//
//	client := rpc.NewClient(session)
//	resp, err := client.Call(ctx, "identity.getUser", payload, metadata)
package rpc
