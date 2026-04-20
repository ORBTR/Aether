//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package adapter

import (
	"fmt"
	"net"

	"github.com/ORBTR/aether"
)

// NewSessionForProtocol creates the appropriate Aether session adapter
// for the given transport protocol. The conn must be the transport's
// native connection (already established and authenticated).
//
// Always takes SessionOptions. Every adapter honours opts end-to-end:
//
//   - Noise-UDP gets the full surface (FEC, compression, encryption,
//     MaxConcurrentStreams, SessionIdleTimeout, CongestionAlgo, etc.)
//   - TCP / WebSocket / gRPC / QUIC byte-stream adapters get the
//     non-UDP-specific surface (scheduler, header compression,
//     MaxConcurrentStreams, SessionIdleTimeout, StreamGC, abuse
//     scoring, malformed-frame validation)
//
// The agnostic `aether.AbuseScoreCapable` + `aether.IdleEvictable`
// interfaces are implemented by every session this factory returns.
// Numeric zero-values in opts are normalised to package defaults —
// start from aether.DefaultSessionOptions() when you want feature-
// flag bools enabled.
func NewSessionForProtocol(conn net.Conn, proto aether.Protocol,
	localNodeID, remoteNodeID aether.NodeID, opts aether.SessionOptions) (aether.Session, error) {

	switch proto {
	case aether.ProtoNoise:
		return NewNoiseSession(conn, localNodeID, remoteNodeID, opts), nil
	case aether.ProtoWebSocket:
		return NewWebSocketSession(conn, localNodeID, remoteNodeID, opts), nil
	case aether.ProtoQUIC:
		// QUIC via this factory is the byte-stream adapter path
		// (net.Conn-wrapped QUIC stream). For native QUIC
		// multiplexing, callers invoke NewQuicSession directly.
		return NewTCPSession(conn, localNodeID, remoteNodeID, aether.ProtoQUIC, opts), nil
	case aether.ProtoGRPC:
		return NewGrpcSession(conn, localNodeID, remoteNodeID, opts), nil
	default:
		// TCP/TLS and any unknown protocol use the TCP adapter.
		return NewTCPSession(conn, localNodeID, remoteNodeID, aether.ProtoTCP, opts), nil
	}
}

// NewSessionForProtocolString is the protocol-as-string convenience
// wrapper around NewSessionForProtocol. Takes the same opts.
func NewSessionForProtocolString(conn net.Conn, protoStr string,
	localNodeID, remoteNodeID aether.NodeID, opts aether.SessionOptions) (aether.Session, error) {

	proto := aether.ParseProtocol(protoStr)
	if proto == aether.ProtoUnknown {
		return nil, fmt.Errorf("aether adapter: unknown protocol %q", protoStr)
	}
	return NewSessionForProtocol(conn, proto, localNodeID, remoteNodeID, opts)
}
