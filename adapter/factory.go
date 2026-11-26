//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
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
//
// remoteNodeID is the identity that authentication proved: the session it
// builds shares that node's per-peer ledgers (peerMemoryLedgers, and on Noise
// sessionPeerLedgers) with every other session to it. A caller that holds only
// a node ID the remote stated, with no proof of its key, builds the session
// through NewSessionForStatedPeer.
func NewSessionForProtocol(conn net.Conn, proto aether.Protocol,
	localNodeID, remoteNodeID aether.NodeID, opts aether.SessionOptions) (aether.Session, error) {
	return newSessionForProtocol(conn, proto, localNodeID, remoteNodeID, opts, true)
}

// NewSessionForStatedPeer is NewSessionForProtocol for a conn whose remote node
// ID is a label the remote stated (a header or a plaintext line) and no
// handshake proved. The session reports statedNodeID as its RemoteNodeID, and
// its per-peer ceilings are its own: it joins no other session's per-peer
// ledger, so a remote stating another node's ID cannot fill that node's room or
// send that node's streams a typed reset. Every other bound is
// NewSessionForProtocol's.
func NewSessionForStatedPeer(conn net.Conn, proto aether.Protocol,
	localNodeID, statedNodeID aether.NodeID, opts aether.SessionOptions) (aether.Session, error) {
	return newSessionForProtocol(conn, proto, localNodeID, statedNodeID, opts, false)
}

// newSessionForProtocol builds the adapter proto names. sharedPeer is the
// choice newNoiseSession and newTCPSession take: true joins remoteNodeID's
// per-peer ledgers, false gives the session ledgers of its own.
func newSessionForProtocol(conn net.Conn, proto aether.Protocol,
	localNodeID, remoteNodeID aether.NodeID, opts aether.SessionOptions, sharedPeer bool) (aether.Session, error) {

	switch proto {
	case aether.ProtoNoise:
		return newNoiseSession(conn, localNodeID, remoteNodeID, opts, sharedPeer), nil
	case aether.ProtoWebSocket:
		return newWebSocketSession(conn, localNodeID, remoteNodeID, opts, sharedPeer), nil
	case aether.ProtoQUIC:
		// QUIC via this factory is the byte-stream adapter path
		// (net.Conn-wrapped QUIC stream). For native QUIC
		// multiplexing, callers invoke NewQuicSession directly.
		return newTCPSession(conn, localNodeID, remoteNodeID, aether.ProtoQUIC, opts, sharedPeer), nil
	case aether.ProtoGRPC:
		return newGrpcSession(conn, localNodeID, remoteNodeID, opts, sharedPeer), nil
	default:
		// TCP/TLS and any unknown protocol use the TCP adapter.
		return newTCPSession(conn, localNodeID, remoteNodeID, aether.ProtoTCP, opts, sharedPeer), nil
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
