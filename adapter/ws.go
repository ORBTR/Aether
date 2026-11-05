//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"net"

	"github.com/ORBTR/aether"
)

// WebSocketSession implements Session over a WebSocket connection.
// WebSocket provides reliable, ordered delivery (TCP underneath) with
// message framing. Structurally identical to TCPSession — both carry
// full Aether frames over a single reliable connection.
//
// Aether provides: frame codec, stream multiplexing, priority scheduler, flow control.
// WS/TCP provides: reliability, ordering, congestion control, encryption (TLS).
type WebSocketSession struct {
	*TCPSession // embed TCPSession — identical behavior
	proto       aether.Protocol
}

// NewWebSocketSession creates an Aether session over a WebSocket
// connection. The conn parameter should be a websocket.WSConn which
// implements net.Conn. See NewTCPSession for the opts semantics —
// WebSocket uses the TCP-family adapter under the hood. remoteNodeID must
// be the identity the WebSocket transport proved, as NewTCPSession states.
func NewWebSocketSession(conn net.Conn, localNodeID, remoteNodeID aether.NodeID, opts aether.SessionOptions) *WebSocketSession {
	return newWebSocketSession(conn, localNodeID, remoteNodeID, opts, true)
}

// newWebSocketSession is NewWebSocketSession with newTCPSession's choice of
// per-peer memory ledger, which NewSessionForStatedPeer passes as false.
func newWebSocketSession(conn net.Conn, localNodeID, remoteNodeID aether.NodeID, opts aether.SessionOptions, sharedPeer bool) *WebSocketSession {
	tcp := newTCPSession(conn, localNodeID, remoteNodeID, aether.ProtoWebSocket, opts, sharedPeer)
	return &WebSocketSession{TCPSession: tcp, proto: aether.ProtoWebSocket}
}

// Ensure interface compliance at compile time.
var _ aether.Session = (*WebSocketSession)(nil)
