//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
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
// WebSocket uses the TCP-family adapter under the hood.
func NewWebSocketSession(conn net.Conn, localNodeID, remoteNodeID aether.NodeID, opts aether.SessionOptions) *WebSocketSession {
	tcp := NewTCPSession(conn, localNodeID, remoteNodeID, aether.ProtoWebSocket, opts)
	return &WebSocketSession{TCPSession: tcp, proto: aether.ProtoWebSocket}
}

// Ensure interface compliance at compile time.
var _ aether.Session = (*WebSocketSession)(nil)
