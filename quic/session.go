//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package quic

import (
	"context"
	"io"
	"net"

	"github.com/ORBTR/aether"
	"github.com/quic-go/quic-go"
)

// QuicSession implements aether.Session for QUIC.
type QuicSession struct {
	localNode  aether.NodeID
	remoteNode aether.NodeID
	conn       quic.Connection
}

// NewQuicSession creates a new QUIC session.
func NewQuicSession(localNode, remoteNode aether.NodeID, conn quic.Connection) *QuicSession {
	return &QuicSession{
		localNode:  localNode,
		remoteNode: remoteNode,
		conn:       conn,
	}
}

// NetConn returns a net.Conn adapter for protocol-agnostic mux negotiation.
// Wraps the QUIC session in a ConnectionConn since QUIC doesn't have a raw net.Conn.
func (s *QuicSession) NetConn() net.Conn { return aether.NewConnectionConn(s) }

// Send transmits a payload by opening a new unidirectional stream.
func (s *QuicSession) Send(ctx context.Context, payload []byte) error {
	stream, err := s.conn.OpenUniStreamSync(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()

	_, err = stream.Write(payload)
	return err
}

// Receive waits for a payload by accepting a unidirectional stream.
func (s *QuicSession) Receive(ctx context.Context) ([]byte, error) {
	stream, err := s.conn.AcceptUniStream(ctx)
	if err != nil {
		return nil, err
	}
	// No need to close read side of uni stream, but good practice to read until EOF
	return io.ReadAll(stream)
}

// Close terminates the session.
func (s *QuicSession) Close() error {
	return s.conn.CloseWithError(0, "closed")
}

// RemoteAddr returns the remote address.
func (s *QuicSession) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}

// RemoteNodeID returns the ID of the connected peer.
func (s *QuicSession) RemoteNodeID() aether.NodeID {
	return s.remoteNode
}

func (s *QuicSession) Protocol() aether.Protocol { return aether.ProtoQUIC }
func (s *QuicSession) OnClose(fn func()) { /* QUIC handles lifecycle */ }
