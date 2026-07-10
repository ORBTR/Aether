//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package quic

import (
	"context"
	"fmt"
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
	// AE-M-15: cap the read at MaxPayloadSize so a peer cannot stream
	// arbitrarily large data on a single uni-stream and OOM the process
	// (QUIC per-stream flow control only bounds in-flight bytes, not the
	// total io.ReadAll accumulates). Read one byte past the cap so an
	// over-limit stream is rejected rather than silently truncated. Mirrors
	// adapter/quic.go's length guard and adapter/noise_reliability.go's LimitReader.
	limited := io.LimitReader(stream, int64(aether.MaxPayloadSize)+1)
	payload, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(payload) > aether.MaxPayloadSize {
		return nil, fmt.Errorf("aether: quic payload too large (max %d bytes)", aether.MaxPayloadSize)
	}
	return payload, nil
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
