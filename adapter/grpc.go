//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package adapter

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/ORBTR/aether"
)

// GrpcSession implements Session over a gRPC connection.
// gRPC provides native bidi streaming, reliability, flow control (HTTP/2),
// congestion control, and TLS encryption. Like QUIC, the adapter maps
// Aether operations to gRPC operations with minimal overhead.
//
// Aether provides: stream lifecycle semantics only.
// gRPC provides: EVERYTHING ELSE via HTTP/2.
//
// Since gRPC doesn't expose raw bidirectional streams like QUIC does,
// this adapter multiplexes Aether streams over a single gRPC bidi stream
// using the Aether frame codec. This is necessary because gRPC's streaming
// model (client→server or bidi on a single RPC) doesn't map cleanly to
// arbitrary dynamic stream creation.
type GrpcSession struct {
	// gRPC sessions use the TCPSession internally because gRPC exposes
	// a net.Conn-like interface via its aether. The gRPC HTTP/2 framing
	// carries Aether frames as payload.
	*TCPSession
	proto aether.Protocol
}

// NewGrpcSession creates an Aether session over a gRPC connection's net.Conn.
// gRPC provides HTTP/2 reliability, flow control, and TLS — the adapter only
// adds Aether stream lifecycle semantics (same as TCP/WS adapters).
// The conn must be extracted from the gRPC transport (e.g., via peer.FromContext).
// NewGrpcSession creates an Aether gRPC session with the caller-
// supplied SessionOptions. gRPC sessions use TCPSession internally
// since gRPC's HTTP/2 provides the same reliable stream semantics as
// TCP. See NewTCPSession for the opts semantics.
func NewGrpcSession(conn interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}, localNodeID, remoteNodeID aether.NodeID, opts aether.SessionOptions) *GrpcSession {
	wrapped := &grpcConnWrapper{conn: conn}
	return &GrpcSession{
		TCPSession: NewTCPSession(wrapped, localNodeID, remoteNodeID, aether.ProtoGRPC, opts),
		proto:      aether.ProtoGRPC,
	}
}

// grpcConnWrapper wraps a gRPC connection's read/write/close interface as net.Conn.
type grpcConnWrapper struct {
	conn interface {
		Read([]byte) (int, error)
		Write([]byte) (int, error)
		Close() error
	}
}

func (w *grpcConnWrapper) Read(b []byte) (int, error)         { return w.conn.Read(b) }
func (w *grpcConnWrapper) Write(b []byte) (int, error)        { return w.conn.Write(b) }
func (w *grpcConnWrapper) Close() error                       { return w.conn.Close() }
func (w *grpcConnWrapper) LocalAddr() net.Addr                { return grpcAddr{} }
func (w *grpcConnWrapper) RemoteAddr() net.Addr               { return grpcAddr{} }
func (w *grpcConnWrapper) SetDeadline(t time.Time) error      { return nil }
func (w *grpcConnWrapper) SetReadDeadline(t time.Time) error  { return nil }
func (w *grpcConnWrapper) SetWriteDeadline(t time.Time) error { return nil }

type grpcAddr struct{}

func (grpcAddr) Network() string { return "grpc" }
func (grpcAddr) String() string  { return "grpc" }

// GrpcStreamAdapter wraps a gRPC send/recv interface as an Aether stream.
// This is used when gRPC bidi streams ARE available (e.g., custom RPC service).
type GrpcStreamAdapter struct {
	streamID uint64
	config   aether.StreamConfig
	state    *aether.StreamStateMachine
	sendFn   func([]byte) error
	recvFn   func() ([]byte, error)
	closeFn  func() error
	connOnce sync.Once
	connView net.Conn
}

// NewGrpcStreamAdapter creates an Aether stream from gRPC send/recv functions.
func NewGrpcStreamAdapter(streamID uint64, cfg aether.StreamConfig,
	send func([]byte) error, recv func() ([]byte, error), close func() error) *GrpcStreamAdapter {
	return &GrpcStreamAdapter{
		streamID: streamID,
		config:   cfg,
		state:    aether.NewStreamStateMachine(),
		sendFn:   send,
		recvFn:   recv,
		closeFn:  close,
	}
}

func (s *GrpcStreamAdapter) StreamID() uint64            { return s.streamID }
func (s *GrpcStreamAdapter) Config() aether.StreamConfig { return s.config }
func (s *GrpcStreamAdapter) IsOpen() bool                { return s.state.IsOpen() }

func (s *GrpcStreamAdapter) Conn() net.Conn {
	s.connOnce.Do(func() { s.connView = NewStreamConn(s) })
	return s.connView
}

func (s *GrpcStreamAdapter) Send(ctx context.Context, data []byte) error {
	return s.sendFn(data)
}

func (s *GrpcStreamAdapter) Receive(ctx context.Context) ([]byte, error) {
	return s.recvFn()
}

func (s *GrpcStreamAdapter) Close() error {
	s.state.Transition(aether.EventSendFIN)
	if s.closeFn != nil {
		return s.closeFn()
	}
	return nil
}

func (s *GrpcStreamAdapter) Reset(reason aether.ResetReason) error {
	s.state.Transition(aether.EventSendReset)
	return s.Close()
}

func (s *GrpcStreamAdapter) SetPriority(weight uint8, dependency uint64) {
	s.config.Priority = weight
	s.config.Dependency = dependency
}

var _ aether.Stream = (*GrpcStreamAdapter)(nil)
