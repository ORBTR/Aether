//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package adapter

import (
	"context"
	"fmt"
	"net"
	"os"
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
// TCP. See NewTCPSession for the opts semantics, and for remoteNodeID, which
// must be the identity the gRPC transport proved.
func NewGrpcSession(conn interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}, localNodeID, remoteNodeID aether.NodeID, opts aether.SessionOptions) *GrpcSession {
	return newGrpcSession(conn, localNodeID, remoteNodeID, opts, true)
}

// newGrpcSession is NewGrpcSession with newTCPSession's choice of per-peer
// memory ledger, which NewSessionForStatedPeer passes as false.
func newGrpcSession(conn interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}, localNodeID, remoteNodeID aether.NodeID, opts aether.SessionOptions, sharedPeer bool) *GrpcSession {
	wrapped := &grpcConnWrapper{conn: conn}
	return &GrpcSession{
		TCPSession: newTCPSession(wrapped, localNodeID, remoteNodeID, aether.ProtoGRPC, opts, sharedPeer),
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

func (w *grpcConnWrapper) Read(b []byte) (int, error)  { return w.conn.Read(b) }
func (w *grpcConnWrapper) Write(b []byte) (int, error) { return w.conn.Write(b) }
func (w *grpcConnWrapper) Close() error                { return w.conn.Close() }
func (w *grpcConnWrapper) LocalAddr() net.Addr         { return grpcAddr{} }
func (w *grpcConnWrapper) RemoteAddr() net.Addr        { return grpcAddr{} }

// The deadline methods hand t to the wrapped connection, whose Read and
// Write they bound. NewSessionForProtocol passes a net.Conn, so the
// deadlines are that connection's own. A connection that has no deadline
// method gets an error wrapping os.ErrNoDeadline: the wrapper cannot
// interrupt a Read or Write it does not own, and reporting success would
// leave the caller's Write unbounded.

func (w *grpcConnWrapper) SetDeadline(t time.Time) error {
	if d, ok := w.conn.(interface{ SetDeadline(time.Time) error }); ok {
		return d.SetDeadline(t)
	}
	return grpcNoDeadline("SetDeadline")
}

func (w *grpcConnWrapper) SetReadDeadline(t time.Time) error {
	if d, ok := w.conn.(interface{ SetReadDeadline(time.Time) error }); ok {
		return d.SetReadDeadline(t)
	}
	return grpcNoDeadline("SetReadDeadline")
}

func (w *grpcConnWrapper) SetWriteDeadline(t time.Time) error {
	if d, ok := w.conn.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return d.SetWriteDeadline(t)
	}
	return grpcNoDeadline("SetWriteDeadline")
}

func grpcNoDeadline(op string) error {
	return fmt.Errorf("adapter: grpc conn %s: %w", op, os.ErrNoDeadline)
}

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

	sends     sendGate // one sendFn runs at a time; see Send
	abandonMu sync.Mutex
	abandoned error // set once a Send returned before its sendFn did

	recvPending chan grpcRecv // the recvFn call a Receive left running; see Receive
}

// grpcRecv is what one recvFn call returned.
type grpcRecv struct {
	data []byte
	err  error
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

// Send hands data to sendFn, one Send at a time. sendFn takes no context,
// so under a ctx that can end, sendFn runs on its own copy of data and
// Send returns ctx's error if ctx ends first. That is how StreamConn's
// write deadline reaches this adapter. The abandoned sendFn keeps running
// and may still deliver the message, so the caller cannot tell whether it
// was sent; as with a net.Conn whose write timed out partway, every later
// Send fails, and the caller resets or closes the stream. A Send whose ctx
// has already ended never calls sendFn.
func (s *GrpcStreamAdapter) Send(ctx context.Context, data []byte) error {
	// Checked before the gate too: an abandoned sendFn still holds it.
	if err := s.sendRefusal(ctx); err != nil {
		return err
	}
	if err := s.sends.acquire(ctx); err != nil {
		return err
	}
	if err := s.sendRefusal(ctx); err != nil {
		s.sends.release()
		return err
	}
	if ctx.Done() == nil {
		defer s.sends.release()
		return s.sendFn(data)
	}
	msg := append([]byte(nil), data...)
	done := make(chan error, 1)
	go func() {
		done <- s.sendFn(msg)
		s.sends.release()
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
	}
	select {
	case err := <-done:
		return err
	default:
	}
	s.abandonMu.Lock()
	s.abandoned = fmt.Errorf("adapter: grpc stream %d: an earlier Send returned before its send function did, so its message may still be delivered: %w",
		s.streamID, ctx.Err())
	s.abandonMu.Unlock()
	return ctx.Err()
}

// sendRefusal is the error a Send returns without calling sendFn: ctx has
// ended, or an earlier Send was abandoned.
func (s *GrpcStreamAdapter) sendRefusal(ctx context.Context) error {
	s.abandonMu.Lock()
	err := s.abandoned
	s.abandonMu.Unlock()
	if err != nil {
		return err
	}
	return ctx.Err()
}

// Receive returns the next message recvFn yields. recvFn takes no context,
// so under a ctx that can end, recvFn runs on its own goroutine and Receive
// returns ctx's error if ctx ends first. That is how StreamConn's read
// deadline reaches this adapter. The recvFn left running still takes the
// next message off the stream, so its result is kept in recvPending and
// the next Receive waits for that call instead of making another: no
// message is lost, recvFn never runs twice at once, and the stream stays
// usable. A Receive whose ctx has already ended takes nothing. One
// goroutine calls Receive at a time, as StreamConn.Read does; recvPending
// has no lock.
func (s *GrpcStreamAdapter) Receive(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pending := s.recvPending
	if pending == nil {
		if ctx.Done() == nil {
			return s.recvFn()
		}
		pending = make(chan grpcRecv, 1)
		s.recvPending = pending
		go func() {
			data, err := s.recvFn()
			pending <- grpcRecv{data, err}
		}()
	}
	select {
	case r := <-pending:
		s.recvPending = nil
		return r.data, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *GrpcStreamAdapter) Close() error {
	recordStreamEvent(s.state, aether.EventSendFIN)
	if s.closeFn != nil {
		return s.closeFn()
	}
	return nil
}

func (s *GrpcStreamAdapter) Reset(reason aether.ResetReason) error {
	recordStreamEvent(s.state, aether.EventSendReset)
	return s.Close()
}

func (s *GrpcStreamAdapter) SetPriority(weight uint8, dependency uint64) {
	s.config.Priority = weight
	s.config.Dependency = dependency
}

var _ aether.Stream = (*GrpcStreamAdapter)(nil)
