/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import (
	"context"
	"crypto/ed25519"
	"net"
	"sync"
	"time"
)

// BaseConnection implements the Session interface wrapping a connection.
type BaseConnection struct {
	localNode  NodeID
	remoteNode NodeID
	Conn       net.Conn
	proto      Protocol
	mu         sync.Mutex
	// onCloseFns is a slice so multiple independent consumers (stream GC,
	// session multipath promoter, metrics subscribers) can all register
	// teardown callbacks without clobbering each other. A single func()
	// field would let a second registration silently overwrite the first.
	onCloseFns []func()
	initialRTT time.Duration // TCP handshake / dial RTT for cross-region latency

	// pendingRead preserves an in-flight fallback Read across a cancelled
	// Receive (AER-050). When Receive's ctx fires while the read goroutine is
	// still blocked in Conn.Read, the goroutine's eventual result is kept here
	// so the NEXT Receive consumes it instead of the orphaned read swallowing
	// and discarding that inbound message. Guarded by readMu.
	readMu      sync.Mutex
	pendingRead chan readResult
}

type readResult struct {
	data []byte
	err  error
}

// Protocol returns the transport protocol.
func (s *BaseConnection) Protocol() Protocol { return s.proto }

// NewConnection creates a new BaseConnection. AER-058: pass the transport
// protocol so Connection.Protocol() reports the real transport instead of
// ProtoUnknown (which collapsed any protocol-grade fallback / capability
// lookup keyed on it). The variadic parameter keeps older call sites
// compiling; transports should always supply their protocol.
func NewConnection(localNode, remoteNode NodeID, conn net.Conn, proto ...Protocol) *BaseConnection {
	p := ProtoUnknown
	if len(proto) > 0 {
		p = proto[0]
	}
	return &BaseConnection{
		localNode:  localNode,
		remoteNode: remoteNode,
		Conn:       conn,
		proto:      p,
	}
}

// NetConn returns the underlying net.Conn for protocol-agnostic mux negotiation.
// Implements ConnProvider interface.
func (s *BaseConnection) NetConn() net.Conn { return s.Conn }

// Send transmits a payload.
func (s *BaseConnection) Send(ctx context.Context, payload []byte) error {
	_, err := s.Conn.Write(payload)
	return err
}

// ContextReader allows reading with context support.
type ContextReader interface {
	ReadContext(ctx context.Context, p []byte) (int, error)
}

// Receive waits for a payload, respecting context cancellation.
func (s *BaseConnection) Receive(ctx context.Context) ([]byte, error) {
	buf := make([]byte, 4096) // Default buffer size, might need adjustment

	// Check if the connection supports context-aware reading
	if cr, ok := s.Conn.(ContextReader); ok {
		n, err := cr.ReadContext(ctx, buf)
		if err != nil {
			return nil, err
		}
		return buf[:n], nil
	}

	// Fallback: a goroutine performs the blocking Read. AER-050: reuse a
	// still-running read from a previously cancelled Receive so a cancelled
	// call doesn't orphan a Read that then swallows and discards the next
	// inbound message. The read goroutine owns its own buffer, so nothing
	// aliases across calls.
	s.readMu.Lock()
	ch := s.pendingRead
	if ch == nil {
		ch = make(chan readResult, 1)
		s.pendingRead = ch
		go func(out chan<- readResult) {
			rbuf := make([]byte, 4096)
			n, err := s.Conn.Read(rbuf)
			out <- readResult{data: rbuf[:n], err: err}
		}(ch)
	}
	s.readMu.Unlock()

	select {
	case <-ctx.Done():
		// Leave pendingRead set — the goroutine is still running and its
		// result will be consumed by the next Receive, not lost.
		return nil, ctx.Err()
	case r := <-ch:
		s.readMu.Lock()
		s.pendingRead = nil
		s.readMu.Unlock()
		if r.err != nil {
			return nil, r.err
		}
		return r.data, nil
	}
}

// Close terminates the session. Invokes every registered OnClose callback
// in the order they were registered. A panic in one callback does not
// prevent later callbacks from running, so a broken subscriber can't break
// a later subscriber's teardown.
func (s *BaseConnection) Close() error {
	s.mu.Lock()
	fns := s.onCloseFns
	s.onCloseFns = nil
	s.mu.Unlock()
	for _, fn := range fns {
		func() {
			defer func() { _ = recover() }()
			fn()
		}()
	}
	return s.Conn.Close()
}

// RemoteAddr returns the remote address.
func (s *BaseConnection) RemoteAddr() net.Addr {
	return s.Conn.RemoteAddr()
}

// RemoteNodeID returns the ID of the connected peer.
func (s *BaseConnection) RemoteNodeID() NodeID {
	return s.remoteNode
}

// RemoteIdentity returns the peer's verified ed25519 identity public key when
// the wrapped conn exposes one (e.g. the noise transport's noiseConn, which
// captures it from the handshake NodeInfo verification). Returns nil when the
// underlying conn does not carry a verified identity. Forwarded via an
// interface assertion — deliberately NOT part of the exported Connection
// interface — so consumers holding the aether.Connection can type-assert
// interface{ RemoteIdentity() ed25519.PublicKey } and obtain the key.
func (s *BaseConnection) RemoteIdentity() ed25519.PublicKey {
	if ri, ok := s.Conn.(interface {
		RemoteIdentity() ed25519.PublicKey
	}); ok {
		return ri.RemoteIdentity()
	}
	return nil
}

// SetInitialRTT records the dial/handshake RTT measured during connection establishment.
func (s *BaseConnection) SetInitialRTT(d time.Duration) { s.initialRTT = d }

// InitialRTT returns the dial/handshake RTT. Returns 0 if not measured.
func (s *BaseConnection) InitialRTT() time.Duration { return s.initialRTT }

// OnClose registers a callback to be invoked when the session is closed.
// Multiple registrations are supported — every registered callback fires,
// in the order they were registered. Nil is ignored.
func (s *BaseConnection) OnClose(f func()) {
	if f == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onCloseFns = append(s.onCloseFns, f)
}

// Read implements io.Reader
func (s *BaseConnection) Read(p []byte) (n int, err error) {
	return s.Conn.Read(p)
}

// Write implements io.Writer
func (s *BaseConnection) Write(p []byte) (n int, err error) {
	return s.Conn.Write(p)
}

// --- Health interface forwarding ---
// BaseConnection delegates HealthReporter and Pingable to the inner Conn
// if it supports those interfaces. This allows session_health.go to
// type-assert on BaseConnection and reach the underlying noiseConn's health.

// Compile-time checks: BaseConnection satisfies health interfaces when Conn supports them.
// These verify the forwarding methods exist with correct signatures.
var _ HealthReporter = (*BaseConnection)(nil)
var _ Pingable = (*BaseConnection)(nil)

func (s *BaseConnection) SendPing() (uint32, error) {
	if p, ok := s.Conn.(Pingable); ok {
		return p.SendPing()
	}
	return 0, ErrSessionClosed
}

func (s *BaseConnection) IncrementMissedPings() int {
	if p, ok := s.Conn.(Pingable); ok {
		return p.IncrementMissedPings()
	}
	return 0
}

func (s *BaseConnection) LastActivity() time.Time {
	if hr, ok := s.Conn.(HealthReporter); ok {
		return hr.LastActivity()
	}
	return time.Time{}
}

func (s *BaseConnection) RTT() (last, avg time.Duration) {
	if hr, ok := s.Conn.(HealthReporter); ok {
		return hr.RTT()
	}
	return 0, 0
}

func (s *BaseConnection) IsAlive(timeout time.Duration) bool {
	if hr, ok := s.Conn.(HealthReporter); ok {
		return hr.IsAlive(timeout)
	}
	return false
}

func (s *BaseConnection) MissedPings() int {
	if hr, ok := s.Conn.(HealthReporter); ok {
		return hr.MissedPings()
	}
	return 0
}

func (s *BaseConnection) LastPongReceived() time.Time {
	if hr, ok := s.Conn.(HealthReporter); ok {
		return hr.LastPongReceived()
	}
	return time.Time{}
}

func (s *BaseConnection) IsClosed() bool {
	if hr, ok := s.Conn.(HealthReporter); ok {
		return hr.IsClosed()
	}
	return false
}
