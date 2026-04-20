/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package adapter

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/ORBTR/aether"
)

// StreamConn bridges an Aether Stream to the net.Conn interface.
// This is the single canonical net.Conn adapter for Aether streams, used by
// gossip, PingableConn, and any consumer that needs byte-stream semantics
// over Aether's message-oriented streams.
//
// Key capabilities:
//   - Read/Write with message-to-byte-stream buffering (partial reads)
//   - SetDeadline creates per-call context.WithDeadline for timeout support
//   - Parent context propagation (cancelled when connection dies)
//   - StreamID accessor for debug logging
//   - net.Conn compliant (verified by interface assertion)
type StreamConn struct {
	stream     aether.Stream
	parentCtx  context.Context
	readCtx    context.Context    // per-exchange deadline context
	readCancel context.CancelFunc // cancels readCtx
	buf        []byte             // read buffer for partial message reads
}

// Ensure net.Conn compliance at compile time.
var _ net.Conn = (*StreamConn)(nil)

// NewStreamConn creates a net.Conn wrapper around an Aether Stream.
// The parent context controls the connection lifetime — when cancelled,
// all blocked Read/Write operations return immediately.
// If no parent context is provided, context.Background() is used.
func NewStreamConn(stream aether.Stream, parentCtx ...context.Context) *StreamConn {
	ctx := context.Background()
	if len(parentCtx) > 0 && parentCtx[0] != nil {
		ctx = parentCtx[0]
	}
	return &StreamConn{
		stream:    stream,
		parentCtx: ctx,
	}
}

// Read implements net.Conn. Reads data from the Aether stream.
// Aether streams are message-oriented (Receive returns a complete message).
// This method buffers partial reads so callers can use io.ReadFull and
// other byte-stream patterns.
//
// Uses readCtx (set by SetDeadline) if available, otherwise parentCtx.
// Not concurrent-safe — callers must not call Read from multiple goroutines.
func (c *StreamConn) Read(p []byte) (int, error) {
	// Return buffered data from a previous oversized Receive
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}

	ctx := c.activeCtx()
	data, err := c.stream.Receive(ctx)
	if err != nil {
		return 0, err
	}

	n := copy(p, data)
	if n < len(data) {
		c.buf = data[n:]
	}
	return n, nil
}

// Write implements net.Conn. Sends data on the Aether stream as a single message.
// On Aether, Send() enqueues to the scheduler and returns immediately (non-blocking
// for TCP/WS). For Noise-UDP, flow control may block until credit is available.
func (c *StreamConn) Write(p []byte) (int, error) {
	ctx := c.activeCtx()
	if err := c.stream.Send(ctx, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close cancels any active deadline and closes the underlying Aether stream.
func (c *StreamConn) Close() error {
	if c.readCancel != nil {
		c.readCancel()
		c.readCancel = nil
		c.readCtx = nil
	}
	return c.stream.Close()
}

// SetDeadline creates a per-exchange context with the given deadline.
// When the deadline fires, any blocked Read (stream.Receive) is cancelled.
// This prevents goroutine leaks when callers use concurrent read patterns
// with timeout-based fallback (e.g., GossipOverConn).
//
// Pass time.Time{} (zero) to clear the deadline and revert to parentCtx.
func (c *StreamConn) SetDeadline(t time.Time) error {
	// Cancel any previous deadline
	if c.readCancel != nil {
		c.readCancel()
	}
	// Flush stale read buffer from any previous failed exchange.
	// Without this, a partial payload from a timed-out exchange remains
	// in buf and is read as the next exchange's magic header — causing
	// "invalid magic 0xXXXX" errors (JSON fragments misread as headers).
	c.buf = nil
	if t.IsZero() {
		c.readCtx = nil
		c.readCancel = nil
		return nil
	}
	c.readCtx, c.readCancel = context.WithDeadline(c.parentCtx, t)
	return nil
}

// SetReadDeadline delegates to SetDeadline (same context for both).
func (c *StreamConn) SetReadDeadline(t time.Time) error { return c.SetDeadline(t) }

// SetWriteDeadline is a no-op — Aether writes enqueue to the scheduler and
// return immediately on TCP/WS. Noise-UDP flow control has its own timeout.
func (c *StreamConn) SetWriteDeadline(t time.Time) error { return nil }

// LocalAddr implements net.Conn with a placeholder Aether address.
func (c *StreamConn) LocalAddr() net.Addr {
	return streamConnAddr{fmt.Sprintf("aether-stream-%d-local", c.stream.StreamID())}
}

// RemoteAddr implements net.Conn with a placeholder Aether address.
func (c *StreamConn) RemoteAddr() net.Addr {
	return streamConnAddr{fmt.Sprintf("aether-stream-%d-remote", c.stream.StreamID())}
}

// StreamID returns the underlying Aether stream ID for debug logging.
func (c *StreamConn) StreamID() uint64 { return c.stream.StreamID() }

// AvailableCredit returns the send-side flow-control credit currently
// available on the underlying stream, or -1 if the stream doesn't expose
// flow control (e.g. QUIC, which has its own native flow control and
// bypasses the Aether credit layer).
//
// Callers (notably gossip) use this to self-throttle: when credit is low,
// prefer a delta sync over a full sync to avoid guaranteed ConsumeTimeout
// stalls. This is an agnostic check — any stream type that exposes an
// `AvailableCredit() int64` method via the underlying adapter is picked up.
func (c *StreamConn) AvailableCredit() int64 {
	type avail interface{ AvailableCredit() int64 }
	if a, ok := c.stream.(avail); ok {
		return a.AvailableCredit()
	}
	return -1
}

// ParentContext returns the connection-level context. Useful for callers
// that need to derive sub-contexts tied to the connection lifetime.
func (c *StreamConn) ParentContext() context.Context { return c.parentCtx }

// activeCtx returns readCtx if a deadline is set, otherwise parentCtx.
func (c *StreamConn) activeCtx() context.Context {
	if c.readCtx != nil {
		return c.readCtx
	}
	return c.parentCtx
}

// streamConnAddr implements net.Addr for StreamConn.
type streamConnAddr struct{ s string }

func (a streamConnAddr) Network() string { return "aether" }
func (a streamConnAddr) String() string  { return a.s }
