/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package aether

import (
	"context"
	"io"
	"net"
	"sync"
	"time"
)

// ConnectionConn wraps a transport.Session as a net.Conn for byte-stream consumers.
// Bridges the Send/Receive API to Read/Write for sessions that don't
// natively expose a net.Conn (QUIC, gRPC).
type ConnectionConn struct {
	conn  Connection
	buf      []byte
	mu       sync.Mutex
	closed   bool
	deadline time.Time
}

// NewConnectionConn wraps any Session into a net.Conn.
// For BaseConnection, prefer using BaseConnection.Conn directly (zero overhead).
func NewConnectionConn(conn Connection) *ConnectionConn {
	return &ConnectionConn{conn: conn}
}

// NetConn returns itself — ConnectionConn IS a net.Conn. Implements ConnProvider.
func (c *ConnectionConn) NetConn() net.Conn { return c }

func (c *ConnectionConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, io.EOF
	}
	c.mu.Unlock()

	// Drain buffer first
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}

	// Receive new message with optional deadline
	ctx := context.Background()
	if !c.deadline.IsZero() {
		var cancel context.CancelFunc
		timeout := time.Until(c.deadline)
		if timeout <= 0 {
			return 0, &net.OpError{Op: "read", Err: context.DeadlineExceeded}
		}
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	data, err := c.conn.Receive(ctx)
	if err != nil {
		return 0, err
	}

	n := copy(p, data)
	if n < len(data) {
		c.buf = data[n:]
	}
	return n, nil
}

func (c *ConnectionConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	c.mu.Unlock()

	ctx := context.Background()
	if !c.deadline.IsZero() {
		var cancel context.CancelFunc
		timeout := time.Until(c.deadline)
		if timeout <= 0 {
			return 0, &net.OpError{Op: "write", Err: context.DeadlineExceeded}
		}
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	if err := c.conn.Send(ctx, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *ConnectionConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return c.conn.Close()
}

func (c *ConnectionConn) LocalAddr() net.Addr  { return &net.TCPAddr{} }
func (c *ConnectionConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

func (c *ConnectionConn) SetDeadline(t time.Time) error {
	c.deadline = t
	return nil
}
func (c *ConnectionConn) SetReadDeadline(t time.Time) error {
	c.deadline = t
	return nil
}
func (c *ConnectionConn) SetWriteDeadline(t time.Time) error {
	c.deadline = t
	return nil
}

// ConnFromSession returns a net.Conn from any Session.
// If the session is a BaseConnection with a Conn field, returns it directly (zero overhead).
// Otherwise wraps the session in a ConnectionConn adapter.
func ConnFromSession(session Connection) net.Conn {
	if bs, ok := session.(*BaseConnection); ok && bs.Conn != nil {
		return bs.Conn
	}
	return NewConnectionConn(session)
}
