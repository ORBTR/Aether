/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 */
package websocket

import (
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/gobwas/ws"
)

// WSConn wraps a post-handshake net.Conn with WebSocket framing.
// Implements net.Conn — transparent to gossip/RPC code.
// Handles ping/pong at the frame level for proxy keepalive.
type WSConn struct {
	raw      net.Conn
	isServer bool       // true = server side (reads client frames, writes server frames)
	mu       sync.Mutex // protects writes (reads are single-goroutine in gossip loop)
	readBuf  []byte     // leftover data from a partially-consumed frame
	closed   bool
	pingStop chan struct{}
	peerID   string
}

// NewWSConn creates a WSConn adapter.
// isServer: true if this side accepted the connection (affects frame masking per RFC 6455).
// pingInterval: how often to send WebSocket ping frames (0 = no pings).
func NewWSConn(raw net.Conn, isServer bool, peerID string, pingInterval time.Duration) *WSConn {
	c := &WSConn{
		raw:      raw,
		isServer: isServer,
		peerID:   peerID,
		pingStop: make(chan struct{}),
	}
	if pingInterval > 0 {
		go c.pingLoop(pingInterval)
	}
	return c
}

// Read reads data from the WebSocket connection.
// Control frames (ping, pong, close) are handled transparently.
// Only data frame payloads are returned to the caller.
func (c *WSConn) Read(p []byte) (int, error) {
	// Return leftover data from previous frame
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	for {
		header, err := ws.ReadHeader(c.raw)
		if err != nil {
			log.Printf("[WS-DIAG] Read: ReadHeader err=%v remote=%s", err, c.peerID)
			return 0, err
		}

		// Read frame payload
		payload := make([]byte, header.Length)
		if header.Length > 0 {
			if _, err := io.ReadFull(c.raw, payload); err != nil {
				return 0, err
			}
			if header.Masked {
				ws.Cipher(payload, header.Mask, 0)
			}
		}

		switch header.OpCode {
		case ws.OpPing:
			// Auto-respond with pong (echo payload back)
			c.mu.Lock()
			pongHeader := ws.Header{Fin: true, OpCode: ws.OpPong, Length: int64(len(payload))}
			if !c.isServer {
				pongHeader.Masked = true
				pongHeader.Mask = ws.NewMask()
			}
			if err := ws.WriteHeader(c.raw, pongHeader); err != nil {
				c.mu.Unlock()
				return 0, err
			}
			if len(payload) > 0 {
				out := payload
				if pongHeader.Masked {
					out = make([]byte, len(payload))
					copy(out, payload)
					ws.Cipher(out, pongHeader.Mask, 0)
				}
				if _, err := c.raw.Write(out); err != nil {
					c.mu.Unlock()
					return 0, err
				}
			}
			c.mu.Unlock()
			continue // read next frame

		case ws.OpPong:
			// Pong received — keepalive acknowledged, continue reading
			continue

		case ws.OpClose:
			return 0, io.EOF

		case ws.OpBinary, ws.OpText, ws.OpContinuation:
			if len(payload) == 0 {
				continue // empty data frame (keepalive), read next
			}
			n := copy(p, payload)
			if n < len(payload) {
				c.readBuf = payload[n:]
			}
			return n, nil

		default:
			// Unknown opcode — skip
			continue
		}
	}
}

// Write wraps data in a WebSocket binary frame and sends it.
func (c *WSConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	header := ws.Header{
		Fin:    true,
		OpCode: ws.OpBinary,
		Length: int64(len(p)),
	}

	// Client frames must be masked per RFC 6455
	if !c.isServer {
		header.Masked = true
		header.Mask = ws.NewMask()
	}

	if err := ws.WriteHeader(c.raw, header); err != nil {
		return 0, err
	}

	if header.Masked {
		// Copy to avoid mutating caller's buffer
		masked := make([]byte, len(p))
		copy(masked, p)
		ws.Cipher(masked, header.Mask, 0)
		return c.raw.Write(masked)
	}
	return c.raw.Write(p)
}

// Close sends a WebSocket close frame and closes the underlying connection.
func (c *WSConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	close(c.pingStop) // stop ping loop goroutine
	// Write close frame while still holding mu (no interleave with Write())
	closeHeader := ws.Header{Fin: true, OpCode: ws.OpClose, Length: 0}
	if !c.isServer {
		closeHeader.Masked = true
		closeHeader.Mask = ws.NewMask()
	}
	_ = ws.WriteHeader(c.raw, closeHeader)
	c.mu.Unlock()
	return c.raw.Close()
}

// pingLoop sends WebSocket ping frames at the configured interval.
// Keeps the connection alive through HTTP proxies (Fly.io, Cloudflare, etc.)
// that enforce idle timeouts on WebSocket connections.
func (c *WSConn) pingLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.pingStop:
			return
		case <-ticker.C:
			c.mu.Lock()
			if c.closed {
				c.mu.Unlock()
				return
			}
			header := ws.Header{Fin: true, OpCode: ws.OpPing, Length: 0}
			if !c.isServer {
				header.Masked = true
				header.Mask = ws.NewMask()
			}
			err := ws.WriteHeader(c.raw, header)
			c.mu.Unlock()
			if err != nil {
				log.Printf("[WS] Ping write failed for %s: %v", truncWSID(c.peerID), err)
				return
			}
		}
	}
}

// net.Conn interface delegation
func (c *WSConn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *WSConn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *WSConn) SetDeadline(t time.Time) error       { return c.raw.SetDeadline(t) }
func (c *WSConn) SetReadDeadline(t time.Time) error    { return c.raw.SetReadDeadline(t) }
func (c *WSConn) SetWriteDeadline(t time.Time) error   { return c.raw.SetWriteDeadline(t) }

var _ net.Conn = (*WSConn)(nil) // compile-time interface check

func truncWSID(id string) string {
	if len(id) > 12 {
		return id[:12] + "..."
	}
	return id
}
