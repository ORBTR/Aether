/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package websocket

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gobwas/ws"
	"github.com/ORBTR/aether"
)

const (
	// NodeIDHeader is the HTTP header used to transmit the client's NodeID
	NodeIDHeader = "X-HSTLES-NodeID"
	// PubKeyHeader contains hex-encoded Ed25519 public key for signature verification.
	// Sent alongside NodeID because NodeID is base32-encoded fingerprint (not the raw key).
	PubKeyHeader = "X-HSTLES-PubKey"
	// SignatureHeader contains Ed25519 signature proving ownership of NodeID
	SignatureHeader = "X-HSTLES-Signature"
	// NonceHeader contains the challenge nonce for signature verification
	NonceHeader = "X-HSTLES-Nonce"

	// pingInterval is how often to send WebSocket ping frames for proxy keepalive
	pingInterval = 10 * time.Second
)

type WebsocketTransportConfig struct {
	LocalNode  aether.NodeID
	PrivateKey ed25519.PrivateKey
	ListenAddr string
}

type WebsocketTransport struct {
	localNode  aether.NodeID
	privateKey ed25519.PrivateKey
	listenAddr string
	server     *http.Server
}

func NewWebsocketTransport(cfg WebsocketTransportConfig) (*WebsocketTransport, error) {
	return &WebsocketTransport{
		localNode:  cfg.LocalNode,
		privateKey: cfg.PrivateKey,
		listenAddr: cfg.ListenAddr,
	}, nil
}

// NewWebsocketTransportFromConfig creates a WebSocket transport from the unified Config.
// Returns nil if Config.WebSocket is nil (protocol disabled).
func NewWebsocketTransportFromConfig(cfg aether.Config) (*WebsocketTransport, error) {
	if cfg.WebSocket == nil {
		return nil, nil
	}
	return NewWebsocketTransport(WebsocketTransportConfig{
		LocalNode:  cfg.NodeID,
		PrivateKey: cfg.PrivateKey,
		ListenAddr: cfg.WebSocket.ListenAddr,
	})
}

func (t *WebsocketTransport) Dial(ctx context.Context, target aether.Target) (aether.Connection, error) {
	// Create signed headers to prove our identity
	headers := make(http.Header)
	headers.Set(NodeIDHeader, string(t.localNode))
	headers.Set(PubKeyHeader, hex.EncodeToString(t.privateKey.Public().(ed25519.PublicKey)))

	// Sign the dial intent to prevent replay attacks
	message := []byte(fmt.Sprintf("ws-dial:%s:%s", t.localNode, target.NodeID))
	signature := ed25519.Sign(t.privateKey, message)
	headers.Set(SignatureHeader, base64.StdEncoding.EncodeToString(signature))

	// Dial using gobwas/ws — returns the raw net.Conn post-handshake
	// Measure dial RTT (TCP handshake + TLS + WS upgrade) for cross-region latency
	dialStart := time.Now()
	dialer := ws.Dialer{
		Header: ws.HandshakeHeaderHTTP(headers),
		TLSConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
	}
	rawConn, _, _, err := dialer.Dial(ctx, target.Address)
	if err != nil {
		return nil, aether.WrapOp("dial", aether.ProtoWebSocket, target.NodeID, err)
	}
	dialRTT := time.Since(dialStart)

	// Wrap with WSConn adapter (client side: isServer=false, with ping keepalive)
	wsConn := NewWSConn(rawConn, false, string(target.NodeID), pingInterval)

	session := aether.NewConnection(t.localNode, target.NodeID, wsConn)
	session.SetInitialRTT(dialRTT)
	session.OnClose(func() { wsConn.Close() })
	return session, nil
}

func (t *WebsocketTransport) Listen(ctx context.Context) (aether.Listener, error) {
	ch := make(chan aether.IncomingSession, 32)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract and validate NodeID from headers
		remoteNodeIDStr := r.Header.Get(NodeIDHeader)
		if remoteNodeIDStr == "" {
			http.Error(w, "missing NodeID header", http.StatusBadRequest)
			return
		}
		remoteNodeID := aether.NodeID(remoteNodeIDStr)

		// Verify signature if present
		signatureStr := r.Header.Get(SignatureHeader)
		if signatureStr != "" {
			signature, err := base64.StdEncoding.DecodeString(signatureStr)
			if err != nil {
				http.Error(w, "invalid signature encoding", http.StatusBadRequest)
				return
			}

			// The signature should be over "ws-dial:<clientNodeID>:<serverNodeID>"
			message := []byte(fmt.Sprintf("ws-dial:%s:%s", remoteNodeID, t.localNode))

			// Extract public key from PubKey header (NodeID is base32 fingerprint, not the raw key)
			pubKeyHex := r.Header.Get(PubKeyHeader)
			if pubKeyHex == "" {
				http.Error(w, "missing public key header", http.StatusBadRequest)
				return
			}
			pubKeyBytes, err := hex.DecodeString(pubKeyHex)
			if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
				http.Error(w, "invalid public key", http.StatusBadRequest)
				return
			}
			pubKey := ed25519.PublicKey(pubKeyBytes)

			// Verify the NodeID derives from this public key
			derivedNodeID, err := aether.NewNodeID(pubKey)
			if err != nil || derivedNodeID != remoteNodeID {
				http.Error(w, "public key does not match NodeID", http.StatusBadRequest)
				return
			}

			if !ed25519.Verify(pubKey, message, signature) {
				http.Error(w, "invalid signature", http.StatusUnauthorized)
				return
			}
		}

		// Upgrade to WebSocket using gobwas/ws — hijacks the HTTP connection
		rawConn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			return
		}

		// Wrap with WSConn adapter (server side: isServer=true, with ping keepalive)
		wsConn := NewWSConn(rawConn, true, string(remoteNodeID), pingInterval)

		session := aether.NewConnection(t.localNode, remoteNodeID, wsConn)
		session.OnClose(func() { wsConn.Close() })

		select {
		case ch <- aether.IncomingSession{Session: session}:
		default:
			// Channel full — close
			wsConn.Close()
		}
	})

	ln, err := net.Listen("tcp", t.listenAddr)
	if err != nil {
		return nil, aether.WrapOp("listen", aether.ProtoWebSocket, "", err)
	}

	server := &http.Server{
		Handler: handler,
	}
	t.server = server

	go server.Serve(ln)

	return &WebsocketListener{
		ch:     ch,
		ln:     ln,
		server: server,
	}, nil
}

func (t *WebsocketTransport) Close() error {
	if t.server != nil {
		return t.server.Close()
	}
	return nil
}

// Protocol implements aether.ProtocolAdapter.
func (t *WebsocketTransport) Protocol() aether.Protocol { return aether.ProtoWebSocket }

// Compile-time interface check.
var _ aether.ProtocolAdapter = (*WebsocketTransport)(nil)

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// HTTP/1.1 Hijack Transport — proxy-safe fallback for Fly/Cloudflare
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//
// Fly.io and some CDN proxies interfere with WebSocket frame reassembly,
// causing intermittent drops mid-session. The VL1 bootstrap (HTTP/1.1 Upgrade
// with hijack) does NOT drop because the proxy treats it as an opaque TCP
// stream after the 101 Switching Protocols response.
//
// DialHijack uses the same pattern: the client sends a POST with
// "Connection: Upgrade, Upgrade: mesh-relay" headers. The server hijacks
// the connection and writes a raw 101 response. Both sides then use
// length-prefixed binary framing (4-byte big-endian length + payload)
// over the raw TLS connection — no WebSocket frames for the proxy to
// mishandle.
//
// Wire format after hijack (both directions):
//   [4 bytes: payload length (big-endian)] [N bytes: payload]
//
// This is the same framing gossip/RPC already uses on TLS bootstrap
// connections.

const (
	// HijackUpgradeToken is the Upgrade header value for hijack relay connections.
	HijackUpgradeToken = "mesh-relay"

	// HijackPath is the HTTP path for hijack relay connections.
	HijackPath = "/mesh/relay"

	// hijackMaxFrameSize limits individual frame payloads (16 MB, same as MuxFrame).
	hijackMaxFrameSize = 16 << 20
)

// DialHijack establishes a transport session using HTTP/1.1 Upgrade + hijack
// instead of the WebSocket protocol. This avoids proxy interference on Fly.io
// and Cloudflare by producing a plain TCP stream after the HTTP upgrade.
//
// The target.Address should be a hostname (e.g., "node.hstles.com") — the
// method constructs the full URL internally.
func (t *WebsocketTransport) DialHijack(ctx context.Context, target aether.Target) (aether.Connection, error) {
	// Build the target URL — strip any existing scheme
	host := target.Address
	if strings.HasPrefix(host, "wss://") {
		host = strings.TrimPrefix(host, "wss://")
	}
	if strings.HasPrefix(host, "https://") {
		host = strings.TrimPrefix(host, "https://")
	}
	// Strip path if present (we add our own)
	if idx := strings.Index(host, "/"); idx >= 0 {
		host = host[:idx]
	}

	// Ensure host:port
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "443")
	}

	dialStart := time.Now()

	// Dial TLS
	tlsHost := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		tlsHost = h
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, aether.WrapOp("dial-hijack", aether.ProtoWebSocket, target.NodeID, err)
	}
	tlsConn := tls.Client(rawConn, &tls.Config{ServerName: tlsHost})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, aether.WrapOp("dial-hijack-tls", aether.ProtoWebSocket, target.NodeID, err)
	}

	// Send HTTP/1.1 Upgrade request
	reqURL := fmt.Sprintf("https://%s%s", host, HijackPath)
	req, err := http.NewRequestWithContext(ctx, "POST", reqURL, nil)
	if err != nil {
		tlsConn.Close()
		return nil, aether.WrapOp("dial-hijack-req", aether.ProtoWebSocket, target.NodeID, err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", HijackUpgradeToken)
	req.Header.Set(NodeIDHeader, string(t.localNode))
	req.Header.Set(PubKeyHeader, hex.EncodeToString(t.privateKey.Public().(ed25519.PublicKey)))
	message := []byte(fmt.Sprintf("hijack-dial:%s:%s", t.localNode, target.NodeID))
	signature := ed25519.Sign(t.privateKey, message)
	req.Header.Set(SignatureHeader, base64.StdEncoding.EncodeToString(signature))

	// Write the request manually (we own the TLS conn, no http.Client needed)
	if err := req.Write(tlsConn); err != nil {
		tlsConn.Close()
		return nil, aether.WrapOp("dial-hijack-write", aether.ProtoWebSocket, target.NodeID, err)
	}

	// Read 101 response
	br := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		tlsConn.Close()
		return nil, aether.WrapOp("dial-hijack-resp", aether.ProtoWebSocket, target.NodeID, err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		resp.Body.Close()
		tlsConn.Close()
		return nil, aether.WrapOp("dial-hijack-status", aether.ProtoWebSocket, target.NodeID,
			fmt.Errorf("expected 101, got %d", resp.StatusCode))
	}

	dialRTT := time.Since(dialStart)

	// Wrap the raw TLS conn (with buffered reader for any pipelined bytes)
	// in a HijackConn that provides length-prefixed framing.
	hjConn := NewHijackConn(tlsConn, br)

	session := aether.NewConnection(t.localNode, target.NodeID, hjConn)
	session.SetInitialRTT(dialRTT)
	session.OnClose(func() { hjConn.Close() })
	return session, nil
}

// HijackHandler returns an http.HandlerFunc that accepts incoming hijack relay
// connections. Register at /mesh/relay on the same HTTP server as /mesh/ws.
//
// Incoming connections are delivered to the returned channel. The caller (usually
// runtime.WebSocketHandler or a relay endpoint) should consume from the channel
// and run gossip/RPC on the resulting net.Conn.
func (t *WebsocketTransport) HijackHandler() (http.HandlerFunc, <-chan HijackSession) {
	ch := make(chan HijackSession, 32)

	handler := func(w http.ResponseWriter, r *http.Request) {
		// Verify Upgrade header
		if !strings.EqualFold(r.Header.Get("Upgrade"), HijackUpgradeToken) {
			http.Error(w, "mesh-relay upgrade required", http.StatusBadRequest)
			return
		}

		remoteNodeIDStr := r.Header.Get(NodeIDHeader)
		if remoteNodeIDStr == "" {
			http.Error(w, "missing NodeID header", http.StatusBadRequest)
			return
		}
		remoteNodeID := aether.NodeID(remoteNodeIDStr)

		// Verify signature if present
		signatureStr := r.Header.Get(SignatureHeader)
		if signatureStr != "" {
			signature, err := base64.StdEncoding.DecodeString(signatureStr)
			if err != nil {
				http.Error(w, "invalid signature encoding", http.StatusBadRequest)
				return
			}
			message := []byte(fmt.Sprintf("hijack-dial:%s:%s", remoteNodeID, t.localNode))
			pubKeyHex := r.Header.Get(PubKeyHeader)
			if pubKeyHex == "" {
				http.Error(w, "missing public key header", http.StatusBadRequest)
				return
			}
			pubKeyBytes, err := hex.DecodeString(pubKeyHex)
			if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
				http.Error(w, "invalid public key", http.StatusBadRequest)
				return
			}
			pubKey := ed25519.PublicKey(pubKeyBytes)
			derivedNodeID, err := aether.NewNodeID(pubKey)
			if err != nil || derivedNodeID != remoteNodeID {
				http.Error(w, "public key does not match NodeID", http.StatusBadRequest)
				return
			}
			if !ed25519.Verify(pubKey, message, signature) {
				http.Error(w, "invalid signature", http.StatusUnauthorized)
				return
			}
		}

		// Hijack the connection
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "server does not support hijacking", http.StatusInternalServerError)
			return
		}
		conn, rw, err := hj.Hijack()
		if err != nil {
			log.Printf("[WS-HIJACK] Hijack failed from %s: %v", r.RemoteAddr, err)
			return
		}

		// Write 101 Switching Protocols
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
		_, _ = rw.WriteString("Upgrade: " + HijackUpgradeToken + "\r\n")
		_, _ = rw.WriteString("Connection: Upgrade\r\n")
		_, _ = rw.WriteString(NodeIDHeader + ": " + string(t.localNode) + "\r\n")
		_, _ = rw.WriteString("\r\n")
		if err := rw.Flush(); err != nil {
			log.Printf("[WS-HIJACK] Flush failed for %s: %v", r.RemoteAddr, err)
			conn.Close()
			return
		}

		hjConn := NewHijackConn(conn, rw.Reader)

		select {
		case ch <- HijackSession{Conn: hjConn, RemoteNodeID: remoteNodeID}:
		default:
			log.Printf("[WS-HIJACK] Session channel full, dropping connection from %s", remoteNodeIDStr)
			hjConn.Close()
		}
	}

	return handler, ch
}

// HijackSession represents an accepted hijack relay connection.
type HijackSession struct {
	Conn         net.Conn
	RemoteNodeID aether.NodeID
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// HijackConn — length-prefixed framing over a hijacked TCP connection
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//
// After the HTTP/1.1 101 upgrade, both sides use length-prefixed binary
// framing: [4 bytes big-endian length][payload]. This is transparent to
// gossip and RPC code that expects a net.Conn — Read/Write operate on
// complete messages.

// HijackConn wraps a raw (post-hijack) connection with length-prefixed framing.
// Implements net.Conn for transparent use by gossip/RPC.
type HijackConn struct {
	raw    net.Conn
	reader *bufio.Reader // may contain pipelined data from HTTP response
	mu     sync.Mutex    // protects writes
	closed bool
	readBuf []byte // leftover from partially-consumed frame
}

// NewHijackConn creates a HijackConn. The bufio.Reader should be the buffered
// reader from the HTTP response parsing (may contain leftover bytes).
func NewHijackConn(raw net.Conn, br *bufio.Reader) *HijackConn {
	if br == nil {
		br = bufio.NewReader(raw)
	}
	return &HijackConn{
		raw:    raw,
		reader: br,
	}
}

// Read reads the next length-prefixed message (or returns leftover from previous).
func (c *HijackConn) Read(p []byte) (int, error) {
	// Return leftover first
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	// Read 4-byte length header
	var hdr [4]byte
	if _, err := io.ReadFull(c.reader, hdr[:]); err != nil {
		return 0, err
	}
	length := binary.BigEndian.Uint32(hdr[:])
	if length > hijackMaxFrameSize {
		return 0, fmt.Errorf("hijack: frame too large (%d bytes)", length)
	}
	if length == 0 {
		// Keepalive frame — read next
		return c.Read(p)
	}

	// Read payload
	payload := make([]byte, length)
	if _, err := io.ReadFull(c.reader, payload); err != nil {
		return 0, err
	}

	n := copy(p, payload)
	if n < len(payload) {
		c.readBuf = payload[n:]
	}
	return n, nil
}

// Write sends a length-prefixed message.
func (c *HijackConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(p)))
	if _, err := c.raw.Write(hdr[:]); err != nil {
		return 0, err
	}
	return c.raw.Write(p)
}

// Close closes the underlying connection.
func (c *HijackConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.raw.Close()
}

// net.Conn interface delegation
func (c *HijackConn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *HijackConn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *HijackConn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *HijackConn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *HijackConn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

var _ net.Conn = (*HijackConn)(nil) // compile-time interface check

type WebsocketListener struct {
	ch     chan aether.IncomingSession
	ln     net.Listener
	server *http.Server
}

func (l *WebsocketListener) Accept(ctx context.Context) (aether.Connection, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case s, ok := <-l.ch:
		if !ok {
			return nil, errors.New("listener closed")
		}
		return s.Session, nil
	}
}

func (l *WebsocketListener) Close() error {
	return l.server.Close()
}

func (l *WebsocketListener) Addr() net.Addr {
	return l.ln.Addr()
}
