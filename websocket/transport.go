/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package websocket

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gobwas/ws"
	"github.com/ORBTR/aether"
)

const (
	// NodeIDHeader is the HTTP header used to transmit the client's NodeID
	NodeIDHeader = "X-NodeID"
	// PubKeyHeader contains hex-encoded Ed25519 public key for signature verification.
	// Sent alongside NodeID because NodeID is base32-encoded fingerprint (not the raw key).
	PubKeyHeader = "X-PubKey"
	// SignatureHeader contains Ed25519 signature proving ownership of NodeID
	SignatureHeader = "X-Signature"
	// NonceHeader carries the client-chosen random nonce bound into the dial
	// signature; with TimestampHeader it makes each handshake unique so a
	// captured signature cannot be replayed (AE-M-16).
	NonceHeader = "X-Nonce"
	// TimestampHeader carries the unix-nanosecond dial time bound into the
	// signature; the server rejects anything outside dialFreshnessWindow.
	TimestampHeader = "X-Timestamp"

	// pingInterval is how often to send WebSocket ping frames for proxy keepalive.
	// Sized at 5s rather than the obvious 10s because some HTTP edge proxies
	// (fly.io's WebSocket upgrade path being the observed case) idle-close
	// upgraded connections inside ~10s when no frames flow. WSConn.pingLoop
	// also fires its FIRST ping at T+1s — together they ensure the
	// underlying TCP never goes more than ~1s idle initially, then ~5s
	// thereafter, well under any observed proxy idle threshold.
	pingInterval = 5 * time.Second

	// dialFreshnessWindow bounds clock skew between a dial signature's
	// timestamp and the server clock; the replay cache retains authenticated
	// nonces for the same span (AE-M-16). Sized generously (not tightened) so
	// NTP-synced Fly nodes never falsely reject a legitimate dial.
	dialFreshnessWindow = 60 * time.Second
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
	replay     *dialReplayGuard
}

func NewWebsocketTransport(cfg WebsocketTransportConfig) (*WebsocketTransport, error) {
	return &WebsocketTransport{
		localNode:  cfg.LocalNode,
		privateKey: cfg.PrivateKey,
		listenAddr: cfg.ListenAddr,
		replay:     newDialReplayGuard(),
	}, nil
}

// dialReplayGuard rejects reuse of an authenticated dial nonce within the
// freshness window (AE-M-16). Only signature-valid nonces are recorded, so
// an unauthenticated peer cannot poison it. Retention is bounded by expiry.
type dialReplayGuard struct {
	mu   sync.Mutex
	seen map[string]time.Time // nonce -> expiry
}

func newDialReplayGuard() *dialReplayGuard { return &dialReplayGuard{seen: make(map[string]time.Time)} }

// checkAndRecord returns false if nonce was already seen; otherwise records
// it with expiry and prunes expired entries.
func (g *dialReplayGuard) checkAndRecord(nonce string, now, expiry time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, exp := range g.seen {
		if now.After(exp) {
			delete(g.seen, k)
		}
	}
	if _, dup := g.seen[nonce]; dup {
		return false
	}
	g.seen[nonce] = expiry
	return true
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

	// AE-M-16: bind the dial intent to a fresh timestamp + random nonce so a
	// captured (NodeID, PubKey, Signature) header set cannot be replayed to
	// re-establish a session as us. The server rejects timestamps outside
	// dialFreshnessWindow and any nonce it has already seen within that window.
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, aether.WrapOp("dial", aether.ProtoWebSocket, target.NodeID, err)
	}
	nonceStr := base64.RawStdEncoding.EncodeToString(nonce)
	tsStr := strconv.FormatInt(time.Now().UnixNano(), 10)
	headers.Set(NonceHeader, nonceStr)
	headers.Set(TimestampHeader, tsStr)
	message := []byte(fmt.Sprintf("ws-dial:%s:%s:%s:%s", t.localNode, target.NodeID, tsStr, nonceStr))
	signature := ed25519.Sign(t.privateKey, message)
	headers.Set(SignatureHeader, base64.StdEncoding.EncodeToString(signature))

	// TLS config — by default the SNI is derived from the URL host in
	// target.Address. Callers that need to dial a host that doesn't have
	// a public cert (e.g. fly's `<app>.flycast` private anycast address
	// when the public DNS resolver is broken) can pass the original
	// public hostname via Metadata["sni_host"]; the cert presented by
	// the same backend machine validates against that name even when
	// reached via the private address.
	tlsConfig := &tls.Config{InsecureSkipVerify: false}
	if target.Metadata != nil {
		if sniHost := target.Metadata["sni_host"]; sniHost != "" {
			tlsConfig.ServerName = sniHost
		}
	}

	// Dial using gobwas/ws — returns the raw net.Conn post-handshake
	// Measure dial RTT (TCP handshake + TLS + WS upgrade) for cross-region latency
	dialStart := time.Now()
	// AE-P-26: capture the server's signed identity headers from the 101
	// response so we can verify the server owns target.NodeID before trusting
	// it (matching the HTTPUpgrader emit in Listen). Header keys arrive as
	// canonicalized wire bytes, so match case-insensitively.
	var srvNodeIDHdr, srvPubHex, srvSigB64 string
	dialer := ws.Dialer{
		Header:    ws.HandshakeHeaderHTTP(headers),
		TLSConfig: tlsConfig,
		OnHeader: func(key, value []byte) error {
			switch {
			case strings.EqualFold(string(key), NodeIDHeader):
				srvNodeIDHdr = string(value)
			case strings.EqualFold(string(key), PubKeyHeader):
				srvPubHex = string(value)
			case strings.EqualFold(string(key), SignatureHeader):
				srvSigB64 = string(value)
			}
			return nil
		},
	}
	rawConn, _, _, err := dialer.Dial(ctx, target.Address)
	if err != nil {
		return nil, aether.WrapOp("dial", aether.ProtoWebSocket, target.NodeID, err)
	}
	dialRTT := time.Since(dialStart)

	// AE-P-26: verify the server's mesh identity (fail closed) before stamping
	// target.NodeID. Mirrors the hijack path: require a signed triple, check the
	// pubkey derives the claimed NodeID, verify the signature over OUR fresh
	// nonce+timestamp, and require the proven NodeID == the dialed target. TLS
	// alone only proves the endpoint holds a cert for the hostname, not which
	// NodeID answered on shared infra.
	srvNodeID := aether.NodeID(srvNodeIDHdr)
	if srvNodeID == "" || srvPubHex == "" || srvSigB64 == "" {
		rawConn.Close()
		return nil, aether.WrapOp("dial-serverauth", aether.ProtoWebSocket, target.NodeID,
			errors.New("server did not present a signed identity"))
	}
	srvPub, err := hex.DecodeString(srvPubHex)
	if err != nil || len(srvPub) != ed25519.PublicKeySize {
		rawConn.Close()
		return nil, aether.WrapOp("dial-serverauth", aether.ProtoWebSocket, target.NodeID,
			errors.New("server public key invalid"))
	}
	derivedSrv, err := aether.NewNodeID(ed25519.PublicKey(srvPub))
	if err != nil || derivedSrv != srvNodeID {
		rawConn.Close()
		return nil, aether.WrapOp("dial-serverauth", aether.ProtoWebSocket, target.NodeID,
			errors.New("server public key does not match its NodeID"))
	}
	srvSig, err := base64.StdEncoding.DecodeString(srvSigB64)
	if err != nil {
		rawConn.Close()
		return nil, aether.WrapOp("dial-serverauth", aether.ProtoWebSocket, target.NodeID,
			errors.New("server signature encoding invalid"))
	}
	acceptMsg := []byte(fmt.Sprintf("ws-accept:%s:%s:%s", srvNodeID, nonceStr, tsStr))
	if !ed25519.Verify(ed25519.PublicKey(srvPub), acceptMsg, srvSig) {
		rawConn.Close()
		return nil, aether.WrapOp("dial-serverauth", aether.ProtoWebSocket, target.NodeID,
			errors.New("server identity signature invalid"))
	}
	if srvNodeID != target.NodeID {
		rawConn.Close()
		return nil, aether.WrapOp("dial-serverauth", aether.ProtoWebSocket, target.NodeID,
			fmt.Errorf("server NodeID %s does not match dialed target %s", srvNodeID.Short(), target.NodeID.Short()))
	}

	// Wrap with WSConn adapter (client side: isServer=false, with ping keepalive)
	wsConn := NewWSConn(rawConn, false, string(target.NodeID), pingInterval)

	session := aether.NewConnection(t.localNode, target.NodeID, wsConn)
	session.SetInitialRTT(dialRTT)
	session.OnClose(func() { wsConn.Close() })
	return session, nil
}

// VerifyMeshDialError carries the HTTP status a mesh-dial verification failure
// should surface. VerifyMeshDial returns it (as the error interface) so a
// caller mounting its own /mesh/ws handler can map the failure to the exact
// status + message the built-in Listen handler uses: 400 for a malformed
// request, 401 for a failed authentication (AE-C-04 mandatory signature /
// AE-M-16 freshness+replay).
type VerifyMeshDialError struct {
	Status int
	Msg    string
}

func (e *VerifyMeshDialError) Error() string { return e.Msg }

// VerifyMeshDial runs the AE-C-04 dial verification on an inbound mesh WS
// upgrade request and returns the cryptographically-proven remote NodeID and
// its ed25519 public key. Callers that mount their own /mesh/ws handler call
// this before upgrading, replacing a presence-only signature check. The
// returned error carries the correct HTTP status via VerifyMeshDialError.
func (t *WebsocketTransport) VerifyMeshDial(r *http.Request) (aether.NodeID, ed25519.PublicKey, error) {
	return t.verifyMeshDial(r, "ws-dial")
}

// verifyMeshDial is the single source of truth for inbound mesh-dial
// verification, shared by VerifyMeshDial/Listen (dialPrefix "ws-dial") and
// HijackHandler (dialPrefix "hijack-dial"). Both inbound paths sign a byte-
// identical structure that differs ONLY in this prefix, so threading it keeps
// one implementation of the mandatory-signature (AE-C-04) and freshness+replay
// (AE-M-16) checks while each path preserves its exact signed message. On
// success it has already recorded the dial nonce in the shared replay guard.
func (t *WebsocketTransport) verifyMeshDial(r *http.Request, dialPrefix string) (aether.NodeID, ed25519.PublicKey, error) {
	// Extract and validate NodeID from headers
	remoteNodeIDStr := r.Header.Get(NodeIDHeader)
	if remoteNodeIDStr == "" {
		return "", nil, &VerifyMeshDialError{Status: http.StatusBadRequest, Msg: "missing NodeID header"}
	}
	remoteNodeID := aether.NodeID(remoteNodeIDStr)

	// NodeID ownership MUST be cryptographically proven — the signature is
	// mandatory, never optional-on-presence. A client that omits it would
	// otherwise be accepted under any claimed NodeID (peer impersonation,
	// AE-C-04). Ordinary server TLS gives no client-identity guarantee, so
	// this signature is the sole NodeID binding. Legitimate clients always
	// send it (see Dial), so requiring it breaks nothing.
	signatureStr := r.Header.Get(SignatureHeader)
	if signatureStr == "" {
		return "", nil, &VerifyMeshDialError{Status: http.StatusUnauthorized, Msg: "missing signature header"}
	}
	signature, err := base64.StdEncoding.DecodeString(signatureStr)
	if err != nil {
		return "", nil, &VerifyMeshDialError{Status: http.StatusBadRequest, Msg: "invalid signature encoding"}
	}

	// AE-M-16: reject stale dials before spending a signature verify.
	tsStr := r.Header.Get(TimestampHeader)
	nonceStr := r.Header.Get(NonceHeader)
	if tsStr == "" || nonceStr == "" {
		return "", nil, &VerifyMeshDialError{Status: http.StatusUnauthorized, Msg: "missing dial freshness headers"}
	}
	tsNano, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return "", nil, &VerifyMeshDialError{Status: http.StatusBadRequest, Msg: "invalid dial timestamp"}
	}
	now := time.Now()
	if skew := now.Sub(time.Unix(0, tsNano)); skew > dialFreshnessWindow || skew < -dialFreshnessWindow {
		return "", nil, &VerifyMeshDialError{Status: http.StatusUnauthorized, Msg: "stale dial signature"}
	}

	// The signature should be over "<dialPrefix>:<clientNodeID>:<serverNodeID>:<ts>:<nonce>"
	message := []byte(fmt.Sprintf("%s:%s:%s:%s:%s", dialPrefix, remoteNodeID, t.localNode, tsStr, nonceStr))

	// Extract public key from PubKey header (NodeID is base32 fingerprint, not the raw key)
	pubKeyHex := r.Header.Get(PubKeyHeader)
	if pubKeyHex == "" {
		return "", nil, &VerifyMeshDialError{Status: http.StatusBadRequest, Msg: "missing public key header"}
	}
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		return "", nil, &VerifyMeshDialError{Status: http.StatusBadRequest, Msg: "invalid public key"}
	}
	pubKey := ed25519.PublicKey(pubKeyBytes)

	// Verify the NodeID derives from this public key
	derivedNodeID, err := aether.NewNodeID(pubKey)
	if err != nil || derivedNodeID != remoteNodeID {
		return "", nil, &VerifyMeshDialError{Status: http.StatusBadRequest, Msg: "public key does not match NodeID"}
	}

	if !ed25519.Verify(pubKey, message, signature) {
		return "", nil, &VerifyMeshDialError{Status: http.StatusUnauthorized, Msg: "invalid signature"}
	}

	// AE-M-16: authentic signature — now reject a replay of it.
	if !t.replay.checkAndRecord(nonceStr, now, time.Unix(0, tsNano).Add(dialFreshnessWindow)) {
		return "", nil, &VerifyMeshDialError{Status: http.StatusUnauthorized, Msg: "replayed dial signature"}
	}

	return remoteNodeID, pubKey, nil
}

// writeVerifyMeshDialError maps a verifyMeshDial failure to the HTTP status +
// message the inline handlers wrote before extraction. Non-VerifyMeshDialError
// values (never produced by verifyMeshDial today) default to 400.
func writeVerifyMeshDialError(w http.ResponseWriter, err error) {
	var ve *VerifyMeshDialError
	if errors.As(err, &ve) {
		http.Error(w, ve.Msg, ve.Status)
		return
	}
	http.Error(w, err.Error(), http.StatusBadRequest)
}

func (t *WebsocketTransport) Listen(ctx context.Context) (aether.Listener, error) {
	ch := make(chan aether.IncomingSession, 32)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// AE-C-04 / AE-M-16 dial verification — single source of truth shared
		// with HijackHandler and exported as VerifyMeshDial for callers that
		// mount their own /mesh/ws handler.
		remoteNodeID, _, err := t.VerifyMeshDial(r)
		if err != nil {
			writeVerifyMeshDialError(w, err)
			return
		}

		// Re-read the freshness headers VerifyMeshDial already validated —
		// they seed the AE-P-26 accept signature below.
		tsStr := r.Header.Get(TimestampHeader)
		nonceStr := r.Header.Get(NonceHeader)

		// AE-P-26: prove our mesh identity to the client on the plain WS path too.
		// The server previously emitted NO identity header here, so a client had
		// only TLS hostname validation backing target.NodeID. Sign the client's
		// fresh dial nonce+timestamp with our own key and emit the signed triple
		// in the 101 response; the client verifies it before trusting
		// target.NodeID and fails closed on mismatch. Guard on key presence
		// (ed25519.Sign panics on a nil key): a keyless transport emits only the
		// NodeID header and the client — which requires the triple — fails closed.
		respHdr := make(http.Header)
		respHdr.Set(NodeIDHeader, string(t.localNode))
		if len(t.privateKey) == ed25519.PrivateKeySize {
			acceptMsg := []byte(fmt.Sprintf("ws-accept:%s:%s:%s", t.localNode, nonceStr, tsStr))
			acceptSig := ed25519.Sign(t.privateKey, acceptMsg)
			respHdr.Set(PubKeyHeader, hex.EncodeToString(t.privateKey.Public().(ed25519.PublicKey)))
			respHdr.Set(SignatureHeader, base64.StdEncoding.EncodeToString(acceptSig))
		}
		// Upgrade to WebSocket using gobwas/ws — hijacks the HTTP connection and
		// writes our signed identity headers into the 101 response (AE-P-26).
		rawConn, _, _, err := ws.HTTPUpgrader{Header: respHdr}.Upgrade(r, w)
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
// The target.Address should be a hostname (e.g., "node.orbtr.io") — the
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

	// Dial TLS — derive default SNI from the URL host, but allow the
	// caller to override via Metadata["sni_host"]. Override is needed
	// when dialing a private host (e.g. fly `.flycast` anycast) whose
	// cert is issued for the public name; cert validation still works
	// because the same backend machine serves both addresses.
	tlsHost := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		tlsHost = h
	}
	if target.Metadata != nil {
		if sniHost := target.Metadata["sni_host"]; sniHost != "" {
			tlsHost = sniHost
		}
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
	// AE-M-16: bind a fresh timestamp + random nonce into the hijack dial
	// signature so a captured header set cannot be replayed.
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		tlsConn.Close()
		return nil, aether.WrapOp("dial-hijack", aether.ProtoWebSocket, target.NodeID, err)
	}
	nonceStr := base64.RawStdEncoding.EncodeToString(nonce)
	tsStr := strconv.FormatInt(time.Now().UnixNano(), 10)
	req.Header.Set(NonceHeader, nonceStr)
	req.Header.Set(TimestampHeader, tsStr)
	message := []byte(fmt.Sprintf("hijack-dial:%s:%s:%s:%s", t.localNode, target.NodeID, tsStr, nonceStr))
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

	// AE-P-26: verify the server's mesh identity before trusting target.NodeID.
	// TLS only proves the endpoint holds a cert for the dialed hostname; on
	// shared infra (Fly anycast, one cert across many machines) that does not
	// prove WHICH NodeID answered. The client's dial signature already makes an
	// HONEST wrong-identity server reject the dial, but a malicious cert-holder
	// can accept while claiming the victim's NodeID. Require the server to prove
	// ownership of target.NodeID by signing OUR fresh dial nonce+timestamp with
	// its own key: the proof is bound to THIS dial (non-replayable) and cannot be
	// forged by echoing headers, because forging it needs the victim's private
	// key. Fail closed on any mismatch instead of stamping target.NodeID blind.
	srvNodeID := aether.NodeID(resp.Header.Get(NodeIDHeader))
	srvPubHex := resp.Header.Get(PubKeyHeader)
	srvSigB64 := resp.Header.Get(SignatureHeader)
	if srvNodeID == "" || srvPubHex == "" || srvSigB64 == "" {
		resp.Body.Close()
		tlsConn.Close()
		return nil, aether.WrapOp("dial-hijack-serverauth", aether.ProtoWebSocket, target.NodeID,
			errors.New("server did not present a signed identity"))
	}
	srvPub, err := hex.DecodeString(srvPubHex)
	if err != nil || len(srvPub) != ed25519.PublicKeySize {
		resp.Body.Close()
		tlsConn.Close()
		return nil, aether.WrapOp("dial-hijack-serverauth", aether.ProtoWebSocket, target.NodeID,
			errors.New("server public key invalid"))
	}
	derivedSrv, err := aether.NewNodeID(ed25519.PublicKey(srvPub))
	if err != nil || derivedSrv != srvNodeID {
		resp.Body.Close()
		tlsConn.Close()
		return nil, aether.WrapOp("dial-hijack-serverauth", aether.ProtoWebSocket, target.NodeID,
			errors.New("server public key does not match its NodeID"))
	}
	srvSig, err := base64.StdEncoding.DecodeString(srvSigB64)
	if err != nil {
		resp.Body.Close()
		tlsConn.Close()
		return nil, aether.WrapOp("dial-hijack-serverauth", aether.ProtoWebSocket, target.NodeID,
			errors.New("server signature encoding invalid"))
	}
	acceptMsg := []byte(fmt.Sprintf("hijack-accept:%s:%s:%s", srvNodeID, nonceStr, tsStr))
	if !ed25519.Verify(ed25519.PublicKey(srvPub), acceptMsg, srvSig) {
		resp.Body.Close()
		tlsConn.Close()
		return nil, aether.WrapOp("dial-hijack-serverauth", aether.ProtoWebSocket, target.NodeID,
			errors.New("server identity signature invalid"))
	}
	if srvNodeID != target.NodeID {
		resp.Body.Close()
		tlsConn.Close()
		return nil, aether.WrapOp("dial-hijack-serverauth", aether.ProtoWebSocket, target.NodeID,
			fmt.Errorf("server NodeID %s does not match dialed target %s", srvNodeID.Short(), target.NodeID.Short()))
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

		// AE-C-04 / AE-M-16 dial verification — single source of truth shared
		// with the WS Listen path. The hijack path signs a "hijack-dial:"
		// prefix rather than "ws-dial:", so it calls the internal verifier with
		// that prefix; the replay guard is the same t.replay instance the WS
		// path uses (nonce keyed on the 128-bit random value).
		remoteNodeID, _, err := t.verifyMeshDial(r, "hijack-dial")
		if err != nil {
			writeVerifyMeshDialError(w, err)
			return
		}

		// Re-read the freshness headers verifyMeshDial already validated —
		// they seed the AE-P-26 accept signature written into the 101 below.
		tsStr := r.Header.Get(TimestampHeader)
		nonceStr := r.Header.Get(NonceHeader)

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

		// Write 101 Switching Protocols. AE-P-26: prove our mesh identity to the
		// client by signing its fresh dial nonce+timestamp with our own key, so an
		// endpoint that merely holds a cert for the hostname (and does not own this
		// NodeID's private key) cannot pass the client's identity check. Guard on
		// key presence: ed25519.Sign panics on a nil key, so a transport built
		// without a private key emits only the NodeID header and the client (which
		// requires the signed triple) fails closed rather than the server panicking.
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
		_, _ = rw.WriteString("Upgrade: " + HijackUpgradeToken + "\r\n")
		_, _ = rw.WriteString("Connection: Upgrade\r\n")
		_, _ = rw.WriteString(NodeIDHeader + ": " + string(t.localNode) + "\r\n")
		if len(t.privateKey) == ed25519.PrivateKeySize {
			acceptMsg := []byte(fmt.Sprintf("hijack-accept:%s:%s:%s", t.localNode, nonceStr, tsStr))
			acceptSig := ed25519.Sign(t.privateKey, acceptMsg)
			_, _ = rw.WriteString(PubKeyHeader + ": " + hex.EncodeToString(t.privateKey.Public().(ed25519.PublicKey)) + "\r\n")
			_, _ = rw.WriteString(SignatureHeader + ": " + base64.StdEncoding.EncodeToString(acceptSig) + "\r\n")
		}
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
			log.Printf("[WS-HIJACK] Session channel full, dropping connection from %s", remoteNodeID)
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
