/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package websocket

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gobwas/ws"

	"github.com/ORBTR/aether"
)

// ─── AE-P-26 — client must verify the server's mesh identity ──────────────
// Before the fix, a WS/hijack client stamped target.NodeID as the session
// RemoteNodeID after only TLS hostname validation — nothing proved WHICH mesh
// identity actually answered on shared infra (Fly anycast, one cert across many
// machines). The fix makes the server sign the client's fresh dial nonce with
// its own key and the client verify that signed identity, failing closed on any
// mismatch. These tests drive the real transports over plain HTTP/WS (gobwas
// only uses TLS for wss://), so no cert-trust plumbing is needed.

func aep26Identity(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, aether.NodeID) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("aep26: GenerateKey: %v", err)
	}
	id, err := aether.NewNodeID(pub)
	if err != nil {
		t.Fatalf("aep26: NewNodeID: %v", err)
	}
	return pub, priv, id
}

func aep26Transport(t *testing.T, id aether.NodeID, priv ed25519.PrivateKey, listenAddr string) *WebsocketTransport {
	t.Helper()
	tr, err := NewWebsocketTransport(WebsocketTransportConfig{
		LocalNode:  id,
		PrivateKey: priv,
		ListenAddr: listenAddr,
	})
	if err != nil {
		t.Fatalf("aep26: NewWebsocketTransport: %v", err)
	}
	return tr
}

// aep26MaliciousWSServer stands up a WS server that completes the gobwas
// handshake but emits attacker-chosen identity headers. claimID/emitPub/signKey
// let each test forge a different failure mode; overrideNonce (when non-empty)
// makes the server sign a nonce OTHER than the client's, exercising the
// nonce-binding check.
func aep26MaliciousWSServer(t *testing.T, claimID aether.NodeID, emitPub ed25519.PublicKey, signKey ed25519.PrivateKey, overrideNonce string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonceStr := r.Header.Get(NonceHeader)
		tsStr := r.Header.Get(TimestampHeader)
		signNonce := nonceStr
		if overrideNonce != "" {
			signNonce = overrideNonce
		}
		h := make(http.Header)
		h.Set(NodeIDHeader, string(claimID))
		h.Set(PubKeyHeader, hex.EncodeToString(emitPub))
		sig := ed25519.Sign(signKey, []byte(fmt.Sprintf("ws-accept:%s:%s:%s", claimID, signNonce, tsStr)))
		h.Set(SignatureHeader, base64.StdEncoding.EncodeToString(sig))
		conn, _, _, err := ws.HTTPUpgrader{Header: h}.Upgrade(r, w)
		if err == nil {
			conn.Close()
		}
	}))
	t.Cleanup(srv.Close)
	return "ws://" + srv.Listener.Addr().String() + "/"
}

// aep26DialWS builds a fresh client transport and dials the given ws:// URL,
// returning the resulting error (nil on accept). Any successful session is
// closed before returning so nothing leaks.
func aep26DialWS(t *testing.T, target aether.Target) error {
	t.Helper()
	_, clientPriv, clientID := aep26Identity(t)
	clientTr := aep26Transport(t, clientID, clientPriv, "")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := clientTr.Dial(ctx, target)
	if conn != nil {
		conn.Close()
	}
	return err
}

// 1) Honest end-to-end: real Listen server + real Dial. The client must accept
//    and both sides must see the correct peer NodeID.
func TestAEP26_WSHonestRoundTripAccepted(t *testing.T) {
	_, srvPriv, srvID := aep26Identity(t)
	_, cliPriv, cliID := aep26Identity(t)

	server := aep26Transport(t, srvID, srvPriv, "127.0.0.1:0")
	ctx := context.Background()
	ln, err := server.Listen(ctx)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	client := aep26Transport(t, cliID, cliPriv, "")
	target := aether.Target{NodeID: srvID, Address: "ws://" + ln.Addr().String() + "/"}

	dctx, dcancel := context.WithTimeout(ctx, 3*time.Second)
	defer dcancel()
	conn, err := client.Dial(dctx, target)
	if err != nil {
		t.Fatalf("honest dial rejected: %v", err)
	}
	defer conn.Close()
	if conn.RemoteNodeID() != srvID {
		t.Fatalf("client RemoteNodeID = %s, want %s", conn.RemoteNodeID(), srvID)
	}

	actx, acancel := context.WithTimeout(ctx, 3*time.Second)
	defer acancel()
	srvConn, err := ln.Accept(actx)
	if err != nil {
		t.Fatalf("server Accept: %v", err)
	}
	defer srvConn.Close()
	if srvConn.RemoteNodeID() != cliID {
		t.Fatalf("server RemoteNodeID = %s, want %s", srvConn.RemoteNodeID(), cliID)
	}
}

// 2) Malicious echo: server claims the victim NodeID but presents its OWN
//    pubkey. The pubkey does not derive the claimed NodeID, so the client must
//    fail closed before trusting it.
func TestAEP26_WSMaliciousEchoRejected(t *testing.T) {
	_, _, victimID := aep26Identity(t)
	atkPub, atkPriv, _ := aep26Identity(t)

	url := aep26MaliciousWSServer(t, victimID, atkPub, atkPriv, "")
	err := aep26DialWS(t, aether.Target{NodeID: victimID, Address: url})
	if err == nil {
		t.Fatal("malicious echo accepted; want rejection")
	}
	if !strings.Contains(err.Error(), "does not match its NodeID") {
		t.Fatalf("wrong rejection reason: %v", err)
	}
}

// 3) Forged signature: server presents the victim's REAL pubkey (derive passes)
//    but signs the accept with the attacker's key. The signature must fail to
//    verify.
func TestAEP26_WSForgedSignatureRejected(t *testing.T) {
	victimPub, _, victimID := aep26Identity(t)
	_, atkPriv, _ := aep26Identity(t)

	url := aep26MaliciousWSServer(t, victimID, victimPub, atkPriv, "")
	err := aep26DialWS(t, aether.Target{NodeID: victimID, Address: url})
	if err == nil {
		t.Fatal("forged-signature server accepted; want rejection")
	}
	if !strings.Contains(err.Error(), "server identity signature invalid") {
		t.Fatalf("wrong rejection reason: %v", err)
	}
}

// 4) Wrong-but-honest identity: server proves a fully self-consistent identity B
//    (correct pubkey + valid signature over B), but the client dialed target A.
//    The proven NodeID must be required to equal the dialed target.
func TestAEP26_WSWrongTargetRejected(t *testing.T) {
	srvPub, srvPriv, srvID := aep26Identity(t)
	_, _, dialedID := aep26Identity(t) // a DIFFERENT target than the honest server

	url := aep26MaliciousWSServer(t, srvID, srvPub, srvPriv, "")
	err := aep26DialWS(t, aether.Target{NodeID: dialedID, Address: url})
	if err == nil {
		t.Fatal("wrong-target server accepted; want rejection")
	}
	if !strings.Contains(err.Error(), "does not match dialed target") {
		t.Fatalf("wrong rejection reason: %v", err)
	}
}

// 5) Old/keyless server: emits NO identity headers (pre-fix behavior). The
//    client must fail closed rather than blindly trust target.NodeID.
func TestAEP26_WSMissingIdentityRejected(t *testing.T) {
	_, _, victimID := aep26Identity(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err == nil {
			conn.Close()
		}
	}))
	defer srv.Close()

	err := aep26DialWS(t, aether.Target{NodeID: victimID, Address: "ws://" + srv.Listener.Addr().String() + "/"})
	if err == nil {
		t.Fatal("identity-less server accepted; want rejection")
	}
	if !strings.Contains(err.Error(), "did not present a signed identity") {
		t.Fatalf("wrong rejection reason: %v", err)
	}
}

// 6) Nonce binding: server signs a nonce OTHER than the one the client sent.
//    The client verifies over ITS OWN nonce, so a captured/replayed accept must
//    not verify.
func TestAEP26_WSStaleNonceRejected(t *testing.T) {
	srvPub, srvPriv, srvID := aep26Identity(t)
	url := aep26MaliciousWSServer(t, srvID, srvPub, srvPriv, "some-other-captured-nonce")
	err := aep26DialWS(t, aether.Target{NodeID: srvID, Address: url})
	if err == nil {
		t.Fatal("stale-nonce accept accepted; want rejection")
	}
	if !strings.Contains(err.Error(), "server identity signature invalid") {
		t.Fatalf("wrong rejection reason: %v", err)
	}
}

// 7) Hijack server-emit: a real hijack round-trip (httptest.Server exposes a
//    genuine http.Hijacker) must make the server sign the client's fresh nonce
//    with its own key. Proves the client's hijack-side check is not inert and
//    that the accept is bound to THIS dial (non-replayable).
func TestAEP26_HijackServerEmitsBoundAccept(t *testing.T) {
	_, srvPriv, srvID := aep26Identity(t)
	srvPub := srvPriv.Public().(ed25519.PublicKey)

	server := aep26Transport(t, srvID, srvPriv, "")
	handler, _ := server.HijackHandler()
	ts := httptest.NewServer(handler)
	defer ts.Close()

	_, cliPriv, cliID := aep26Identity(t)
	cliPub := cliPriv.Public().(ed25519.PublicKey)

	nonceStr := "aep26-hijack-nonce"
	tsStr := strconv.FormatInt(time.Now().UnixNano(), 10)

	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	defer conn.Close()

	req, err := http.NewRequest("POST", ts.URL+HijackPath, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", HijackUpgradeToken)
	req.Header.Set(NodeIDHeader, string(cliID))
	req.Header.Set(PubKeyHeader, hex.EncodeToString(cliPub))
	req.Header.Set(NonceHeader, nonceStr)
	req.Header.Set(TimestampHeader, tsStr)
	dialSig := ed25519.Sign(cliPriv, []byte(fmt.Sprintf("hijack-dial:%s:%s:%s:%s", cliID, srvID, tsStr, nonceStr)))
	req.Header.Set(SignatureHeader, base64.StdEncoding.EncodeToString(dialSig))

	if err := req.Write(conn); err != nil {
		t.Fatalf("req.Write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	if got := resp.Header.Get(NodeIDHeader); got != string(srvID) {
		t.Fatalf("101 NodeID = %q, want %q", got, srvID)
	}
	pubHex := resp.Header.Get(PubKeyHeader)
	sigB64 := resp.Header.Get(SignatureHeader)
	if pubHex == "" || sigB64 == "" {
		t.Fatal("server 101 omitted signed identity triple (AE-P-26 emit missing)")
	}
	gotPub, err := hex.DecodeString(pubHex)
	if err != nil {
		t.Fatalf("decode server pubkey: %v", err)
	}
	if derived, err := aether.NewNodeID(ed25519.PublicKey(gotPub)); err != nil || derived != srvID {
		t.Fatalf("server pubkey does not derive its NodeID: derived=%s err=%v", derived, err)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("decode server sig: %v", err)
	}
	// The accept must verify over the CLIENT's nonce+timestamp.
	good := []byte(fmt.Sprintf("hijack-accept:%s:%s:%s", srvID, nonceStr, tsStr))
	if !ed25519.Verify(srvPub, good, sig) {
		t.Fatal("server accept signature does not verify over the client nonce (AE-P-26)")
	}
	// And it must NOT verify against a different nonce (proves per-dial binding).
	stale := []byte(fmt.Sprintf("hijack-accept:%s:%s:%s", srvID, "different-nonce", tsStr))
	if ed25519.Verify(srvPub, stale, sig) {
		t.Fatal("server accept signature is not bound to the dial nonce (replayable)")
	}
}

// 8) Keyless hijack server: a transport built without a private key must NOT
//    panic (ed25519.Sign panics on a nil key) and must emit only the NodeID
//    header, leaving the client to fail closed on the missing triple.
func TestAEP26_HijackKeylessServerNoPanic(t *testing.T) {
	_, _, srvID := aep26Identity(t)
	server := aep26Transport(t, srvID, nil, "")
	handler, _ := server.HijackHandler()
	ts := httptest.NewServer(handler)
	defer ts.Close()

	_, cliPriv, cliID := aep26Identity(t)
	cliPub := cliPriv.Public().(ed25519.PublicKey)

	nonceStr := "aep26-keyless-nonce"
	tsStr := strconv.FormatInt(time.Now().UnixNano(), 10)

	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	defer conn.Close()

	req, err := http.NewRequest("POST", ts.URL+HijackPath, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", HijackUpgradeToken)
	req.Header.Set(NodeIDHeader, string(cliID))
	req.Header.Set(PubKeyHeader, hex.EncodeToString(cliPub))
	req.Header.Set(NonceHeader, nonceStr)
	req.Header.Set(TimestampHeader, tsStr)
	dialSig := ed25519.Sign(cliPriv, []byte(fmt.Sprintf("hijack-dial:%s:%s:%s:%s", cliID, srvID, tsStr, nonceStr)))
	req.Header.Set(SignatureHeader, base64.StdEncoding.EncodeToString(dialSig))

	if err := req.Write(conn); err != nil {
		t.Fatalf("req.Write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101 (keyless server should still hijack)", resp.StatusCode)
	}
	if resp.Header.Get(PubKeyHeader) != "" || resp.Header.Get(SignatureHeader) != "" {
		t.Fatal("keyless server emitted a signature it could not have signed")
	}
	if got := resp.Header.Get(NodeIDHeader); got != string(srvID) {
		t.Fatalf("101 NodeID = %q, want %q", got, srvID)
	}
}
