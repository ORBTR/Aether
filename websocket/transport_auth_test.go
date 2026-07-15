/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package websocket

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// ─── AE-C-04 — WebSocket NodeID auth binding must be mandatory ─────────
// Both Listen and HijackHandler used to gate signature verification behind
// `if signatureStr != ""`, so omitting the X-Signature header skipped
// all verification and bound the session to any claimed NodeID (impersonation).
// HijackHandler returns its handler, so it is directly exercisable; Listen
// carries the identical guard.

func newWSAuthTransport(t *testing.T) *WebsocketTransport {
	t.Helper()
	tr, err := NewWebsocketTransport(WebsocketTransportConfig{LocalNode: aether.NodeID("server-node")})
	if err != nil {
		t.Fatalf("NewWebsocketTransport: %v", err)
	}
	return tr
}

// A hijack upgrade carrying a NodeID but NO signature must be rejected 401,
// not accepted under the claimed NodeID.
func TestAEC04_HijackMissingSignatureRejected(t *testing.T) {
	tr := newWSAuthTransport(t)
	handler, _ := tr.HijackHandler()

	req := httptest.NewRequest(http.MethodGet, "/mesh/relay", nil)
	req.Header.Set("Upgrade", HijackUpgradeToken)
	req.Header.Set(NodeIDHeader, "victim-node-id") // claimed, no signature
	rec := httptest.NewRecorder()

	handler(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned hijack accepted: got %d, want 401 (AE-C-04)", rec.Code)
	}
}

// A present-but-invalid signature must also be rejected.
func TestAEC04_HijackInvalidSignatureRejected(t *testing.T) {
	tr := newWSAuthTransport(t)
	handler, _ := tr.HijackHandler()

	pub, _, _ := ed25519.GenerateKey(nil)
	req := httptest.NewRequest(http.MethodGet, "/mesh/relay", nil)
	req.Header.Set("Upgrade", HijackUpgradeToken)
	req.Header.Set(NodeIDHeader, "victim")
	req.Header.Set(PubKeyHeader, hex.EncodeToString(pub))
	req.Header.Set(SignatureHeader, base64.StdEncoding.EncodeToString([]byte("not-a-real-signature-bytes-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")))
	rec := httptest.NewRecorder()

	handler(rec, req)
	if rec.Code == http.StatusOK || rec.Code == http.StatusSwitchingProtocols {
		t.Fatalf("invalid-signature hijack accepted: got %d (AE-C-04)", rec.Code)
	}
}

// A correctly-signed hijack must PASS auth. httptest.ResponseRecorder is not an
// http.Hijacker, so after auth succeeds the handler returns 500 at the hijack
// step — which proves auth was NOT the thing that rejected it (i.e. not 401/400).
func TestAEC04_HijackValidSignaturePassesAuth(t *testing.T) {
	tr := newWSAuthTransport(t)
	handler, _ := tr.HijackHandler()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	nodeID, err := aether.NewNodeID(pub)
	if err != nil {
		t.Fatalf("NewNodeID: %v", err)
	}
	// AE-M-16: the signed message now binds a fresh timestamp + nonce, and both
	// are carried as headers. A valid dial must supply them for auth to pass.
	tsStr := strconv.FormatInt(time.Now().UnixNano(), 10)
	nonceStr := "test-nonce-aem16"
	msg := []byte(fmt.Sprintf("hijack-dial:%s:%s:%s:%s", nodeID, tr.localNode, tsStr, nonceStr))
	sig := ed25519.Sign(priv, msg)

	req := httptest.NewRequest(http.MethodGet, "/mesh/relay", nil)
	req.Header.Set("Upgrade", HijackUpgradeToken)
	req.Header.Set(NodeIDHeader, string(nodeID))
	req.Header.Set(PubKeyHeader, hex.EncodeToString(pub))
	req.Header.Set(TimestampHeader, tsStr)
	req.Header.Set(NonceHeader, nonceStr)
	req.Header.Set(SignatureHeader, base64.StdEncoding.EncodeToString(sig))
	rec := httptest.NewRecorder()

	handler(rec, req)
	if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusBadRequest {
		t.Fatalf("valid signed hijack rejected by auth: got %d (want auth to pass) (AE-C-04)", rec.Code)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Logf("note: expected 500 (recorder is not http.Hijacker); got %d — auth still passed", rec.Code)
	}
}
