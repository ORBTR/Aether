//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package quic

import (
	"crypto/tls"
	"testing"
)

// TestGenerateTLSConfigRequestsClientCert is the AE-H-12 regression guard.
//
// The single tls.Config produced by generateTLSConfig is shared by both the
// dial and listen sides. Before the fix it never set ClientAuth, so the QUIC
// server defaulted to tls.NoClientCert: it sent no CertificateRequest, the
// client presented no cert, and the server's VerifyConnection aborted every
// inbound handshake with "no peer certificate" (cs.PeerCertificates empty) —
// no inbound peer NodeID could ever be bound.
//
// The fix sets ClientAuth: tls.RequireAnyClientCert so the server requests the
// client cert (identity is still validated in VerifyConnection, consistent with
// InsecureSkipVerify:true). This test fails before the fix and passes after.
func TestGenerateTLSConfigRequestsClientCert(t *testing.T) {
	key := generateTestKey(t)

	cfg, err := generateTLSConfig(key)
	if err != nil {
		t.Fatalf("generateTLSConfig failed: %v", err)
	}

	// Must be RequireAnyClientCert, not RequireAndVerifyClientCert: ClientCAs is
	// nil, so full-chain verification would reject every client. The self-signed
	// Ed25519 identity is instead verified manually in VerifyConnection.
	if cfg.ClientAuth != tls.RequireAnyClientCert {
		t.Fatalf("ClientAuth = %v, want tls.RequireAnyClientCert: without it the QUIC server sends no CertificateRequest and every inbound connection fails in VerifyConnection with \"no peer certificate\"", cfg.ClientAuth)
	}
}
