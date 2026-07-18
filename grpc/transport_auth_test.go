//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package grpc

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"google.golang.org/grpc/metadata"
)

// ─── AE-C-03 — gRPC NodeID auth binding must be mandatory ──────────────
// extractNodeID must NOT return an attacker-supplied NodeID without a valid
// ed25519 signature proving ownership. Verification used to be gated behind
// `if len(signatures) > 0`, so omitting the signature metadata authenticated
// the caller under any claimed NodeID (peer impersonation).

func newAuthTestTransport(t *testing.T) *GrpcTransport {
	t.Helper()
	tr, err := NewGrpcTransport(GrpcTransportConfig{LocalNode: aether.NodeID("server-node")})
	if err != nil {
		t.Fatalf("NewGrpcTransport: %v", err)
	}
	return tr
}

func TestAEC03_MissingSignatureRejected(t *testing.T) {
	tr := newAuthTestTransport(t)
	md := metadata.New(map[string]string{
		MetadataNodeID: "victim-node-id", // claimed, unproven, NO signature
	})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	if got, err := tr.extractNodeID(ctx); err == nil {
		t.Fatalf("extractNodeID accepted unsigned NodeID %q — impersonation (AE-C-03)", got)
	}
}

func TestAEC03_PubKeyWithoutSignatureRejected(t *testing.T) {
	tr := newAuthTestTransport(t)
	pub, _, _ := ed25519.GenerateKey(nil)
	md := metadata.New(map[string]string{
		MetadataNodeID: "victim",
		MetadataPubKey: hex.EncodeToString(pub), // pubkey but still no signature
	})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	if _, err := tr.extractNodeID(ctx); err == nil {
		t.Fatal("extractNodeID accepted NodeID with pubkey but no signature (AE-C-03)")
	}
}

// A correctly-signed request must still be accepted — the fix must not break
// legitimate clients (Dial always sends NodeID+PubKey+Signature).
func TestAEC03_ValidSignatureAccepted(t *testing.T) {
	tr := newAuthTestTransport(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	nodeID, err := aether.NewNodeID(pub)
	if err != nil {
		t.Fatalf("NewNodeID: %v", err)
	}
	tsStr := strconv.FormatInt(time.Now().UnixNano(), 10)
	nonceStr := "test-nonce-" + tsStr
	msg := []byte(fmt.Sprintf("grpc-dial:%s:%s:%s:%s", nodeID, tr.localNode, tsStr, nonceStr))
	sig := ed25519.Sign(priv, msg)
	md := metadata.New(map[string]string{
		MetadataNodeID:    string(nodeID),
		MetadataPubKey:    hex.EncodeToString(pub),
		MetadataSignature: hex.EncodeToString(sig),
		MetadataNonce:     nonceStr,
		MetadataTimestamp: tsStr,
	})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	got, err := tr.extractNodeID(ctx)
	if err != nil {
		t.Fatalf("valid signed request rejected: %v", err)
	}
	if got != nodeID {
		t.Fatalf("extractNodeID = %q, want %q", got, nodeID)
	}
}

// A forged signature (valid key, wrong NodeID claim) must be rejected: the
// pubkey→NodeID derivation check must catch a mismatched claim.
func TestAEC03_MismatchedNodeIDRejected(t *testing.T) {
	tr := newAuthTestTransport(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	realID, _ := aether.NewNodeID(pub)
	claimed := aether.NodeID("some-other-victim")
	msg := []byte(fmt.Sprintf("grpc-dial:%s:%s", claimed, tr.localNode))
	sig := ed25519.Sign(priv, msg)
	md := metadata.New(map[string]string{
		MetadataNodeID:    string(claimed), // claims a NodeID the key doesn't derive
		MetadataPubKey:    hex.EncodeToString(pub),
		MetadataSignature: hex.EncodeToString(sig),
	})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	if got, err := tr.extractNodeID(ctx); err == nil {
		t.Fatalf("extractNodeID accepted claimed %q that key derives to %q (AE-C-03)", got, realID)
	}
}
