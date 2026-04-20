/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 *
 * CryptoIdentity encapsulates Ed25519 + Curve25519 key derivation and
 * node identity operations. Extracted from NoiseTransport to be reusable
 * across all transport protocols (Noise, QUIC TLS, WebSocket auth, gRPC metadata).
 */
package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
	aether "github.com/ORBTR/aether"
)

// Identity holds the Ed25519 keypair and derived Curve25519 keys for a mesh node.
// Thread-safe: all fields are immutable after construction.
type Identity struct {
	NodeID         aether.NodeID
	Ed25519Priv    ed25519.PrivateKey
	Ed25519Pub     ed25519.PublicKey
	Curve25519Priv []byte // derived from Ed25519 (for Noise handshakes)
	Curve25519Pub  []byte // derived from Ed25519 (for Noise handshakes)
}

// NewIdentity creates an Identity from an Ed25519 private key.
// Derives NodeID and Curve25519 keys automatically.
func NewIdentity(privKey ed25519.PrivateKey) (*Identity, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return nil, errors.New("crypto: invalid ed25519 private key size")
	}
	pubKey := privKey.Public().(ed25519.PublicKey)

	nodeID, err := aether.NewNodeID(pubKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: derive node ID: %w", err)
	}

	curvePriv, err := Ed25519PrivateKeyToCurve(privKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: derive curve25519 private: %w", err)
	}
	curvePub, err := Ed25519PublicKeyToCurve(pubKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: derive curve25519 public: %w", err)
	}

	return &Identity{
		NodeID:         nodeID,
		Ed25519Priv:    privKey,
		Ed25519Pub:     pubKey,
		Curve25519Priv: append([]byte(nil), curvePriv[:]...),
		Curve25519Pub:  append([]byte(nil), curvePub[:]...),
	}, nil
}

// SignatureMessage returns the SHA-256 hash used for Noise handshake signature verification.
// The message is: SHA256("vl1/noise/static:" + staticCurve25519PublicKey)
func SignatureMessage(staticPub []byte) [32]byte {
	return sha256.Sum256(append([]byte("vl1/noise/static:"), staticPub...))
}

// NodeInfo represents the identity payload exchanged during Noise handshakes.
type NodeInfo struct {
	NodeID    string `json:"node_id"`
	PubKey    []byte `json:"ed25519_pub"`
	Signature []byte `json:"sig"`
	Caps      uint32 `json:"caps,omitempty"`
}

// EncodeNodeInfo creates a signed NodeInfo payload for handshake exchange.
func (id *Identity) EncodeNodeInfo(caps uint32) ([]byte, error) {
	msg := SignatureMessage(id.Curve25519Pub)
	signature := ed25519.Sign(id.Ed25519Priv, msg[:])
	info := NodeInfo{
		NodeID:    string(id.NodeID),
		PubKey:    append([]byte(nil), id.Ed25519Pub...),
		Signature: signature,
		Caps:      caps,
	}
	return json.Marshal(info)
}

// VerifyNodeInfo validates a received NodeInfo payload.
// Returns the derived NodeID, Ed25519 public key, and capabilities.
func VerifyNodeInfo(peerStatic []byte, payload []byte, expected aether.NodeID) (aether.NodeID, ed25519.PublicKey, uint32, error) {
	var info NodeInfo
	if err := json.Unmarshal(payload, &info); err != nil {
		return "", nil, 0, err
	}
	if len(info.PubKey) != ed25519.PublicKeySize {
		return "", nil, 0, errors.New("crypto: invalid ed25519 key")
	}
	edPub := ed25519.PublicKey(info.PubKey)
	derived, err := aether.NewNodeID(edPub)
	if err != nil {
		return "", nil, 0, err
	}
	if expected != "" && derived != expected {
		return "", nil, 0, errors.New("crypto: unexpected node id in handshake")
	}
	curve, err := Ed25519PublicKeyToCurve(edPub)
	if err != nil {
		return "", nil, 0, err
	}
	if len(peerStatic) != len(curve) || !equalBytes(peerStatic, curve[:]) {
		return "", nil, 0, errors.New("crypto: static key mismatch")
	}
	msg := SignatureMessage(peerStatic)
	if !ed25519.Verify(edPub, msg[:], info.Signature) {
		return "", nil, 0, errors.New("crypto: handshake signature verification failed")
	}
	return derived, edPub, info.Caps, nil
}

// --- Ed25519 → Curve25519 conversion ---

// Ed25519PrivateKeyToCurve derives a Curve25519 private key from an Ed25519 private key.
// Uses the standard RFC 8032 derivation: SHA-512(seed) → clamp → Curve25519 scalar.
func Ed25519PrivateKeyToCurve(edPriv ed25519.PrivateKey) ([]byte, error) {
	h := sha512.Sum512(edPriv[:32])
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	return h[:32], nil
}

// Ed25519PublicKeyToCurve converts an Ed25519 public key to Curve25519.
func Ed25519PublicKeyToCurve(edPub ed25519.PublicKey) ([]byte, error) {
	p, err := new(edwards25519.Point).SetBytes(edPub)
	if err != nil {
		return nil, fmt.Errorf("crypto: invalid ed25519 public key: %w", err)
	}
	return p.BytesMontgomery(), nil
}

func equalBytes(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
