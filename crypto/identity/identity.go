/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
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
//
// MaxAckDelayUS is the sender's advertised maximum ACK delay in microseconds,
// piggybacked here so RFC 9002 §6.2's "sender PTO must include the peer's
// max_ack_delay" requirement can be satisfied at session-open BEFORE the first
// inbound CompositeACK arrives. Zero means "not advertised" — receivers fall
// back to a receiver-side approximation max(ACKPolicy.MaxDelay, SRTT/4).
//
// `json:",omitempty"` keeps the wire compact when the field is zero. New
// initiator/responder paths always stamp a non-zero value.
//
// Versions is the sender's wire version offer in the canonical encoding of
// aether.WireVersions.Encode. It travels inside the encrypted, authenticated
// handshake message, so each side reads the other's offer before either
// creates a session, and the noise handshake chooses from the two offers with
// aether.ChooseWireVersions. An absent field decodes to the empty offer, which
// that choice refuses on aether's required frame entry.
type NodeInfo struct {
	NodeID        string `json:"nodeId"`
	PubKey        []byte `json:"ed25519Pub"`
	Signature     []byte `json:"sig"`
	Caps          uint32 `json:"caps,omitempty"`
	MaxAckDelayUS uint32 `json:"maxAckDelayUs,omitempty"`
	Versions      []byte `json:"versions,omitempty"`
}

// EncodeNodeInfo creates a signed NodeInfo payload for handshake exchange.
// maxAckDelayUS is the sender's advertised max_ack_delay (RFC 9002 §6.2) in
// microseconds; pass 0 if not advertising. versions is the sender's wire
// version offer (aether.LocalWireVersions); an offer that is not in canonical
// form is refused with aether.ErrWireVersionsMalformed.
func (id *Identity) EncodeNodeInfo(caps uint32, maxAckDelayUS uint32, versions aether.WireVersions) ([]byte, error) {
	encodedVersions, err := versions.Encode()
	if err != nil {
		return nil, err
	}
	msg := SignatureMessage(id.Curve25519Pub)
	signature := ed25519.Sign(id.Ed25519Priv, msg[:])
	info := NodeInfo{
		NodeID:        string(id.NodeID),
		PubKey:        append([]byte(nil), id.Ed25519Pub...),
		Signature:     signature,
		Caps:          caps,
		MaxAckDelayUS: maxAckDelayUS,
		Versions:      encodedVersions,
	}
	return json.Marshal(info)
}

// VerifiedNodeInfo is what VerifyNodeInfo establishes about the peer: its
// node id and Ed25519 key (the signature over the handshake static key
// checked), its capability bits, its advertised max_ack_delay in
// microseconds (0 = not advertised; the caller falls back to the
// receiver-side approximation) and its wire version offer, decoded strictly.
type VerifiedNodeInfo struct {
	NodeID        aether.NodeID
	PubKey        ed25519.PublicKey
	Caps          uint32
	MaxAckDelayUS uint32
	WireVersions  aether.WireVersions
}

// VerifyNodeInfo validates a received NodeInfo payload: the Ed25519 key
// derives the expected node id (when one is given), converts to the static
// key the handshake proved, and signed that static key. A versions field that
// is not a canonical encoding fails verification with
// aether.ErrWireVersionsMalformed.
func VerifyNodeInfo(peerStatic []byte, payload []byte, expected aether.NodeID) (VerifiedNodeInfo, error) {
	var info NodeInfo
	if err := json.Unmarshal(payload, &info); err != nil {
		return VerifiedNodeInfo{}, err
	}
	if len(info.PubKey) != ed25519.PublicKeySize {
		return VerifiedNodeInfo{}, errors.New("crypto: invalid ed25519 key")
	}
	edPub := ed25519.PublicKey(info.PubKey)
	derived, err := aether.NewNodeID(edPub)
	if err != nil {
		return VerifiedNodeInfo{}, err
	}
	if expected != "" && derived != expected {
		return VerifiedNodeInfo{}, errors.New("crypto: unexpected node id in handshake")
	}
	curve, err := Ed25519PublicKeyToCurve(edPub)
	if err != nil {
		return VerifiedNodeInfo{}, err
	}
	if len(peerStatic) != len(curve) || !equalBytes(peerStatic, curve[:]) {
		return VerifiedNodeInfo{}, errors.New("crypto: static key mismatch")
	}
	msg := SignatureMessage(peerStatic)
	if !ed25519.Verify(edPub, msg[:], info.Signature) {
		return VerifiedNodeInfo{}, errors.New("crypto: handshake signature verification failed")
	}
	versions, err := aether.DecodeWireVersions(info.Versions)
	if err != nil {
		return VerifiedNodeInfo{}, fmt.Errorf("crypto: NodeInfo versions: %w", err)
	}
	return VerifiedNodeInfo{
		NodeID:        derived,
		PubKey:        edPub,
		Caps:          info.Caps,
		MaxAckDelayUS: info.MaxAckDelayUS,
		WireVersions:  versions,
	}, nil
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
