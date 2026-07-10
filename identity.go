/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
)

const (
	nodeIDPrefix   = "vl1_"
	ed25519KeySize = ed25519.PublicKeySize
)

var (
	base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

	ErrInvalidNodeID = errors.New("transport: invalid node id")
)

// NewNodeID derives a short node ID from an Ed25519 public key.
// The ID is a SHA-256 fingerprint of the key (first 16 bytes), base32-encoded.
// Result: "vl1_" + 26 lowercase chars = 30 chars total (128 bits of entropy).
func NewNodeID(pub ed25519.PublicKey) (NodeID, error) {
	if len(pub) != ed25519KeySize {
		return "", fmt.Errorf("transport: expected %d-byte Ed25519 public key", ed25519KeySize)
	}
	hash := sha256.Sum256(pub)
	encoded := base32NoPad.EncodeToString(hash[:16])
	return NodeID(nodeIDPrefix + strings.ToLower(encoded)), nil
}

// ParseNodeID validates the textual form and returns a NodeID instance.
// Accepts both legacy (52-char) and new (26-char) encoded formats.
func ParseNodeID(value string) (NodeID, error) {
	if !strings.HasPrefix(value, nodeIDPrefix) {
		return "", ErrInvalidNodeID
	}
	trimmed := strings.TrimPrefix(value, nodeIDPrefix)
	if len(trimmed) == 0 {
		return "", ErrInvalidNodeID
	}
	if _, err := base32NoPad.DecodeString(strings.ToUpper(trimmed)); err != nil {
		return "", fmt.Errorf("transport: decode node id: %w", err)
	}
	return NodeID(NormalizeNodeID(value)), nil
}

// Canonical returns the normalized string form of this NodeID.
func (id NodeID) Canonical() string {
	return NormalizeNodeID(string(id))
}

// MapKey returns the canonical form suitable for use as a map key.
func (id NodeID) MapKey() string {
	return NormalizeNodeID(string(id))
}

// MustParseNodeID panics on invalid input and should be used for constants.
func MustParseNodeID(value string) NodeID {
	id, err := ParseNodeID(value)
	if err != nil {
		panic(err)
	}
	return id
}

// NormalizeNodeID trims whitespace from a raw nodeID string.
// This is the single normalization entry point — all external nodeID inputs
// (HTTP headers, LAD records) should pass through here before map storage or lookup.
func NormalizeNodeID(raw string) string {
	return strings.TrimSpace(raw)
}

// Fingerprint returns the raw bytes encoded in the NodeID (SHA-256 fingerprint).
func (id NodeID) Fingerprint() ([]byte, error) {
	if !strings.HasPrefix(string(id), nodeIDPrefix) {
		return nil, ErrInvalidNodeID
	}
	encoded := strings.TrimPrefix(string(id), nodeIDPrefix)
	decoded, err := base32NoPad.DecodeString(strings.ToUpper(encoded))
	if err != nil {
		return nil, fmt.Errorf("transport: decode node id: %w", err)
	}
	return decoded, nil
}

// Short returns a shortened representation useful for logs.
// With 30-char IDs, shows first 10 + last 6 = 18 chars.
func (id NodeID) Short() string {
	value := string(id)
	if len(value) <= 20 {
		return value
	}
	return value[:10] + "…" + value[len(value)-6:]
}

// ToPeerID returns the 8-byte PeerID derived from the NodeID's decoded key
// fingerprint. The first eight bytes of NodeID.Fingerprint are copied into
// the fixed-size array — this is what every transport adapter stamps into
// outbound Frame.SenderID / Frame.ReceiverID so the wire identity matches
// what the peer sees on its end of the connection. Lives on NodeID (rather
// than each adapter) so the Noise, TCP and QUIC sessions all derive the
// same value from the same input.
//
// AE-L-04: derive from the decoded fingerprint (64 bits), not the textual
// canonical string. The canonical form is nodeIDPrefix ("vl1_") + base32, so
// its first eight bytes are the constant "vl1_" plus only four base32 chars
// (~20 bits) — a near-total PeerID collision across the mesh (birthday
// collisions at ~1000 nodes). A malformed NodeID (Fingerprint error) falls
// back to the textual bytes, matching the prior behaviour for that edge.
func (id NodeID) ToPeerID() PeerID {
	var pid PeerID
	if fp, err := id.Fingerprint(); err == nil {
		copy(pid[:], fp) // AE-L-04: first 8 of the 16-byte SHA-256 fingerprint
		return pid
	}
	copy(pid[:], []byte(string(id)))
	return pid
}

// Validate ensures the NodeID is well-formed.
func (id NodeID) Validate() error {
	_, err := id.Fingerprint()
	return err
}
