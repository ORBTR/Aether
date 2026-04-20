/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

// Package crypto implements per-frame AEAD encryption for Aether.
// Uses ChaCha20-Poly1305 matching the existing Noise cipher suite.
// Per-frame encryption is only used when the transport doesn't provide
// native encryption (e.g., plain WebSocket, or relay scenarios where
// the relay node must not read payload data).
package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/ORBTR/aether"
	"golang.org/x/crypto/chacha20poly1305"
)

// FrameEncryptor encrypts/decrypts Aether frame payloads using ChaCha20-Poly1305.
// The AEAD additional data is the frame header bytes (first 38 bytes before nonce),
// authenticating the header without encrypting it so routers can inspect
// SenderID/ReceiverID for forwarding.
type FrameEncryptor struct {
	aead    cipher.AEAD
	counter uint64 // atomic counter for ordered nonces
	random  bool   // true for unordered streams (use random nonces)
}

// NewFrameEncryptor creates an encryptor with the given 256-bit key.
// Set ordered=true for reliable-ordered streams (counter-based nonces),
// ordered=false for unordered streams (random nonces for replay safety).
func NewFrameEncryptor(key [32]byte, ordered bool) (*FrameEncryptor, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("aether crypto: create AEAD: %w", err)
	}
	return &FrameEncryptor{
		aead:   aead,
		random: !ordered,
	}, nil
}

// Encrypt encrypts the frame payload in-place.
// Sets the ENCRYPTED flag and populates the Nonce field.
// The frame's Length is updated to reflect the ciphertext size (payload + 16-byte auth tag).
func (e *FrameEncryptor) Encrypt(frame *aether.Frame) error {
	if frame.Payload == nil || frame.Length == 0 {
		return nil // nothing to encrypt
	}

	nonce := e.nextNonce()
	frame.Nonce = nonce
	frame.Flags = frame.Flags.Set(aether.FlagENCRYPTED)

	// Set Length to ciphertext size BEFORE computing AD
	// so the AD matches during both encrypt and decrypt.
	plaintextLen := frame.Length
	frame.Length = plaintextLen + uint32(e.aead.Overhead())

	// AEAD additional data = header bytes (authenticates SenderID, ReceiverID, etc.)
	ad := frame.HeaderBytes()

	// Encrypt: ciphertext = plaintext + 16-byte auth tag
	ciphertext := e.aead.Seal(nil, nonce[:], frame.Payload[:plaintextLen], ad)
	frame.Payload = ciphertext

	return nil
}

// Decrypt decrypts the frame payload in-place.
// Clears the ENCRYPTED flag. Verifies the auth tag against the header.
// Returns an error if authentication fails (tampered frame).
func (e *FrameEncryptor) Decrypt(frame *aether.Frame) error {
	if !frame.Flags.Has(aether.FlagENCRYPTED) {
		return nil // not encrypted
	}
	if frame.Payload == nil || frame.Length == 0 {
		return nil
	}

	// AEAD additional data must match what was used during encryption.
	// We need the header as it was BEFORE we clear the ENCRYPTED flag.
	ad := frame.HeaderBytes()

	plaintext, err := e.aead.Open(nil, frame.Nonce[:], frame.Payload, ad)
	if err != nil {
		return fmt.Errorf("aether crypto: decrypt failed (auth tag mismatch): %w", err)
	}

	frame.Payload = plaintext
	frame.Length = uint32(len(plaintext))
	frame.Flags = frame.Flags.Clear(aether.FlagENCRYPTED)
	frame.Nonce = aether.Nonce{} // clear nonce after decryption

	return nil
}

// DecryptWithNonce decrypts a frame using an externally-provided nonce.
// Used by the 0x87 encrypted short header path where the Nonce is extracted
// from the payload envelope rather than the frame header's Nonce field.
func (e *FrameEncryptor) DecryptWithNonce(frame *aether.Frame, nonce []byte) error {
	if frame.Payload == nil || frame.Length == 0 {
		return nil
	}
	if len(nonce) != e.aead.NonceSize() {
		return fmt.Errorf("aether crypto: invalid nonce size %d (need %d)", len(nonce), e.aead.NonceSize())
	}

	plaintext, err := e.aead.Open(nil, nonce, frame.Payload, nil)
	if err != nil {
		return fmt.Errorf("aether crypto: decrypt with nonce failed: %w", err)
	}

	frame.Payload = plaintext
	frame.Length = uint32(len(plaintext))
	return nil
}

// Overhead returns the encryption overhead per frame (16 bytes for Poly1305 auth tag).
func (e *FrameEncryptor) Overhead() int {
	return e.aead.Overhead()
}

// nextNonce generates the next nonce.
// Ordered streams use a monotonic counter (safe — nonces never repeat if encryptor is single-use).
// Unordered streams use crypto/rand for replay safety under concurrent/reordered sends.
func (e *FrameEncryptor) nextNonce() aether.Nonce {
	var nonce aether.Nonce
	if e.random {
		// Random nonce for unordered streams — prevents nonce reuse under reordering
		rand.Read(nonce[:])
		return nonce
	}
	c := atomic.AddUint64(&e.counter, 1)
	binary.BigEndian.PutUint64(nonce[4:12], c) // last 8 bytes = counter
	return nonce
}

// ────────────────────────────────────────────────────────────────────────────
// Identity Truncation
// ────────────────────────────────────────────────────────────────────────────

// IdentityTable maps between full NodeIDs and truncated 8-byte PeerIDs.
// Thread-safe for concurrent registration and lookup.
type IdentityTable struct {
	mu      sync.RWMutex
	byShort map[aether.PeerID]string // PeerID → full NodeID string
	byFull  map[string]aether.PeerID // full NodeID string → PeerID
}

// NewIdentityTable creates an empty identity table.
func NewIdentityTable() *IdentityTable {
	return &IdentityTable{
		byShort: make(map[aether.PeerID]string),
		byFull:  make(map[string]aether.PeerID),
	}
}

// Register adds a NodeID and returns its truncated PeerID.
// If already registered, returns the existing PeerID.
// Detects PeerID collisions (two different NodeIDs mapping to the same 8-byte PeerID).
// On collision: logs a warning and returns the PeerID with an error.
// The caller should fall back to WHOIS-based full NodeID resolution for that peer.
func (t *IdentityTable) Register(nodeID string) (aether.PeerID, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if pid, ok := t.byFull[nodeID]; ok {
		return pid, nil
	}

	pid := TruncateNodeID(nodeID)

	// Collision detection: another NodeID already maps to this PeerID
	if existing, ok := t.byShort[pid]; ok && existing != nodeID {
		return pid, fmt.Errorf("aether: PeerID collision: %q and %q both map to %s (use WHOIS for disambiguation)",
			existing[:min(20, len(existing))], nodeID[:min(20, len(nodeID))], pid)
	}

	t.byShort[pid] = nodeID
	t.byFull[nodeID] = pid
	return pid, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Lookup returns the full NodeID for a PeerID.
func (t *IdentityTable) Lookup(peerID aether.PeerID) (string, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	nodeID, ok := t.byShort[peerID]
	return nodeID, ok
}

// Reverse returns the PeerID for a full NodeID.
func (t *IdentityTable) Reverse(nodeID string) (aether.PeerID, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	pid, ok := t.byFull[nodeID]
	return pid, ok
}

// TruncateNodeID creates an 8-byte PeerID from a full NodeID string.
// Uses SHA-256 hash of the NodeID, truncated to 8 bytes. This ensures
// uniform distribution and avoids prefix collisions (e.g., nodes sharing
// the same region prefix like "syd-node-1" vs "syd-node-2").
func TruncateNodeID(nodeID string) aether.PeerID {
	hash := sha256.Sum256([]byte(nodeID))
	var pid aether.PeerID
	copy(pid[:], hash[:8])
	return pid
}
