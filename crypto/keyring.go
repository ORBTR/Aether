/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

// Keyring implements HKDF-based per-session key derivation for Aether.
// Derives separate keys for encryption, authentication, and IV generation
// from the transport's shared secret (Noise handshake output).

package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// KeyringSize is the number of bytes in each derived key.
const KeyringSize = 32

// Keyring holds derived session keys for per-frame encryption.
// All keys are derived from a single shared secret using HKDF with
// distinct info strings, ensuring cryptographic separation.
type Keyring struct {
	EncryptionKey [32]byte // ChaCha20-Poly1305 AEAD key
	AuthKey       [32]byte // HMAC key for migration/resume token validation
	IVKey         [32]byte // Additional entropy for nonce generation
}

// DeriveKeyring derives a full keyring from a shared secret and peer identities.
// The shared secret typically comes from the Noise handshake (IK or XX pattern).
// LocalID and remoteID are included in the HKDF info to bind keys to the session.
//
// Key derivation:
//
//	PRK = HKDF-Extract(salt=nil, IKM=sharedSecret)
//	EncryptionKey = HKDF-Expand(PRK, info="aether-enc-v1"||localID||remoteID, L=32)
//	AuthKey       = HKDF-Expand(PRK, info="aether-auth-v1"||localID||remoteID, L=32)
//	IVKey         = HKDF-Expand(PRK, info="aether-iv-v1"||localID||remoteID, L=32)
func DeriveKeyring(sharedSecret []byte, localID, remoteID string) (*Keyring, error) {
	if len(sharedSecret) < 32 {
		return nil, fmt.Errorf("aether crypto: shared secret too short (%d < 32)", len(sharedSecret))
	}

	kr := &Keyring{}

	// Derive encryption key
	if err := deriveKey(sharedSecret, "aether-enc-v1", localID, remoteID, kr.EncryptionKey[:]); err != nil {
		return nil, fmt.Errorf("aether crypto: derive encryption key: %w", err)
	}

	// Derive authentication key (for migration HMAC, resume tokens)
	if err := deriveKey(sharedSecret, "aether-auth-v1", localID, remoteID, kr.AuthKey[:]); err != nil {
		return nil, fmt.Errorf("aether crypto: derive auth key: %w", err)
	}

	// Derive IV key (additional entropy for nonce generation)
	if err := deriveKey(sharedSecret, "aether-iv-v1", localID, remoteID, kr.IVKey[:]); err != nil {
		return nil, fmt.Errorf("aether crypto: derive IV key: %w", err)
	}

	return kr, nil
}

// NewEncryptor creates a FrameEncryptor from this keyring's encryption key.
func (kr *Keyring) NewEncryptor(ordered bool) (*FrameEncryptor, error) {
	return NewFrameEncryptor(kr.EncryptionKey, ordered)
}

// deriveKey uses HKDF-SHA256 to derive a single key.
func deriveKey(secret []byte, purpose, localID, remoteID string, out []byte) error {
	info := []byte(purpose)
	info = append(info, []byte(localID)...)
	info = append(info, []byte(remoteID)...)

	reader := hkdf.New(sha256.New, secret, nil, info)
	if _, err := io.ReadFull(reader, out); err != nil {
		return err
	}
	return nil
}
