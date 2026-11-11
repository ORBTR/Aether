/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

// Keyring implements HKDF-based per-session key derivation for Aether.
// Derives separate keys for sealing, opening, authentication, and IV generation
// from a shared secret of at least 32 bytes that both ends of the session hold
// and the caller supplies.

package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// KeyringSize is the number of bytes in each derived key.
const KeyringSize = 32

// Keyring holds one end's derived session keys for per-frame encryption.
// All keys are derived from a single shared secret using HKDF with
// distinct info strings, ensuring cryptographic separation.
//
// The two ends of a session derive mirrored keyrings: one end's EncryptionKey
// is the other end's OpenKey, so each direction of the session has its own key
// and each end's ordered nonce counter runs under a key only that end seals
// with. AuthKey is one key both ends hold, so an HMAC one end computes verifies
// at the other.
type Keyring struct {
	EncryptionKey [32]byte // ChaCha20-Poly1305 key sealing the frames this end sends (local to remote)
	OpenKey       [32]byte // ChaCha20-Poly1305 key opening the frames this end receives (remote to local)
	AuthKey       [32]byte // HMAC key for migration/resume token validation, the same at both ends
	IVKey         [32]byte // Additional entropy for nonce generation in the local-to-remote direction
}

// DeriveKeyring derives one end's keyring from a shared secret and the two
// identities, the end's own first: the peer calls it with the identities
// swapped and derives the mirrored keyring.
//
// Key derivation, where id(x) is x's length as a uvarint followed by x, so no
// two identity pairs give one info string:
//
//	PRK = HKDF-Extract(salt=nil, IKM=sharedSecret)
//	EncryptionKey = HKDF-Expand(PRK, info="aether-enc-v1"||id(localID)||id(remoteID), L=32)
//	OpenKey       = HKDF-Expand(PRK, info="aether-enc-v1"||id(remoteID)||id(localID), L=32)
//	AuthKey       = HKDF-Expand(PRK, info="aether-auth-v1"||id(lower)||id(higher), L=32)
//	IVKey         = HKDF-Expand(PRK, info="aether-iv-v1"||id(localID)||id(remoteID), L=32)
//
// lower and higher are the two identities in byte order, so both ends name
// them alike.
func DeriveKeyring(sharedSecret []byte, localID, remoteID string) (*Keyring, error) {
	if len(sharedSecret) < 32 {
		return nil, fmt.Errorf("aether crypto: shared secret too short (%d < 32)", len(sharedSecret))
	}

	kr := &Keyring{}

	// Derive the sealing key: this end to the peer
	if err := deriveKey(sharedSecret, "aether-enc-v1", localID, remoteID, kr.EncryptionKey[:]); err != nil {
		return nil, fmt.Errorf("aether crypto: derive encryption key: %w", err)
	}

	// Derive the opening key: the peer's sealing key, the peer to this end
	if err := deriveKey(sharedSecret, "aether-enc-v1", remoteID, localID, kr.OpenKey[:]); err != nil {
		return nil, fmt.Errorf("aether crypto: derive open key: %w", err)
	}

	// Derive authentication key (for migration HMAC, resume tokens), over the
	// identities in one order so both ends hold it
	lower, higher := localID, remoteID
	if higher < lower {
		lower, higher = higher, lower
	}
	if err := deriveKey(sharedSecret, "aether-auth-v1", lower, higher, kr.AuthKey[:]); err != nil {
		return nil, fmt.Errorf("aether crypto: derive auth key: %w", err)
	}

	// Derive IV key (additional entropy for nonce generation)
	if err := deriveKey(sharedSecret, "aether-iv-v1", localID, remoteID, kr.IVKey[:]); err != nil {
		return nil, fmt.Errorf("aether crypto: derive IV key: %w", err)
	}

	return kr, nil
}

// NewEncryptor creates a FrameEncryptor that seals with this keyring's
// EncryptionKey and opens with its OpenKey, so the encryptor built at the
// peer's end from the mirrored keyring opens what this one seals.
func (kr *Keyring) NewEncryptor(ordered bool) (*FrameEncryptor, error) {
	return NewDirectionalFrameEncryptor(kr.EncryptionKey, kr.OpenKey, ordered)
}

// deriveKey uses HKDF-SHA256 to derive a single key, binding purpose and the
// two identities, each identity preceded by its length.
func deriveKey(secret []byte, purpose, firstID, secondID string, out []byte) error {
	info := []byte(purpose)
	info = binary.AppendUvarint(info, uint64(len(firstID)))
	info = append(info, firstID...)
	info = binary.AppendUvarint(info, uint64(len(secondID)))
	info = append(info, secondID...)

	reader := hkdf.New(sha256.New, secret, nil, info)
	if _, err := io.ReadFull(reader, out); err != nil {
		return err
	}
	return nil
}
