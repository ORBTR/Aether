//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package noise

import (
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"

	fnoise "github.com/flynn/noise"
)

var errNonceReplayed = errors.New("vl1: replayed or too-old nonce")

// nonceWindow implements sliding-window replay protection for explicit-nonce
// decryption. Uses a bitmap to track which nonces in the recent window have
// been seen, rejecting duplicates and nonces that fall behind the window.
//
// This solves the fundamental problem with flynn/noise's CipherState: it uses
// sequential nonces that permanently break on out-of-order UDP delivery. By
// extracting the raw Cipher via CipherState.Cipher() and managing nonces
// ourselves, we can tolerate reordering within the window size.
type nonceWindow struct {
	mu      sync.Mutex
	cipher  fnoise.Cipher
	highest uint64 // Highest nonce successfully decrypted
	bitmap  uint64 // Bitmask: bit i = nonce (highest - i) was seen
	window  int    // Window size (max 64 for uint64 bitmap)
}

func newNonceWindow(c fnoise.Cipher, windowSize int) *nonceWindow {
	if windowSize <= 0 || windowSize > 64 {
		windowSize = 64
	}
	return &nonceWindow{
		cipher: c,
		window: windowSize,
	}
}

// Decrypt decrypts using an explicit nonce prepended to the ciphertext as an
// 8-byte big-endian uint64. Returns the plaintext or an error.
// Thread-safe.
func (nw *nonceWindow) Decrypt(dst, ad, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 8 {
		return nil, errors.New("vl1: ciphertext too short for nonce")
	}

	// Extract explicit nonce from first 8 bytes
	n := binary.BigEndian.Uint64(ciphertext[:8])
	ct := ciphertext[8:]

	nw.mu.Lock()
	defer nw.mu.Unlock()

	// Check replay protection BEFORE decryption (reject obvious replays early)
	if n <= nw.highest {
		age := nw.highest - n
		if age >= uint64(nw.window) {
			return nil, errNonceReplayed // Too old
		}
		bit := uint64(1) << age
		if nw.bitmap&bit != 0 {
			return nil, errNonceReplayed // Already seen
		}
	}

	// Decrypt FIRST — only update bitmap on success (no undo needed)
	plaintext, err := nw.cipher.Decrypt(dst, n, ad, ct)
	if err != nil {
		// Decryption failed — no bitmap update, state unchanged
		return nil, err
	}

	// Success — now update bitmap (safe, decryption proved packet is authentic)
	if n > nw.highest {
		shift := n - nw.highest
		if shift >= uint64(nw.window) {
			nw.bitmap = 1
		} else {
			nw.bitmap = (nw.bitmap << shift) | 1
		}
		nw.highest = n
	} else {
		age := nw.highest - n
		nw.bitmap |= uint64(1) << age
	}

	return plaintext, nil
}

// nonceEncryptor handles explicit-nonce encryption with an atomic counter.
// Prepends the 8-byte nonce to the ciphertext so the receiver can extract it.
type nonceEncryptor struct {
	cipher fnoise.Cipher
	nonce  atomic.Uint64
}

func newNonceEncryptor(c fnoise.Cipher) *nonceEncryptor {
	return &nonceEncryptor{cipher: c}
}

// Encrypt encrypts the plaintext, prepending the 8-byte explicit nonce.
// Thread-safe (uses atomic counter — no mutex needed for sends).
func (ne *nonceEncryptor) Encrypt(dst, ad, plaintext []byte) []byte {
	n := ne.nonce.Add(1) - 1 // Start at 0

	// Prepend 8-byte explicit nonce
	var header [8]byte
	binary.BigEndian.PutUint64(header[:], n)
	dst = append(dst, header[:]...)

	// Encrypt using the raw Cipher interface (accepts explicit uint64 nonce)
	return ne.cipher.Encrypt(dst, n, ad, plaintext)
}
