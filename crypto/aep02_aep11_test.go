/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package crypto

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/ORBTR/aether"
)

// ─── AE-P-02 — ordered-mode counter nonce restarts at zero per encryptor ────
//
// Before the fix, nextNonce() left nonce[0:4] zero and wrote only the atomic
// counter into nonce[4:12]. Two FrameEncryptors that share a key (both
// directions of a session, or a re-installed/resumed key) therefore emitted
// identical (key,nonce) pairs starting from counter=1 — catastrophic
// ChaCha20-Poly1305 nonce reuse. The fix seeds a per-instance random 32-bit
// prefix into nonce[0:4] so those nonce spaces are disjoint.

// TestAEP02_CrossInstanceNonceDisjoint proves two encryptors sharing a key
// produce disjoint nonces on their FIRST frame even though the counter is
// identical (both 1): the random prefix is what separates them.
func TestAEP02_CrossInstanceNonceDisjoint(t *testing.T) {
	key := testKey()
	e1, err := NewFrameEncryptor(key, true)
	if err != nil {
		t.Fatalf("new e1: %v", err)
	}
	e2, err := NewFrameEncryptor(key, true)
	if err != nil {
		t.Fatalf("new e2: %v", err)
	}

	f1 := aep02Frame(t)
	f2 := aep02Frame(t)
	if err := e1.Encrypt(f1); err != nil {
		t.Fatalf("e1 encrypt: %v", err)
	}
	if err := e2.Encrypt(f2); err != nil {
		t.Fatalf("e2 encrypt: %v", err)
	}

	// Counters must both be 1 (each instance restarts at 0 then AddUint64→1).
	c1 := binary.BigEndian.Uint64(f1.Nonce[4:12])
	c2 := binary.BigEndian.Uint64(f2.Nonce[4:12])
	if c1 != 1 || c2 != 1 {
		t.Fatalf("counters: got c1=%d c2=%d, want both 1 (first frame each)", c1, c2)
	}

	// Prefixes (and therefore the whole nonces) must differ.
	if bytes.Equal(f1.Nonce[0:4], f2.Nonce[0:4]) {
		t.Fatalf("AE-P-02 regressed: shared-key encryptors emitted identical nonce "+
			"prefix %x — counter alone restarts at 0, so (key,nonce) is reused", f1.Nonce[0:4])
	}
	if f1.Nonce == f2.Nonce {
		t.Fatalf("AE-P-02 regressed: shared-key encryptors emitted identical nonce %x", f1.Nonce)
	}
}

// TestAEP02_CrossInstanceRoundTrip proves the random prefix does not break
// interop: the nonce travels on the wire in frame.Nonce, so a second encryptor
// with the same key can still decrypt the first's frame.
func TestAEP02_CrossInstanceRoundTrip(t *testing.T) {
	key := testKey()
	e1, _ := NewFrameEncryptor(key, true)
	e2, _ := NewFrameEncryptor(key, true)

	original := []byte("aep02 cross-instance interop")
	f := &aether.Frame{
		SenderID: aether.PeerID{1, 2, 3, 4, 5, 6, 7, 8},
		StreamID: 9,
		Type:     aether.TypeDATA,
		SeqNo:    77,
		Length:   uint32(len(original)),
		Payload:  append([]byte(nil), original...),
	}
	if err := e1.Encrypt(f); err != nil {
		t.Fatalf("e1 encrypt: %v", err)
	}
	if err := e2.Decrypt(f); err != nil {
		t.Fatalf("AE-P-02 regressed: peer encryptor could not decrypt (prefix broke interop): %v", err)
	}
	if !bytes.Equal(f.Payload, original) {
		t.Fatalf("round-trip payload mismatch: got %q want %q", f.Payload, original)
	}
}

// TestAEP02_ReinstallNoReplay proves that re-installing the key (a fresh
// encryptor whose counter resets to 0) does not replay the prior instance's
// nonces, because the fresh instance draws a fresh prefix.
func TestAEP02_ReinstallNoReplay(t *testing.T) {
	key := testKey()
	const n = 1000

	seen := make(map[aether.Nonce]bool, 2*n)
	e1, _ := NewFrameEncryptor(key, true)
	for i := 0; i < n; i++ {
		f := aep02Frame(t)
		if err := e1.Encrypt(f); err != nil {
			t.Fatalf("e1 encrypt %d: %v", i, err)
		}
		seen[f.Nonce] = true
	}

	// Re-install: fresh encryptor, counter resets to 0.
	e2, _ := NewFrameEncryptor(key, true)
	for i := 0; i < n; i++ {
		f := aep02Frame(t)
		if err := e2.Encrypt(f); err != nil {
			t.Fatalf("e2 encrypt %d: %v", i, err)
		}
		if seen[f.Nonce] {
			t.Fatalf("AE-P-02 regressed: re-installed key replayed nonce %x at frame %d "+
				"(counter reset to 0 with no fresh prefix)", f.Nonce, i)
		}
	}
}

// TestAEP02_PrefixStableCounterMonotonic asserts the intra-instance invariants:
// nonce[0:4] is a constant per-instance prefix and nonce[4:12] increments.
func TestAEP02_PrefixStableCounterMonotonic(t *testing.T) {
	e, _ := NewFrameEncryptor(testKey(), true)

	var prefix [4]byte
	var lastCounter uint64
	for i := 0; i < 256; i++ {
		f := aep02Frame(t)
		if err := e.Encrypt(f); err != nil {
			t.Fatalf("encrypt %d: %v", i, err)
		}
		if i == 0 {
			copy(prefix[:], f.Nonce[0:4])
		} else if !bytes.Equal(prefix[:], f.Nonce[0:4]) {
			t.Fatalf("AE-P-02: prefix changed within instance at frame %d: %x != %x",
				i, f.Nonce[0:4], prefix)
		}
		c := binary.BigEndian.Uint64(f.Nonce[4:12])
		if c != lastCounter+1 {
			t.Fatalf("AE-P-02: counter not strictly monotonic at frame %d: got %d want %d",
				i, c, lastCounter+1)
		}
		lastCounter = c
	}
}

// aep02Frame builds a fresh 32-byte DATA frame for encryption.
func aep02Frame(t *testing.T) *aether.Frame {
	t.Helper()
	return &aether.Frame{
		Type:    aether.TypeDATA,
		StreamID: 1,
		Length:  32,
		Payload: make([]byte, 32),
	}
}

// ─── AE-P-11 — DecryptWithNonce authenticated with nil AAD ──────────────────
//
// The 0x87 short-encrypted decrypt path opened with nil AAD while Decrypt()
// binds the frame header (SenderID/ReceiverID/StreamID/SeqNo/Length) into the
// Poly1305 tag. The fix makes DecryptWithNonce authenticate with
// frame.HeaderBytes() too, so a re-enabled send side cannot leave those header
// fields unauthenticated.

// TestAEP11_DecryptWithNonceRoundTrip builds a sealed envelope by hand (the
// 0x87 send path is dead) and confirms DecryptWithNonce recovers the plaintext
// when the header used at seal time matches.
func TestAEP11_DecryptWithNonceRoundTrip(t *testing.T) {
	e, _ := NewFrameEncryptor(testKey(), true)
	plaintext := []byte("aep11 header-authenticated payload")

	nonce := aep11Nonce(e)
	f := aep11SealedFrame(e, nonce, plaintext)

	if err := e.DecryptWithNonce(f, nonce); err != nil {
		t.Fatalf("AE-P-11: round-trip DecryptWithNonce failed: %v", err)
	}
	if !bytes.Equal(f.Payload, plaintext) {
		t.Fatalf("AE-P-11: decrypted payload mismatch: got %q want %q", f.Payload, plaintext)
	}
}

// TestAEP11_DecryptWithNonceRejectsTamperedHeader is the core regression: after
// sealing with a header AAD, flipping a header field must make DecryptWithNonce
// FAIL. Under the pre-fix nil-AAD code the tampered frame decrypted cleanly.
func TestAEP11_DecryptWithNonceRejectsTamperedHeader(t *testing.T) {
	e, _ := NewFrameEncryptor(testKey(), true)
	plaintext := []byte("aep11 tamper detection")

	nonce := aep11Nonce(e)
	f := aep11SealedFrame(e, nonce, plaintext)

	// Tamper the header (StreamID/SeqNo feed HeaderBytes()) after sealing.
	f.SeqNo ^= 0x5A5A

	if err := e.DecryptWithNonce(f, nonce); err == nil {
		t.Fatalf("AE-P-11 regressed: DecryptWithNonce accepted a frame whose header was "+
			"tampered after sealing — the 0x87 path is still authenticating with nil AAD")
	}
}

// TestAEP11_DecryptWithNonceInvalidNonceSize preserves the size guard.
func TestAEP11_DecryptWithNonceInvalidNonceSize(t *testing.T) {
	e, _ := NewFrameEncryptor(testKey(), true)
	f := &aether.Frame{Type: aether.TypeDATA, Length: 4, Payload: []byte{1, 2, 3, 4}}
	if err := e.DecryptWithNonce(f, []byte{1, 2, 3}); err == nil {
		t.Fatalf("AE-P-11: expected invalid-nonce-size error")
	}
}

// aep11Nonce returns a fixed, correctly-sized nonce for the encryptor's AEAD.
func aep11Nonce(e *FrameEncryptor) []byte {
	nonce := make([]byte, e.aead.NonceSize())
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	return nonce
}

// aep11SealedFrame builds a frame whose Payload is sealed under the header AAD,
// mirroring the intended 0x87 envelope. frame.Length is set to the ciphertext
// length (as the receive path does) so HeaderBytes() matches at open time.
func aep11SealedFrame(e *FrameEncryptor, nonce, plaintext []byte) *aether.Frame {
	f := &aether.Frame{
		SenderID: aether.PeerID{0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8},
		StreamID: 7,
		Type:     aether.TypeDATA,
		SeqNo:    4321,
	}
	f.Length = uint32(len(plaintext) + e.Overhead())
	ad := f.HeaderBytes()
	ciphertext := e.aead.Seal(nil, nonce, plaintext, ad)
	f.Payload = ciphertext
	return f
}
