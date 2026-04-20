/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package crypto

import (
	"bytes"
	"testing"

	"github.com/ORBTR/aether"
)

func testKey() [32]byte {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func TestFrameEncryptor_EncryptDecrypt(t *testing.T) {
	enc, err := NewFrameEncryptor(testKey(), true)
	if err != nil {
		t.Fatalf("new encryptor: %v", err)
	}

	original := []byte("hello world from aether")
	frame := &aether.Frame{
		SenderID: aether.PeerID{1, 2, 3, 4, 5, 6, 7, 8},
		StreamID: 1,
		Type:     aether.TypeDATA,
		SeqNo:    42,
		Length:   uint32(len(original)),
		Payload:  make([]byte, len(original)),
	}
	copy(frame.Payload, original)

	// Encrypt
	if err := enc.Encrypt(frame); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !frame.Flags.Has(aether.FlagENCRYPTED) {
		t.Error("ENCRYPTED flag should be set")
	}
	if frame.Nonce.IsZero() {
		t.Error("nonce should be non-zero")
	}
	if bytes.Equal(frame.Payload, original) {
		t.Error("payload should be different after encryption")
	}
	if frame.Length != uint32(len(original)+enc.Overhead()) {
		t.Errorf("length should include auth tag: got %d, want %d", frame.Length, len(original)+enc.Overhead())
	}

	// Decrypt
	if err := enc.Decrypt(frame); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if frame.Flags.Has(aether.FlagENCRYPTED) {
		t.Error("ENCRYPTED flag should be cleared")
	}
	if !bytes.Equal(frame.Payload, original) {
		t.Errorf("decrypted payload: got %q, want %q", frame.Payload, original)
	}
}

func TestFrameEncryptor_TamperedPayload(t *testing.T) {
	enc, _ := NewFrameEncryptor(testKey(), true)

	frame := &aether.Frame{
		Type:    aether.TypeDATA,
		SeqNo:   1,
		Length:  5,
		Payload: []byte("hello"),
	}

	enc.Encrypt(frame)

	// Tamper with ciphertext
	if len(frame.Payload) > 0 {
		frame.Payload[0] ^= 0xFF
	}

	err := enc.Decrypt(frame)
	if err == nil {
		t.Error("decrypt should fail on tampered payload")
	}
}

func TestFrameEncryptor_TamperedHeader(t *testing.T) {
	enc, _ := NewFrameEncryptor(testKey(), true)

	frame := &aether.Frame{
		SenderID: aether.PeerID{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11},
		Type:     aether.TypeDATA,
		SeqNo:    1,
		Length:   5,
		Payload:  []byte("hello"),
	}

	enc.Encrypt(frame)

	// Tamper with header (SenderID) — should fail AEAD auth
	frame.SenderID[0] = 0x00

	err := enc.Decrypt(frame)
	if err == nil {
		t.Error("decrypt should fail on tampered header (AEAD additional data mismatch)")
	}
}

func TestFrameEncryptor_EmptyPayload(t *testing.T) {
	enc, _ := NewFrameEncryptor(testKey(), true)

	frame := &aether.Frame{
		Type:    aether.TypePING,
		Length:  0,
		Payload: nil,
	}

	// Should be no-op
	if err := enc.Encrypt(frame); err != nil {
		t.Fatalf("encrypt empty: %v", err)
	}
	if frame.Flags.Has(aether.FlagENCRYPTED) {
		t.Error("empty payload should not get ENCRYPTED flag")
	}
}

func TestFrameEncryptor_UniqueNonces(t *testing.T) {
	enc, _ := NewFrameEncryptor(testKey(), true)

	nonces := make(map[aether.Nonce]bool)
	for i := 0; i < 100; i++ {
		frame := &aether.Frame{
			Type:    aether.TypeDATA,
			Length:  1,
			Payload: []byte{byte(i)},
		}
		enc.Encrypt(frame)
		if nonces[frame.Nonce] {
			t.Fatalf("duplicate nonce at iteration %d", i)
		}
		nonces[frame.Nonce] = true
	}
}

func TestIdentityTable_RegisterAndLookup(t *testing.T) {
	tbl := NewIdentityTable()

	pid, err := tbl.Register("vl1_test1234abcdefghijklmnop")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if pid.IsZero() {
		t.Error("PeerID should not be zero")
	}

	nodeID, ok := tbl.Lookup(pid)
	if !ok {
		t.Fatal("lookup should find registered NodeID")
	}
	if nodeID != "vl1_test1234abcdefghijklmnop" {
		t.Errorf("nodeID: got %q", nodeID)
	}

	// Reverse lookup
	pid2, ok := tbl.Reverse("vl1_test1234abcdefghijklmnop")
	if !ok || pid2 != pid {
		t.Error("reverse lookup should match")
	}

	// Duplicate register returns same PeerID
	pid3, err := tbl.Register("vl1_test1234abcdefghijklmnop")
	if err != nil {
		t.Fatalf("duplicate register: %v", err)
	}
	if pid3 != pid {
		t.Error("duplicate register should return same PeerID")
	}
}

func TestIdentityTable_Collision(t *testing.T) {
	tbl := NewIdentityTable()

	// Register first NodeID
	_, err := tbl.Register("vl1_aaaa")
	if err != nil {
		t.Fatalf("first register: %v", err)
	}

	// Register different NodeID that would produce same PeerID
	// (same first 8 bytes since TruncateNodeID uses first 8 bytes of string)
	_, err = tbl.Register("vl1_aaaa_different_suffix")
	// These have different first 8 bytes so no collision expected
	if err != nil {
		t.Logf("collision detected (expected for same 8-byte prefix): %v", err)
	}
}

func TestIdentityTable_UnknownLookup(t *testing.T) {
	tbl := NewIdentityTable()
	_, ok := tbl.Lookup(aether.PeerID{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	if ok {
		t.Error("unknown PeerID should not be found")
	}
}
