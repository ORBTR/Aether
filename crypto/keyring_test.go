/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestDeriveKeyring_Basic(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	kr, err := DeriveKeyring(secret, "local-node-1", "remote-node-2")
	if err != nil {
		t.Fatalf("DeriveKeyring: %v", err)
	}

	// All three keys should be different
	if bytes.Equal(kr.EncryptionKey[:], kr.AuthKey[:]) {
		t.Error("encryption key and auth key should differ")
	}
	if bytes.Equal(kr.EncryptionKey[:], kr.IVKey[:]) {
		t.Error("encryption key and IV key should differ")
	}
	if bytes.Equal(kr.AuthKey[:], kr.IVKey[:]) {
		t.Error("auth key and IV key should differ")
	}

	// Keys should be non-zero
	var zero [32]byte
	if kr.EncryptionKey == zero {
		t.Error("encryption key should not be all zeros")
	}
}

func TestDeriveKeyring_Deterministic(t *testing.T) {
	secret := []byte("shared-secret-for-determinism-test-32b")

	kr1, _ := DeriveKeyring(secret, "local", "remote")
	kr2, _ := DeriveKeyring(secret, "local", "remote")

	if kr1.EncryptionKey != kr2.EncryptionKey {
		t.Error("same inputs should produce same encryption key")
	}
	if kr1.AuthKey != kr2.AuthKey {
		t.Error("same inputs should produce same auth key")
	}
}

func TestDeriveKeyring_DifferentPeers(t *testing.T) {
	secret := []byte("shared-secret-for-peer-diff-test-32b")

	kr1, _ := DeriveKeyring(secret, "local", "remote-A")
	kr2, _ := DeriveKeyring(secret, "local", "remote-B")

	if kr1.EncryptionKey == kr2.EncryptionKey {
		t.Error("different remote peers should produce different keys")
	}
}

func TestDeriveKeyring_ShortSecret(t *testing.T) {
	_, err := DeriveKeyring([]byte("short"), "a", "b")
	if err == nil {
		t.Error("expected error for short secret (<32 bytes)")
	}
}

func TestKeyring_NewEncryptor(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	kr, _ := DeriveKeyring(secret, "local", "remote")

	enc, err := kr.NewEncryptor(true)
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}
	if enc == nil {
		t.Fatal("expected non-nil encryptor")
	}
}

func TestDeriveKeyring_DirectionMatters(t *testing.T) {
	secret := []byte("shared-secret-for-direction-test-32b")

	kr1, _ := DeriveKeyring(secret, "alice", "bob")
	kr2, _ := DeriveKeyring(secret, "bob", "alice")

	if kr1.EncryptionKey == kr2.EncryptionKey {
		t.Error("swapped local/remote should produce different keys")
	}
}
