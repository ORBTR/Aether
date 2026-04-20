//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

package noise

import (
	"testing"
	"time"

	aether "github.com/ORBTR/aether"
)

// TestResumeMaterial_RoundTrip verifies encode/decode symmetry of the
// on-wire resume material blob.
func TestResumeMaterial_RoundTrip(t *testing.T) {
	orig := &resumeMaterial{
		Opaque:    []byte{0x01, 0x02, 0x03, 0x04, 0x05},
		Caps:      0xdeadbeef,
		ExpiresAt: time.Unix(1_700_000_000, 0),
	}
	for i := range orig.SendKey {
		orig.SendKey[i] = byte(i)
		orig.RecvKey[i] = byte(255 - i)
	}

	encoded := encodeResumeMaterial(orig)
	decoded, err := decodeResumeMaterial(encoded)
	if err != nil {
		t.Fatalf("decodeResumeMaterial: %v", err)
	}
	if string(decoded.Opaque) != string(orig.Opaque) {
		t.Errorf("Opaque mismatch: got %x, want %x", decoded.Opaque, orig.Opaque)
	}
	if decoded.SendKey != orig.SendKey {
		t.Errorf("SendKey mismatch")
	}
	if decoded.RecvKey != orig.RecvKey {
		t.Errorf("RecvKey mismatch")
	}
	if decoded.Caps != orig.Caps {
		t.Errorf("Caps mismatch: got %x, want %x", decoded.Caps, orig.Caps)
	}
	if !decoded.ExpiresAt.Equal(orig.ExpiresAt) {
		t.Errorf("ExpiresAt mismatch: got %v, want %v", decoded.ExpiresAt, orig.ExpiresAt)
	}
}

// TestInitiatorTicketCache_FIFOEviction verifies the cache evicts the
// oldest entry when at cap.
func TestInitiatorTicketCache_FIFOEviction(t *testing.T) {
	cache := newInitiatorTicketCache(2)

	m1 := &resumeMaterial{Opaque: []byte{1}, ExpiresAt: time.Now().Add(time.Hour)}
	m2 := &resumeMaterial{Opaque: []byte{2}, ExpiresAt: time.Now().Add(time.Hour)}
	m3 := &resumeMaterial{Opaque: []byte{3}, ExpiresAt: time.Now().Add(time.Hour)}

	cache.Store(aether.NodeID("peer-A"), m1)
	cache.Store(aether.NodeID("peer-B"), m2)
	cache.Store(aether.NodeID("peer-C"), m3) // evicts peer-A

	if got := cache.Lookup(aether.NodeID("peer-A")); got != nil {
		t.Errorf("peer-A should have been evicted, got %v", got)
	}
	if got := cache.Lookup(aether.NodeID("peer-B")); got == nil {
		t.Errorf("peer-B should be cached")
	}
	if got := cache.Lookup(aether.NodeID("peer-C")); got == nil {
		t.Errorf("peer-C should be cached")
	}
}

// TestInitiatorTicketCache_LazyExpiry verifies that Lookup evicts
// expired entries without needing an explicit cleanup call.
func TestInitiatorTicketCache_LazyExpiry(t *testing.T) {
	cache := newInitiatorTicketCache(4)
	fresh := &resumeMaterial{Opaque: []byte{1}, ExpiresAt: time.Now().Add(time.Hour)}
	stale := &resumeMaterial{Opaque: []byte{2}, ExpiresAt: time.Now().Add(-time.Second)}

	cache.Store(aether.NodeID("fresh"), fresh)
	cache.Store(aether.NodeID("stale"), stale)

	if cache.Lookup(aether.NodeID("fresh")) == nil {
		t.Errorf("fresh lookup returned nil")
	}
	if cache.Lookup(aether.NodeID("stale")) != nil {
		t.Errorf("stale lookup should return nil (lazy evict)")
	}
	// After lazy evict, subsequent Store should fit without eviction.
	cache.Store(aether.NodeID("stale"), fresh)
	if cache.Lookup(aether.NodeID("stale")) == nil {
		t.Errorf("re-stored stale peer should be present")
	}
}

// TestSeenTicketCache_ReplayRejection verifies the replay guard admits
// novel nonces once and rejects duplicates.
func TestSeenTicketCache_ReplayRejection(t *testing.T) {
	cache := newSeenTicketCache(16)
	nonce := []byte{0xAA, 0xBB, 0xCC, 0xDD}

	if !cache.MarkOrReject(nonce) {
		t.Errorf("first MarkOrReject should admit")
	}
	if cache.MarkOrReject(nonce) {
		t.Errorf("second MarkOrReject of same nonce should reject")
	}
	// Different nonce admits.
	other := []byte{0x11, 0x22, 0x33, 0x44}
	if !cache.MarkOrReject(other) {
		t.Errorf("different nonce should admit")
	}
}

// TestBuildInitiatorCipherStates verifies raw keys round-trip through
// flynn/noise's UnsafeNewCipherState. The recovered CipherStates must
// be able to Encrypt/Decrypt each other's output symmetrically — that's
// the whole point of resumption.
func TestBuildInitiatorCipherStates(t *testing.T) {
	var sendKey, recvKey [32]byte
	for i := range sendKey {
		sendKey[i] = byte(i + 1)
		recvKey[i] = byte(100 + i)
	}

	// Peer A uses (sendKey, recvKey). Peer B's perspective swaps them
	// so A→B encrypted with A's send can be decrypted with B's recv.
	aSend, aRecv, err := buildInitiatorCipherStates(sendKey, recvKey)
	if err != nil {
		t.Fatalf("buildInitiatorCipherStates A: %v", err)
	}
	bSend, bRecv, err := buildInitiatorCipherStates(recvKey, sendKey)
	if err != nil {
		t.Fatalf("buildInitiatorCipherStates B: %v", err)
	}

	// A encrypts with aSend; B decrypts with bRecv.
	plaintext := []byte("hello resumed world")
	sealed, err := aSend.Encrypt(nil, nil, plaintext)
	if err != nil {
		t.Fatalf("aSend.Encrypt: %v", err)
	}
	opened, err := bRecv.Decrypt(nil, nil, sealed)
	if err != nil {
		t.Fatalf("bRecv.Decrypt: %v", err)
	}
	if string(opened) != string(plaintext) {
		t.Errorf("plaintext mismatch: got %q, want %q", opened, plaintext)
	}

	// Reverse direction: B encrypts with bSend; A decrypts with aRecv.
	plaintext2 := []byte("reply direction")
	sealed2, err := bSend.Encrypt(nil, nil, plaintext2)
	if err != nil {
		t.Fatalf("bSend.Encrypt: %v", err)
	}
	opened2, err := aRecv.Decrypt(nil, nil, sealed2)
	if err != nil {
		t.Fatalf("aRecv.Decrypt: %v", err)
	}
	if string(opened2) != string(plaintext2) {
		t.Errorf("reverse plaintext mismatch: got %q, want %q", opened2, plaintext2)
	}
}
