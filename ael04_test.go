/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import (
	"crypto/ed25519"
	"testing"
)

// TestAEL04_ToPeerID is the AE-L-04 regression test: NodeID.ToPeerID must
// derive the 8-byte wire PeerID from the decoded key fingerprint (64 bits),
// NOT from the first 8 textual bytes of the canonical string (which are the
// constant "vl1_" prefix plus only 4 base32 chars ~20 bits — a near-total
// collision across the mesh).
func TestAEL04_ToPeerID(t *testing.T) {
	// (1) Fingerprint contract: PeerID == first 8 bytes of Fingerprint().
	pub := make([]byte, ed25519.PublicKeySize)
	for i := range pub {
		pub[i] = byte(i + 1)
	}
	id, err := NewNodeID(pub)
	if err != nil {
		t.Fatalf("NewNodeID: %v", err)
	}
	fp, err := id.Fingerprint()
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	var want PeerID
	copy(want[:], fp)
	if got := id.ToPeerID(); got != want {
		t.Fatalf("ToPeerID = %x, want first-8-of-fingerprint %x", got, want)
	}

	// (2) Prefix-collision guard: two valid NodeIDs sharing "vl1_aaaa"
	// (identical first 8 TEXTUAL bytes → identical PeerID under the pre-fix
	// textual copy) must now produce distinct PeerIDs.
	a := NodeID("vl1_aaaabbbbccccddddeeeeffffgg")
	b := NodeID("vl1_aaaaccccddddeeeeffffgggghh")
	if string(a)[:8] != string(b)[:8] {
		t.Fatalf("setup: ids must share first 8 textual bytes")
	}
	// Both suffixes must be decodable so ToPeerID takes the fingerprint path.
	if _, err := a.Fingerprint(); err != nil {
		t.Fatalf("setup: NodeID a must decode: %v", err)
	}
	if _, err := b.Fingerprint(); err != nil {
		t.Fatalf("setup: NodeID b must decode: %v", err)
	}
	if a.ToPeerID() == b.ToPeerID() {
		t.Fatalf("prefix-colliding NodeIDs produced identical PeerID %x (AE-L-04 regressed)", a.ToPeerID())
	}
}
