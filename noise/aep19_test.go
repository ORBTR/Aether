//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

package noise

import (
	"strings"
	"testing"
	"time"

	aether "github.com/ORBTR/aether"
)

// AE-P-19 regression: after RotateKey the previous ticket key must be retired
// once one ticket TTL has elapsed, not held until the next RotateKey call. This
// bounds the window in which a FORGED ticket (built with a stolen previous key
// and an attacker-chosen far-future ExpiresAt) can still be decrypted, so a
// single rotation is enough to drop a compromised key — while an honestly-issued
// pre-rotation ticket still resumes throughout the overlap window.

// aep19MakeKey returns a distinct 32-byte AES-256 key seeded by b.
func aep19MakeKey(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b + byte(i)
	}
	return k
}

// aep19IssueBlob issues a ticket from ts using fresh nonce-0 cipher states.
// The ticket's ExpiresAt is derived from ts.ttl (set at construction), so a
// long-TTL store yields a far-future ExpiresAt that the per-ticket expiry guard
// alone can never retire — isolating the prev-key retirement behaviour.
func aep19IssueBlob(t *testing.T, ts *TicketStore) []byte {
	t.Helper()
	peerID := aether.NodeID(strings.Repeat("p", 32))
	var sendKey, recvKey [32]byte
	for i := range sendKey {
		sendKey[i] = byte(i + 1)
		recvKey[i] = byte(100 + i)
	}
	send, recv, err := buildResumeCipherStates(sendKey, recvKey)
	if err != nil {
		t.Fatalf("buildResumeCipherStates: %v", err)
	}
	blob, err := ts.IssueTicket(peerID, send, recv, capExplicitNonce, "")
	if err != nil {
		t.Fatalf("IssueTicket: %v", err)
	}
	return blob
}

// TestAEP19_PrevKeyRetiredAfterTTL proves the fix: the previous key stops
// decrypting once its one-TTL overlap window elapses, even for a ticket with a
// far-future ExpiresAt. Before AE-P-19 the prevGCM fallback was unbounded and
// this second decrypt succeeded indefinitely (until an unrelated 2nd rotation).
func TestAEP19_PrevKeyRetiredAfterTTL(t *testing.T) {
	keyA := aep19MakeKey(1)
	keyB := aep19MakeKey(200)

	// Attacker holds the soon-to-be-previous key and forges a ticket with a
	// far-future ExpiresAt (100h store TTL), so the per-ticket expiry guard can
	// never retire it — only prev-key retirement can.
	attacker, err := NewTicketStoreWithKey(keyA, 100*time.Hour)
	if err != nil {
		t.Fatalf("attacker store: %v", err)
	}
	blob := aep19IssueBlob(t, attacker)

	// Victim rotates keyA -> keyB with a short overlap window.
	const window = 100 * time.Millisecond
	victim, err := NewTicketStoreWithKey(keyA, window)
	if err != nil {
		t.Fatalf("victim store: %v", err)
	}
	if err := victim.RotateKey(keyB); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	// Inside the overlap window the previous key is still honoured (capability
	// preserved — this decrypt runs microseconds after rotation).
	if _, err := victim.DecryptTicket(blob); err != nil {
		t.Fatalf("within overlap window: DecryptTicket = %v, want success", err)
	}

	// After the window the previous key must be retired despite the forged
	// far-future ExpiresAt. This is the regression AE-P-19 locks down.
	time.Sleep(window + 150*time.Millisecond)
	if _, err := victim.DecryptTicket(blob); err != ErrTicketDecrypt {
		t.Fatalf("after overlap window: DecryptTicket err = %v, want ErrTicketDecrypt", err)
	}
}

// TestAEP19_PrevKeyOverlapStillWorks guards the preserved capability: an
// honestly-issued pre-rotation ticket must still resume immediately after a
// rotation (well within the overlap window). The guard must not shrink the
// promised mid-rotation overlap.
func TestAEP19_PrevKeyOverlapStillWorks(t *testing.T) {
	keyA := aep19MakeKey(1)
	keyB := aep19MakeKey(200)

	ts, err := NewTicketStoreWithKey(keyA, time.Hour)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	blob := aep19IssueBlob(t, ts)
	if err := ts.RotateKey(keyB); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if _, err := ts.DecryptTicket(blob); err != nil {
		t.Fatalf("mid-rotation overlap: DecryptTicket = %v, want success", err)
	}
}

// TestAEP19_NeverRotatedNoOp confirms the guard is inert on a store that never
// rotated: prevGCM is nil and prevInstalledAt is zero, so the current key
// decrypts normally.
func TestAEP19_NeverRotatedNoOp(t *testing.T) {
	ts, err := NewTicketStoreWithKey(aep19MakeKey(1), time.Hour)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	blob := aep19IssueBlob(t, ts)
	if _, err := ts.DecryptTicket(blob); err != nil {
		t.Fatalf("never-rotated store: DecryptTicket = %v, want success", err)
	}
}
