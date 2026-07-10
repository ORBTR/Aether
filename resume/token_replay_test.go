/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package resume

import (
	"crypto/rand"
	"testing"
	"time"
)

// AE-P-29 regression suite: resume tokens must be single-use when validated via
// ValidateOnce, while bare Validate remains intentionally stateless. Names are
// aep29-prefixed to avoid cross-agent symbol collisions in package resume.

func aep29Key(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return key
}

// aep29Backdate returns a fresh token whose timestamp is shifted by age and
// whose HMAC is recomputed to stay valid for that (possibly past) timestamp.
func aep29Backdate(t *testing.T, key []byte, age time.Duration) *Token {
	t.Helper()
	tok, err := GenerateToken(key)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	tok.Timestamp = uint64(time.Now().Add(-age).Unix())
	tok.HMAC = computeTokenHMAC(tok.SessionID, tok.Timestamp, key)
	return tok
}

// AE-P-29 (1): ValidateOnce admits a token once and rejects the replay.
func TestAEP29_ValidateOnceRejectsReplay(t *testing.T) {
	key := aep29Key(t)
	tok, err := GenerateToken(key)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	enc := tok.Encode()

	dec, err := DecodeToken(enc)
	if err != nil {
		t.Fatalf("DecodeToken: %v", err)
	}
	seen := NewSeenTokenSet(0)
	if err := dec.ValidateOnce(key, seen); err != nil {
		t.Fatalf("first ValidateOnce should succeed, got: %v", err)
	}

	// A second presentation of the SAME token (decoded fresh, as an attacker
	// replaying captured wire bytes would) must be rejected.
	dec2, err := DecodeToken(enc)
	if err != nil {
		t.Fatalf("DecodeToken (replay): %v", err)
	}
	if err := dec2.ValidateOnce(key, seen); err == nil {
		t.Fatalf("replayed token must be rejected by ValidateOnce, got nil error")
	}
}

// AE-P-29 (2): bare Validate is intentionally stateless — repeated calls pass.
func TestAEP29_ValidateStatelessRepeats(t *testing.T) {
	key := aep29Key(t)
	tok, err := GenerateToken(key)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := tok.Validate(key); err != nil {
			t.Fatalf("Validate call %d should pass (stateless), got: %v", i, err)
		}
	}
}

// AE-P-29 (3): a forged token (wrong key) must fail on the HMAC check and must
// NOT consume the SessionID slot — a subsequent correct-key ValidateOnce for
// the same SessionID still succeeds, proving a forgery can't burn a live slot.
func TestAEP29_WrongKeyDoesNotConsumeSlot(t *testing.T) {
	key := aep29Key(t)
	other := aep29Key(t)
	tok, err := GenerateToken(key)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	seen := NewSeenTokenSet(0)

	if err := tok.ValidateOnce(other, seen); err == nil {
		t.Fatalf("ValidateOnce with wrong key must fail, got nil error")
	}
	// The real holder must still be able to consume the token exactly once.
	if err := tok.ValidateOnce(key, seen); err != nil {
		t.Fatalf("correct-key ValidateOnce should still succeed after a forged attempt, got: %v", err)
	}
}

// AE-P-29 (4a): an expired token is rejected before it can consume a slot.
func TestAEP29_ExpiredTokenRejected(t *testing.T) {
	key := aep29Key(t)
	tok := aep29Backdate(t, key, MaxTokenAge+time.Hour)
	seen := NewSeenTokenSet(0)
	if err := tok.ValidateOnce(key, seen); err == nil {
		t.Fatalf("expired token must be rejected, got nil error")
	}
}

// AE-P-29 (4b): the seen-set evicts already-expired entries to reclaim space,
// but fails closed (rejects) when full of still-live entries.
func TestAEP29_SeenTokenSetEvictionAndFailClosed(t *testing.T) {
	// Fail-closed: a set full of UNEXPIRED entries rejects a novel nonce
	// rather than forgetting a live one.
	full := NewSeenTokenSet(2)
	future := time.Now().Add(time.Hour)
	if !full.markOrReject([8]byte{1}, future) {
		t.Fatalf("first live insert should be admitted")
	}
	if !full.markOrReject([8]byte{2}, future) {
		t.Fatalf("second live insert should be admitted")
	}
	if full.markOrReject([8]byte{3}, future) {
		t.Fatalf("set full of live entries must reject (fail-closed), got admit")
	}

	// Eviction: a set full of EXPIRED entries reclaims those slots so a novel
	// nonce is admitted.
	stale := NewSeenTokenSet(2)
	past := time.Now().Add(-time.Hour)
	if !stale.markOrReject([8]byte{10}, past) {
		t.Fatalf("first stale insert should be admitted")
	}
	if !stale.markOrReject([8]byte{11}, past) {
		t.Fatalf("second stale insert should be admitted")
	}
	if !stale.markOrReject([8]byte{12}, future) {
		t.Fatalf("expired entries should be evicted to admit a novel nonce, got reject")
	}
}

// AE-P-29 (5): ValidateOnce requires a non-nil SeenTokenSet.
func TestAEP29_ValidateOnceNilSetErrors(t *testing.T) {
	key := aep29Key(t)
	tok, err := GenerateToken(key)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if err := tok.ValidateOnce(key, nil); err == nil {
		t.Fatalf("ValidateOnce with nil SeenTokenSet must error, got nil")
	}
}
