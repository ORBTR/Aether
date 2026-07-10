//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

package noise

import (
	"crypto/rand"
	"encoding/binary"
	"strings"
	"testing"

	aether "github.com/ORBTR/aether"
)

// TestTicketRoundTripPreservesScopeID is the AE-H-07 regression: the tenant
// scope the original session was bound to must survive an IssueTicket ->
// DecryptTicket round-trip. Before the fix the ticket carried no scope, so a
// resumed session came back scopeless ("") and bypassed resolveRelayTarget's
// cross-tenant isolation guard. Also covers the two rejection paths added with
// the scope suffix: an over-length scope on issue and a length-prefix that
// disagrees with the actual suffix on decrypt.
func TestTicketRoundTripPreservesScopeID(t *testing.T) {
	ts, err := NewTicketStore()
	if err != nil {
		t.Fatalf("NewTicketStore: %v", err)
	}

	// 32-byte peer ID so it survives the fixed [8:40] slot byte-for-byte.
	peerID := aether.NodeID(strings.Repeat("p", 32))

	var sendKey, recvKey [32]byte
	for i := range sendKey {
		sendKey[i] = byte(i + 1)
		recvKey[i] = byte(100 + i)
	}

	scopes := []string{"", "tenant-A", strings.Repeat("x", MaxScopeIDLength)}
	for _, scope := range scopes {
		// Fresh nonce-0 CipherStates for each issue (IssueTicket rejects nonce != 0).
		send, recv, err := buildResumeCipherStates(sendKey, recvKey)
		if err != nil {
			t.Fatalf("buildResumeCipherStates: %v", err)
		}

		blob, err := ts.IssueTicket(peerID, send, recv, capExplicitNonce, scope)
		if err != nil {
			t.Fatalf("IssueTicket(scope=%q): %v", scope, err)
		}

		ticket, err := ts.DecryptTicket(blob)
		if err != nil {
			t.Fatalf("DecryptTicket(scope=%q): %v", scope, err)
		}

		if ticket.ScopeID != scope {
			t.Errorf("scope=%q: ScopeID = %q, want %q", scope, ticket.ScopeID, scope)
		}
		if ticket.PeerID != peerID {
			t.Errorf("scope=%q: PeerID = %q, want %q", scope, ticket.PeerID, peerID)
		}
		if ticket.Caps != capExplicitNonce {
			t.Errorf("scope=%q: Caps = %d, want %d", scope, ticket.Caps, capExplicitNonce)
		}
		if ticket.SendKey != sendKey {
			t.Errorf("scope=%q: SendKey mismatch", scope)
		}
		if ticket.RecvKey != recvKey {
			t.Errorf("scope=%q: RecvKey mismatch", scope)
		}
	}

	// Over-length scope must be rejected at issue time (never truncate the uint16).
	send, recv, err := buildResumeCipherStates(sendKey, recvKey)
	if err != nil {
		t.Fatalf("buildResumeCipherStates: %v", err)
	}
	if _, err := ts.IssueTicket(peerID, send, recv, capExplicitNonce, strings.Repeat("x", MaxScopeIDLength+1)); err != ErrTenantIDTooLong {
		t.Errorf("IssueTicket(over-length scope) err = %v, want ErrTenantIDTooLong", err)
	}

	// A ticket whose declared scope length disagrees with the actual suffix
	// length must be rejected (guards against a truncated/forged suffix).
	// Craft a plaintext with a 2-byte suffix but a length prefix claiming 5,
	// then seal it with the store's own GCM so decryption succeeds and the
	// length-consistency check is what rejects it.
	bad := make([]byte, ticketPlaintextSize+ticketScopeLenSize+2)
	binary.BigEndian.PutUint16(bad[ticketPlaintextSize:ticketPlaintextSize+ticketScopeLenSize], 5)
	nonce := make([]byte, ticketNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand nonce: %v", err)
	}
	sealed := ts.gcm.Seal(nonce, nonce, bad, nil)
	if _, err := ts.DecryptTicket(sealed); err != ErrTicketInvalid {
		t.Errorf("DecryptTicket(mismatched scopeLen) err = %v, want ErrTicketInvalid", err)
	}
}
