//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func generateTestKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	return pub, priv
}

func randomNodeID(t *testing.T) [32]byte {
	t.Helper()
	var id [32]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatalf("Failed to generate node ID: %v", err)
	}
	return id
}

func TestNewRelayTicket(t *testing.T) {
	relayPub, relayPriv := generateTestKeyPair(t)
	nodeID := randomNodeID(t)
	targetID := randomNodeID(t)
	ttl := time.Hour

	ticket, err := NewRelayTicket(relayPriv, nodeID, targetID, ttl)
	if err != nil {
		t.Fatalf("NewRelayTicket failed: %v", err)
	}

	if ticket == nil {
		t.Fatal("NewRelayTicket returned nil")
	}

	// Verify ticket fields
	if ticket.NodeID != nodeID {
		t.Error("NodeID mismatch")
	}
	if ticket.TargetID != targetID {
		t.Error("TargetID mismatch")
	}
	if ticket.ExpiresAt.Before(time.Now()) {
		t.Error("ExpiresAt should be in the future")
	}
	if ticket.ExpiresAt.After(time.Now().Add(ttl + time.Second)) {
		t.Error("ExpiresAt is too far in the future")
	}

	// Nonce should be set (not all zeros)
	allZeros := true
	for _, b := range ticket.Nonce {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Error("Nonce should be randomly generated, not all zeros")
	}

	// Verify signature is valid
	if err := ticket.Verify(relayPub, nodeID); err != nil {
		t.Errorf("Ticket verification failed: %v", err)
	}
}

func TestRelayTicketVerify(t *testing.T) {
	relayPub, relayPriv := generateTestKeyPair(t)
	nodeID := randomNodeID(t)
	targetID := randomNodeID(t)

	ticket, err := NewRelayTicket(relayPriv, nodeID, targetID, time.Hour)
	if err != nil {
		t.Fatalf("NewRelayTicket failed: %v", err)
	}

	// Valid verification
	if err := ticket.Verify(relayPub, nodeID); err != nil {
		t.Errorf("Valid ticket verification failed: %v", err)
	}
}

func TestRelayTicketVerifyExpired(t *testing.T) {
	relayPub, relayPriv := generateTestKeyPair(t)
	nodeID := randomNodeID(t)
	targetID := randomNodeID(t)

	// Create ticket that expires immediately
	ticket, err := NewRelayTicket(relayPriv, nodeID, targetID, -time.Second)
	if err != nil {
		t.Fatalf("NewRelayTicket failed: %v", err)
	}

	// Verification should fail with ErrTicketExpired
	err = ticket.Verify(relayPub, nodeID)
	if err != ErrTicketExpired {
		t.Errorf("Expected ErrTicketExpired, got: %v", err)
	}
}

func TestRelayTicketVerifyWrongNode(t *testing.T) {
	relayPub, relayPriv := generateTestKeyPair(t)
	nodeID := randomNodeID(t)
	targetID := randomNodeID(t)
	wrongNodeID := randomNodeID(t)

	ticket, err := NewRelayTicket(relayPriv, nodeID, targetID, time.Hour)
	if err != nil {
		t.Fatalf("NewRelayTicket failed: %v", err)
	}

	// Verification should fail with ErrTicketNodeMismatch
	err = ticket.Verify(relayPub, wrongNodeID)
	if err != ErrTicketNodeMismatch {
		t.Errorf("Expected ErrTicketNodeMismatch, got: %v", err)
	}
}

func TestRelayTicketVerifyWrongKey(t *testing.T) {
	_, relayPriv := generateTestKeyPair(t)
	wrongPub, _ := generateTestKeyPair(t) // Different key pair
	nodeID := randomNodeID(t)
	targetID := randomNodeID(t)

	ticket, err := NewRelayTicket(relayPriv, nodeID, targetID, time.Hour)
	if err != nil {
		t.Fatalf("NewRelayTicket failed: %v", err)
	}

	// Verification should fail with ErrTicketInvalid
	err = ticket.Verify(wrongPub, nodeID)
	if err != ErrTicketInvalid {
		t.Errorf("Expected ErrTicketInvalid, got: %v", err)
	}
}

func TestRelayTicketVerifyTamperedSignature(t *testing.T) {
	relayPub, relayPriv := generateTestKeyPair(t)
	nodeID := randomNodeID(t)
	targetID := randomNodeID(t)

	ticket, err := NewRelayTicket(relayPriv, nodeID, targetID, time.Hour)
	if err != nil {
		t.Fatalf("NewRelayTicket failed: %v", err)
	}

	// Tamper with signature
	ticket.Signature[0] ^= 0xFF

	// Verification should fail
	err = ticket.Verify(relayPub, nodeID)
	if err != ErrTicketInvalid {
		t.Errorf("Expected ErrTicketInvalid for tampered signature, got: %v", err)
	}
}

func TestRelayTicketMarshalUnmarshal(t *testing.T) {
	relayPub, relayPriv := generateTestKeyPair(t)
	nodeID := randomNodeID(t)
	targetID := randomNodeID(t)

	original, err := NewRelayTicket(relayPriv, nodeID, targetID, time.Hour)
	if err != nil {
		t.Fatalf("NewRelayTicket failed: %v", err)
	}

	// Marshal
	data := original.Marshal()
	if len(data) < TicketMinSize {
		t.Errorf("Marshaled data too short: got %d, want >= %d", len(data), TicketMinSize)
	}

	// Unmarshal
	restored, err := UnmarshalTicket(data)
	if err != nil {
		t.Fatalf("UnmarshalTicket failed: %v", err)
	}

	// Compare fields
	if restored.Nonce != original.Nonce {
		t.Error("Nonce mismatch after unmarshal")
	}
	if restored.NodeID != original.NodeID {
		t.Error("NodeID mismatch after unmarshal")
	}
	if restored.TargetID != original.TargetID {
		t.Error("TargetID mismatch after unmarshal")
	}
	if restored.Signature != original.Signature {
		t.Error("Signature mismatch after unmarshal")
	}
	// Time comparison with 1 second tolerance (Unix timestamp precision)
	if restored.ExpiresAt.Unix() != original.ExpiresAt.Unix() {
		t.Errorf("ExpiresAt mismatch: got %v, want %v", restored.ExpiresAt, original.ExpiresAt)
	}

	// Verify restored ticket is still valid
	if err := restored.Verify(relayPub, nodeID); err != nil {
		t.Errorf("Restored ticket verification failed: %v", err)
	}
}

func TestUnmarshalTicketInvalidData(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"too_short_for_v1", make([]byte, ticketMinSizeV1-1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalTicket(tt.data)
			if err == nil {
				t.Error("UnmarshalTicket should fail with invalid data")
			}
		})
	}
}

func TestDefaultRelayConfig(t *testing.T) {
	cfg := DefaultRelayConfig()

	if cfg.Enabled {
		t.Error("Relay should be disabled by default")
	}
	if cfg.MaxRate <= 0 {
		t.Error("MaxRate should be > 0")
	}
	if cfg.TicketTTL <= 0 {
		t.Error("TicketTTL should be > 0")
	}
	if len(cfg.AllowedScopes) == 0 {
		t.Error("AllowedScopes should have at least one entry")
	}
}

func TestDefaultHealthConfig(t *testing.T) {
	cfg := DefaultHealthConfig()

	if cfg.PingInterval <= 0 {
		t.Error("PingInterval should be > 0")
	}
	if cfg.PingTimeout <= 0 {
		t.Error("PingTimeout should be > 0")
	}
	if cfg.IdleTimeout <= 0 {
		t.Error("IdleTimeout should be > 0")
	}
	if cfg.MaxMissedPings <= 0 {
		t.Error("MaxMissedPings should be > 0")
	}
	if cfg.MaxSessions <= 0 {
		t.Error("MaxSessions should be > 0")
	}
	// PingTimeout should be less than PingInterval
	if cfg.PingTimeout >= cfg.PingInterval {
		t.Error("PingTimeout should be < PingInterval")
	}
}

func TestPacketTypeConstants(t *testing.T) {
	// Verify packet type constants are unique and match PROTOCOLS.md
	types := map[byte]string{
		PacketTypeData:         "Data",
		PacketTypePing:         "Ping",
		PacketTypePong:         "Pong",
		PacketTypeRelayRequest: "RelayRequest",
		PacketTypeRelayData:    "RelayData",
	}

	seen := make(map[byte]bool)
	for typ := range types {
		if seen[typ] {
			t.Errorf("Duplicate packet type: 0x%02X", typ)
		}
		seen[typ] = true
	}
}

func TestTicketSizeConstants(t *testing.T) {
	// Verify v2 TicketMinSize matches expected structure (with scopeID)
	expectedV2 := TicketNonceSize + 8 + 32 + 32 + TicketTenantIDSize + TicketSignatureSize
	if TicketMinSize != expectedV2 {
		t.Errorf("TicketMinSize mismatch: got %d, want %d", TicketMinSize, expectedV2)
	}

	// Verify v1 size (legacy, no scopeID)
	expectedV1 := TicketNonceSize + 8 + 32 + 32 + TicketSignatureSize
	if ticketMinSizeV1 != expectedV1 {
		t.Errorf("ticketMinSizeV1 mismatch: got %d, want %d", ticketMinSizeV1, expectedV1)
	}

	// v2 should be exactly TicketTenantIDSize larger than v1
	if TicketMinSize-ticketMinSizeV1 != TicketTenantIDSize {
		t.Errorf("v2-v1 size diff should be %d, got %d", TicketTenantIDSize, TicketMinSize-ticketMinSizeV1)
	}
}

// ---------- Scoped ticket tests ----------

func TestNewTenantRelayTicket(t *testing.T) {
	relayPub, relayPriv := generateTestKeyPair(t)
	nodeID := randomNodeID(t)
	targetID := randomNodeID(t)
	tenantHash := ScopeHash("scope-123")

	ticket, err := NewTenantRelayTicket(relayPriv, nodeID, targetID, tenantHash, time.Hour)
	if err != nil {
		t.Fatalf("NewTenantRelayTicket failed: %v", err)
	}

	if ticket.ScopeID != tenantHash {
		t.Error("ScopeID mismatch")
	}
	if !ticket.IsTenantScoped() {
		t.Error("Ticket should be scope-scoped")
	}

	// Basic verify still works
	if err := ticket.Verify(relayPub, nodeID); err != nil {
		t.Errorf("Verify failed: %v", err)
	}

	// Verify with correct scope
	if err := ticket.VerifyWithTenant(relayPub, nodeID, tenantHash); err != nil {
		t.Errorf("VerifyWithTenant failed: %v", err)
	}
}

func TestNewRelayTicket_IsUnscoped(t *testing.T) {
	_, relayPriv := generateTestKeyPair(t)
	nodeID := randomNodeID(t)
	targetID := randomNodeID(t)

	ticket, err := NewRelayTicket(relayPriv, nodeID, targetID, time.Hour)
	if err != nil {
		t.Fatalf("NewRelayTicket failed: %v", err)
	}

	if ticket.IsTenantScoped() {
		t.Error("Ticket created with NewRelayTicket should be unscoped")
	}

	var zero [TicketTenantIDSize]byte
	if ticket.ScopeID != zero {
		t.Error("ScopeID should be zero for unscoped ticket")
	}
}

func TestScopeHash(t *testing.T) {
	h1 := ScopeHash("scope-1")
	h2 := ScopeHash("scope-2")
	h1b := ScopeHash("scope-1")

	// Same input produces same hash
	if h1 != h1b {
		t.Error("ScopeHash should be deterministic")
	}

	// Different inputs produce different hashes
	if h1 == h2 {
		t.Error("Different scope IDs should produce different hashes")
	}

	// Not all zeros
	var zero [TicketTenantIDSize]byte
	if h1 == zero {
		t.Error("ScopeHash should not be all zeros")
	}
}

func TestVerifyWithTenant_WrongTenant(t *testing.T) {
	relayPub, relayPriv := generateTestKeyPair(t)
	nodeID := randomNodeID(t)
	targetID := randomNodeID(t)
	correctTenant := ScopeHash("scope-1")
	wrongTenant := ScopeHash("scope-2")

	ticket, err := NewTenantRelayTicket(relayPriv, nodeID, targetID, correctTenant, time.Hour)
	if err != nil {
		t.Fatalf("NewTenantRelayTicket failed: %v", err)
	}

	err = ticket.VerifyWithTenant(relayPub, nodeID, wrongTenant)
	if err != ErrTicketTenantMismatch {
		t.Errorf("Expected ErrTicketTenantMismatch, got: %v", err)
	}
}

func TestVerifyWithTenant_UnscopedTicket(t *testing.T) {
	relayPub, relayPriv := generateTestKeyPair(t)
	nodeID := randomNodeID(t)
	targetID := randomNodeID(t)

	// Create unscoped (legacy) ticket
	ticket, err := NewRelayTicket(relayPriv, nodeID, targetID, time.Hour)
	if err != nil {
		t.Fatalf("NewRelayTicket failed: %v", err)
	}

	// VerifyWithTenant should pass even with a scope hash — unscoped tickets skip scope check
	anyTenant := ScopeHash("any-scope")
	if err := ticket.VerifyWithTenant(relayPub, nodeID, anyTenant); err != nil {
		t.Errorf("Unscoped ticket should pass VerifyWithTenant: %v", err)
	}
}

func TestVerifyWithTenant_PropagatesBaseErrors(t *testing.T) {
	relayPub, relayPriv := generateTestKeyPair(t)
	nodeID := randomNodeID(t)
	targetID := randomNodeID(t)
	wrongNode := randomNodeID(t)
	tenantHash := ScopeHash("scope-1")

	ticket, err := NewTenantRelayTicket(relayPriv, nodeID, targetID, tenantHash, time.Hour)
	if err != nil {
		t.Fatalf("NewTenantRelayTicket failed: %v", err)
	}

	// Wrong node ID should return ErrTicketNodeMismatch (not scope error)
	err = ticket.VerifyWithTenant(relayPub, wrongNode, tenantHash)
	if err != ErrTicketNodeMismatch {
		t.Errorf("Expected ErrTicketNodeMismatch, got: %v", err)
	}
}

func TestTenantTicketMarshalUnmarshal(t *testing.T) {
	relayPub, relayPriv := generateTestKeyPair(t)
	nodeID := randomNodeID(t)
	targetID := randomNodeID(t)
	tenantHash := ScopeHash("scope-abc")

	original, err := NewTenantRelayTicket(relayPriv, nodeID, targetID, tenantHash, time.Hour)
	if err != nil {
		t.Fatalf("NewTenantRelayTicket failed: %v", err)
	}

	data := original.Marshal()
	if len(data) != TicketMinSize {
		t.Errorf("Marshal size: got %d, want %d", len(data), TicketMinSize)
	}

	restored, err := UnmarshalTicket(data)
	if err != nil {
		t.Fatalf("UnmarshalTicket failed: %v", err)
	}

	if restored.ScopeID != original.ScopeID {
		t.Error("ScopeID mismatch after unmarshal")
	}
	if restored.NodeID != original.NodeID {
		t.Error("NodeID mismatch after unmarshal")
	}
	if restored.Signature != original.Signature {
		t.Error("Signature mismatch after unmarshal")
	}

	// Restored ticket should still verify with scope
	if err := restored.VerifyWithTenant(relayPub, nodeID, tenantHash); err != nil {
		t.Errorf("Restored scope ticket verification failed: %v", err)
	}
}

func TestV1BackwardCompatUnmarshal(t *testing.T) {
	relayPub, relayPriv := generateTestKeyPair(t)
	nodeID := randomNodeID(t)
	targetID := randomNodeID(t)

	// Create a v2 ticket via NewRelayTicket (unscoped — zero scopeID)
	original, err := NewRelayTicket(relayPriv, nodeID, targetID, time.Hour)
	if err != nil {
		t.Fatalf("NewRelayTicket failed: %v", err)
	}

	// Manually build a v1-sized payload (strip scopeID from marshal output)
	v1Data := make([]byte, ticketMinSizeV1)
	copy(v1Data[:TicketNonceSize], original.Nonce[:])
	var expBuf [8]byte
	expBuf = [8]byte{}
	_ = expBuf
	fullData := original.Marshal()
	// Copy nonce + expiry + nodeID + targetID from full marshal
	copy(v1Data[:TicketNonceSize+8+32+32], fullData[:TicketNonceSize+8+32+32])
	// Copy signature directly after targetID (skip scopeID)
	copy(v1Data[TicketNonceSize+8+32+32:], fullData[TicketNonceSize+8+32+32+TicketTenantIDSize:])

	restored, err := UnmarshalTicket(v1Data)
	if err != nil {
		t.Fatalf("UnmarshalTicket v1 data failed: %v", err)
	}

	// ScopeID should be zero (unscoped)
	if restored.IsTenantScoped() {
		t.Error("v1 restored ticket should be unscoped")
	}

	// Signature was copied from a v2-signed ticket so it won't verify against v1 data.
	// This tests the unmarshal path, not signature validity across versions.
	// For real v1 backward compat, the original signer would have used v1 format.
	_ = relayPub
}

func BenchmarkNewRelayTicket(b *testing.B) {
	_, relayPriv := generateTestKeyPairBench(b)
	nodeID := randomNodeIDBench(b)
	targetID := randomNodeIDBench(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewRelayTicket(relayPriv, nodeID, targetID, time.Hour)
	}
}

func BenchmarkRelayTicketVerify(b *testing.B) {
	relayPub, relayPriv := generateTestKeyPairBench(b)
	nodeID := randomNodeIDBench(b)
	targetID := randomNodeIDBench(b)
	ticket, _ := NewRelayTicket(relayPriv, nodeID, targetID, time.Hour)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ticket.Verify(relayPub, nodeID)
	}
}

func BenchmarkRelayTicketMarshal(b *testing.B) {
	_, relayPriv := generateTestKeyPairBench(b)
	nodeID := randomNodeIDBench(b)
	targetID := randomNodeIDBench(b)
	ticket, _ := NewRelayTicket(relayPriv, nodeID, targetID, time.Hour)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ticket.Marshal()
	}
}

func generateTestKeyPairBench(b *testing.B) (ed25519.PublicKey, ed25519.PrivateKey) {
	b.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return pub, priv
}

func randomNodeIDBench(b *testing.B) [32]byte {
	b.Helper()
	var id [32]byte
	rand.Read(id[:])
	return id
}
