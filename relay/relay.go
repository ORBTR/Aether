//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"
)

const (
	// Packet types (matching PROTOCOLS.md)
	PacketTypeData         = 0x01
	PacketTypePing         = 0x02 // Health check ping
	PacketTypePong         = 0x03 // Health check pong response
	PacketTypeRekey        = 0x04 // Cipher state rekey signal
	PacketTypeResume       = 0x05 // Session ticket resumption
	PacketTypeResumeAck    = 0x06 // Resumption acknowledgment
	PacketTypeRelayRequest = 0x07
	PacketTypeRelayData    = 0x08

	// Relay overhead
	RelayHeaderSize = 32 // NodeID size

	// Ticket sizes
	TicketNonceSize     = 16
	TicketSignatureSize = 64
	TicketTenantIDSize  = 32 // SHA256 hash of scope ID string
	// v2 format: nonce + expiry + nodeID + targetID + scopeID + sig
	TicketMinSize = TicketNonceSize + 8 + 32 + 32 + TicketTenantIDSize + TicketSignatureSize
	// v1 format (legacy, no scope): nonce + expiry + nodeID + targetID + sig
	ticketMinSizeV1 = TicketNonceSize + 8 + 32 + 32 + TicketSignatureSize
)

var (
	ErrRelayNotEnabled    = errors.New("relay: not enabled")
	ErrInvalidPacket      = errors.New("relay: invalid packet")
	ErrTargetUnreachable  = errors.New("relay: target unreachable")
	ErrTicketExpired      = errors.New("relay: ticket expired")
	ErrTicketInvalid      = errors.New("relay: ticket signature invalid")
	ErrTicketNodeMismatch  = errors.New("relay: ticket node mismatch")
	ErrTenantMismatch      = errors.New("relay: cross-scope relay denied")
	ErrTicketTenantMismatch = errors.New("relay: ticket scope mismatch")
)

// RelayTicket authorizes a node to use a relay for a specific target.
// v2 format: [nonce:16][expiry:8][nodeID:32][targetID:32][scopeID:32][signature:64]
type RelayTicket struct {
	Nonce     [TicketNonceSize]byte       // Random nonce for uniqueness
	ExpiresAt time.Time                   // When the ticket expires
	NodeID    [32]byte                    // Node authorized to use this ticket
	TargetID  [32]byte                    // Target node the ticket allows relaying to
	ScopeID  [TicketTenantIDSize]byte    // SHA256 of scope ID (zero = unscoped/legacy)
	Signature [TicketSignatureSize]byte   // Ed25519 signature by relay
}

// NewRelayTicket creates a new relay ticket signed by the relay node.
// The scopeID is the SHA256 hash of the scope string — use ScopeHash() to compute it.
// Pass a zero scopeID for unscoped (legacy/dedicated mode) tickets.
func NewRelayTicket(relayPrivKey ed25519.PrivateKey, nodeID, targetID [32]byte, ttl time.Duration) (*RelayTicket, error) {
	return NewTenantRelayTicket(relayPrivKey, nodeID, targetID, [TicketTenantIDSize]byte{}, ttl)
}

// NewTenantRelayTicket creates a scope-bound relay ticket signed by the relay node.
func NewTenantRelayTicket(relayPrivKey ed25519.PrivateKey, nodeID, targetID [32]byte, scopeID [TicketTenantIDSize]byte, ttl time.Duration) (*RelayTicket, error) {
	ticket := &RelayTicket{
		ExpiresAt: time.Now().Add(ttl),
		NodeID:    nodeID,
		TargetID:  targetID,
		ScopeID:  scopeID,
	}

	// Generate random nonce
	if _, err := rand.Read(ticket.Nonce[:]); err != nil {
		return nil, err
	}

	// Sign the ticket data
	data := ticket.dataToSign()
	sig := ed25519.Sign(relayPrivKey, data)
	copy(ticket.Signature[:], sig)

	return ticket, nil
}

// ScopeHash computes the SHA256 hash of a scope ID string for use in relay tickets.
func ScopeHash(scopeID string) [TicketTenantIDSize]byte {
	return sha256.Sum256([]byte(scopeID))
}

// IsTenantScoped returns true if the ticket is bound to a specific scope.
func (t *RelayTicket) IsTenantScoped() bool {
	var zero [TicketTenantIDSize]byte
	return t.ScopeID != zero
}

// dataToSign returns the bytes that are signed (everything except signature).
func (t *RelayTicket) dataToSign() []byte {
	data := make([]byte, TicketNonceSize+8+32+32+TicketTenantIDSize)
	copy(data[:TicketNonceSize], t.Nonce[:])
	binary.BigEndian.PutUint64(data[TicketNonceSize:], uint64(t.ExpiresAt.Unix()))
	copy(data[TicketNonceSize+8:], t.NodeID[:])
	copy(data[TicketNonceSize+8+32:], t.TargetID[:])
	copy(data[TicketNonceSize+8+32+32:], t.ScopeID[:])
	return data
}

// Marshal serializes the ticket to bytes (v2 format with scopeID).
func (t *RelayTicket) Marshal() []byte {
	data := make([]byte, TicketMinSize)
	copy(data[:TicketNonceSize], t.Nonce[:])
	binary.BigEndian.PutUint64(data[TicketNonceSize:], uint64(t.ExpiresAt.Unix()))
	copy(data[TicketNonceSize+8:], t.NodeID[:])
	copy(data[TicketNonceSize+8+32:], t.TargetID[:])
	copy(data[TicketNonceSize+8+32+32:], t.ScopeID[:])
	copy(data[TicketNonceSize+8+32+32+TicketTenantIDSize:], t.Signature[:])
	return data
}

// UnmarshalTicket deserializes a ticket from bytes.
// Supports both v2 (with scopeID, 184 bytes) and v1 (without, 152 bytes) formats.
func UnmarshalTicket(data []byte) (*RelayTicket, error) {
	if len(data) < ticketMinSizeV1 {
		return nil, ErrInvalidPacket
	}

	ticket := &RelayTicket{}
	copy(ticket.Nonce[:], data[:TicketNonceSize])
	ticket.ExpiresAt = time.Unix(int64(binary.BigEndian.Uint64(data[TicketNonceSize:])), 0)
	copy(ticket.NodeID[:], data[TicketNonceSize+8:])
	copy(ticket.TargetID[:], data[TicketNonceSize+8+32:])

	if len(data) >= TicketMinSize {
		// v2: scopeID + signature
		copy(ticket.ScopeID[:], data[TicketNonceSize+8+32+32:])
		copy(ticket.Signature[:], data[TicketNonceSize+8+32+32+TicketTenantIDSize:])
	} else {
		// v1 (legacy): no scopeID, signature follows targetID directly
		// ScopeID stays zero (unscoped)
		copy(ticket.Signature[:], data[TicketNonceSize+8+32+32:])
	}

	return ticket, nil
}

// Verify checks the ticket signature, expiration, and node ID.
func (t *RelayTicket) Verify(relayPubKey ed25519.PublicKey, requesterNodeID [32]byte) error {
	// Check expiration
	if time.Now().After(t.ExpiresAt) {
		return ErrTicketExpired
	}

	// Check node ID matches requester
	if t.NodeID != requesterNodeID {
		return ErrTicketNodeMismatch
	}

	// Verify signature
	data := t.dataToSign()
	if !ed25519.Verify(relayPubKey, data, t.Signature[:]) {
		return ErrTicketInvalid
	}

	return nil
}

// VerifyWithTenant checks the ticket signature, expiration, node ID, and scope binding.
// If the ticket is scope-scoped, the requester's scope hash must match.
// If the ticket is unscoped (zero ScopeID), the scope check is skipped.
func (t *RelayTicket) VerifyWithTenant(relayPubKey ed25519.PublicKey, requesterNodeID [32]byte, requesterTenantHash [TicketTenantIDSize]byte) error {
	if err := t.Verify(relayPubKey, requesterNodeID); err != nil {
		return err
	}

	// If ticket is scope-scoped, verify scope match
	if t.IsTenantScoped() && t.ScopeID != requesterTenantHash {
		return ErrTicketTenantMismatch
	}

	return nil
}

// RelayConfig configures the relay server
type RelayConfig struct {
	Enabled       bool
	MaxRate       int           // Packets per second per peer
	TicketTTL     time.Duration // How long a relay session is valid
	AllowedScopes []string      // Scopes allowed to use relay (e.g. "public", "mesh")
}

// DefaultRelayConfig returns a safe default configuration
func DefaultRelayConfig() RelayConfig {
	return RelayConfig{
		Enabled:       false,
		MaxRate:       100,
		TicketTTL:     1 * time.Hour,
		AllowedScopes: []string{"public"},
	}
}

// HealthConfig configures session health checking
type HealthConfig struct {
	PingInterval   time.Duration // How often to send pings (default: 30s)
	PingTimeout    time.Duration // How long to wait for pong (default: 10s)
	IdleTimeout    time.Duration // Close session after this idle time (default: 5m)
	MaxMissedPings int           // Close session after this many missed pings (default: 3)
	MaxSessions    int           // Maximum concurrent sessions (0 = unlimited)
}

// DefaultHealthConfig returns sensible defaults for session health
func DefaultHealthConfig() HealthConfig {
	return HealthConfig{
		PingInterval:   30 * time.Second,
		PingTimeout:    10 * time.Second,
		IdleTimeout:    5 * time.Minute,
		MaxMissedPings: 3,
		MaxSessions:    1000, // Default to 1000 concurrent sessions
	}
}
