//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

// Package migration implements Aether connection migration — seamless transport
// changes (WiFi → 5G, IP rebind, transport upgrade) without stream resets.
//
// Migration uses TypeHANDSHAKE(AddressMigration) frames containing a
// ConnectionID + HMAC for validation. The receiver accepts packets from the
// new address if the AEAD validates and the ConnectionID matches.
package migration

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ORBTR/aether"
)

// HandshakeAddressMigration is an alias for aether.HandshakeAddressMigration.
// Prefer the root-package constant directly for new code.
const HandshakeAddressMigration = aether.HandshakeAddressMigration

// MigrationPayloadSize is the fixed size of a migration handshake payload.
// [ConnectionID:8][Nonce:8][Timestamp:8][NewAddr_IP:16][NewAddr_Port:2][HMAC-SHA256:32] = 74 bytes
//
// See _SECURITY.md §3.11. Without a nonce + timestamp the HMAC would be
// deterministic over (ConnID, IP, Port), so a captured migration payload
// could be replayed forever from any observer. The nonce makes each
// migration unique; the timestamp gives a time-bound TTL; the
// per-session seen-set rejects replays even within TTL.
const MigrationPayloadSize = 74

// MigrationTokenTTL is the maximum age of a migration token. Older tokens
// are rejected as stale to bound the replay window.
const MigrationTokenTTL = 30 * time.Second

// MigrationSeenCacheSize is the per-session bounded set of recently-accepted
// nonces. Must be large enough to avoid evicting legitimate migrations
// before they expire under TTL.
const MigrationSeenCacheSize = 1024

// ErrMigrationReplay is returned when a migration payload's nonce has
// already been seen on this session.
var ErrMigrationReplay = errors.New("migration: replay (nonce already used)")

// ErrMigrationExpired is returned when a migration payload's timestamp is
// older than MigrationTokenTTL.
var ErrMigrationExpired = errors.New("migration: token expired")

// MigrationState tracks an in-progress migration for a connection.
type MigrationState struct {
	ConnectionID aether.ConnectionID
	OldAddr      net.Addr
	NewAddr      net.Addr
	ValidatedAt  time.Time
	Complete     bool
}

// Migrator handles connection migration for Aether sessions.
type Migrator struct {
	mu         sync.Mutex
	migrations map[aether.ConnectionID]*MigrationState

	// seenNonces is a bounded LRU-ish set of nonces accepted on this
	// migrator's lifetime. Eviction is FIFO via the seenOrder slice
	// when the cache exceeds MigrationSeenCacheSize. Combined with
	// MigrationTokenTTL, this closes the replay window.
	seenNonces map[[8]byte]time.Time
	seenOrder  [][8]byte
}

// NewMigrator creates a migration handler.
func NewMigrator() *Migrator {
	return &Migrator{
		migrations: make(map[aether.ConnectionID]*MigrationState),
		seenNonces: make(map[[8]byte]time.Time, MigrationSeenCacheSize),
		seenOrder:  make([][8]byte, 0, MigrationSeenCacheSize),
	}
}

// EncodeMigrationPayload creates a HANDSHAKE(AddressMigration) payload.
// The HMAC is computed over ConnectionID || Nonce || Timestamp || IP || Port
// using the session key. A fresh random Nonce + monotonic Timestamp prevent
// replay (S4): the same (connID, ip, port) tuple yields a different HMAC
// every call, and the receiver enforces both a TTL and a seen-set.
func EncodeMigrationPayload(connID aether.ConnectionID, ip net.IP, port uint16, sessionKey []byte) []byte {
	payload := make([]byte, MigrationPayloadSize)

	// ConnectionID (8 bytes)
	copy(payload[0:8], connID[:])

	// Nonce (8 bytes random)
	if _, err := rand.Read(payload[8:16]); err != nil {
		// crypto/rand should never fail; if it does, returning a payload
		// with a zero nonce would still be HMAC-authenticated but allow
		// trivial replay. Surface the failure as a panic — callers
		// shouldn't proceed if randomness is broken.
		panic("migration: rand.Read failed: " + err.Error())
	}

	// Timestamp (8 bytes, unix nanoseconds)
	binary.BigEndian.PutUint64(payload[16:24], uint64(time.Now().UnixNano()))

	// IP as IPv6-mapped (16 bytes)
	ip16 := ip.To16()
	if ip16 == nil {
		ip16 = make(net.IP, 16)
	}
	copy(payload[24:40], ip16)

	// Port (2 bytes)
	binary.BigEndian.PutUint16(payload[40:42], port)

	// HMAC-SHA256 over [ConnectionID || Nonce || Timestamp || IP || Port]
	mac := computeHMAC(payload[:42], sessionKey)
	copy(payload[42:74], mac)

	return payload
}

// DecodeMigrationPayload decodes and validates a migration payload.
// Returns the ConnectionID, nonce, timestamp, and new address if HMAC is valid.
// Does NOT enforce TTL or replay — that's ValidateMigration's job.
func DecodeMigrationPayload(payload []byte, sessionKey []byte) (connID aether.ConnectionID, nonce [8]byte, ts time.Time, ip net.IP, port uint16, err error) {
	if len(payload) < MigrationPayloadSize {
		err = fmt.Errorf("migration: payload too short (%d < %d)", len(payload), MigrationPayloadSize)
		return
	}

	copy(connID[:], payload[0:8])
	copy(nonce[:], payload[8:16])
	ts = time.Unix(0, int64(binary.BigEndian.Uint64(payload[16:24])))

	ip = make(net.IP, 16)
	copy(ip, payload[24:40])
	port = binary.BigEndian.Uint16(payload[40:42])

	// Verify HMAC
	expectedMAC := computeHMAC(payload[:42], sessionKey)
	if !hmac.Equal(payload[42:74], expectedMAC) {
		err = fmt.Errorf("migration: HMAC verification failed (tampered or wrong key)")
		return
	}
	return connID, nonce, ts, ip, port, nil
}

// ValidateMigration checks a migration request: HMAC + ConnectionID match,
// timestamp within TTL, nonce not previously seen on this session.
// On success, records the migration and remembers the nonce.
func (m *Migrator) ValidateMigration(connID aether.ConnectionID, ip net.IP, port uint16, sessionKey []byte, payload []byte) error {
	validConnID, nonce, ts, validIP, validPort, err := DecodeMigrationPayload(payload, sessionKey)
	if err != nil {
		return err
	}
	if validConnID != connID {
		return fmt.Errorf("migration: ConnectionID mismatch")
	}
	if age := time.Since(ts); age < 0 || age > MigrationTokenTTL {
		return ErrMigrationExpired
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, seen := m.seenNonces[nonce]; seen {
		return ErrMigrationReplay
	}
	m.recordNonceLocked(nonce)

	m.migrations[connID] = &MigrationState{
		ConnectionID: connID,
		NewAddr:      &net.UDPAddr{IP: validIP, Port: int(validPort)},
		ValidatedAt:  time.Now(),
	}

	_ = ip // original IP for logging
	return nil
}

// recordNonceLocked stores nonce with FIFO eviction. Caller must hold m.mu.
func (m *Migrator) recordNonceLocked(nonce [8]byte) {
	if len(m.seenOrder) >= MigrationSeenCacheSize {
		oldest := m.seenOrder[0]
		m.seenOrder = m.seenOrder[1:]
		delete(m.seenNonces, oldest)
	}
	m.seenNonces[nonce] = time.Now()
	m.seenOrder = append(m.seenOrder, nonce)
}

// CompleteMigration marks a migration as complete.
func (m *Migrator) CompleteMigration(connID aether.ConnectionID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if state, ok := m.migrations[connID]; ok {
		state.Complete = true
	}
}

// GetMigration returns the migration state for a connection.
func (m *Migrator) GetMigration(connID aether.ConnectionID) (*MigrationState, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.migrations[connID]
	return state, ok
}

// Prune removes completed or stale migrations.
func (m *Migrator) Prune(maxAge time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for id, state := range m.migrations {
		if state.Complete || state.ValidatedAt.Before(cutoff) {
			delete(m.migrations, id)
		}
	}
}

// computeHMAC generates HMAC-SHA256 over data with the given key.
func computeHMAC(data, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}
