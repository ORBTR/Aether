//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package noise

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	fnoise "github.com/flynn/noise"
	aether "github.com/ORBTR/aether"
)

// Session ticket errors
var (
	ErrTicketExpired    = errors.New("vl1: session ticket expired")
	ErrTicketInvalid    = errors.New("vl1: session ticket invalid")
	ErrTicketDecrypt    = errors.New("vl1: session ticket decrypt failed")
	ErrNoTicketKey      = errors.New("vl1: no ticket encryption key configured")
	ErrResumeNotSupport = errors.New("vl1: peer does not support session resumption")
)

// Capability flag for session ticket support (added to NodeInfo.Caps)
const capSessionTicket uint32 = 1 << 1

// sessionTicket contains the cipher state needed to resume a session without
// a full Noise handshake. Encrypted with a server-side AES-256-GCM key.
//
// Wire format (encrypted):
//   [12-byte nonce][encrypted ticket][16-byte GCM tag]
//
// Plaintext ticket format:
//   [8-byte expiry (unix nanos)]
//   [32-byte peer NodeID]
//   [32-byte send key]
//   [8-byte send nonce]
//   [32-byte recv key]
//   [8-byte recv nonce]
//   [1-byte caps flags]
type sessionTicket struct {
	ExpiresAt time.Time
	PeerID    aether.NodeID
	SendKey   [32]byte
	SendNonce uint64
	RecvKey   [32]byte
	RecvNonce uint64
	Caps      uint32
}

const (
	ticketPlaintextSize = 8 + 32 + 32 + 8 + 32 + 8 + 4 // 124 bytes
	ticketNonceSize     = 12
	ticketTagSize       = 16
	ticketEncryptedSize = ticketNonceSize + ticketPlaintextSize + ticketTagSize // 152 bytes
	ticketDefaultTTL    = 4 * time.Hour

	// DefaultTicketCacheSize bounds the client-side ticket cache. An
	// initiator that dials many distinct peers would otherwise grow this
	// map forever. When exceeded, the oldest entry is evicted (FIFO
	// insertion order is good enough — tickets are identically valuable
	// regardless of when they were cached).
	DefaultTicketCacheSize = 4096
)

// TicketStore manages session ticket encryption keys and caches issued tickets.
type TicketStore struct {
	mu       sync.RWMutex
	key      []byte        // AES-256 key (32 bytes)
	prevKey  []byte        // Previous key for rotation overlap
	ttl      time.Duration // Ticket validity duration
	gcm      cipher.AEAD
	prevGCM  cipher.AEAD

	// Client-side ticket cache: peerNodeID → encrypted ticket bytes.
	// Bounded by cacheMax with FIFO eviction (cacheOrder tracks insert order).
	// Also stores per-entry expiry so expired tickets are dropped on read.
	cache       map[aether.NodeID]cachedTicket
	cacheOrder  []aether.NodeID
	cacheMax    int
	cacheMu     sync.RWMutex
}

type cachedTicket struct {
	bytes   []byte
	expires time.Time
}

// NewTicketStore creates a ticket store with a random encryption key.
func NewTicketStore() (*TicketStore, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return NewTicketStoreWithKey(key, ticketDefaultTTL)
}

// NewTicketStoreWithKey creates a ticket store with the given AES-256 key.
func NewTicketStoreWithKey(key []byte, ttl time.Duration) (*TicketStore, error) {
	if len(key) != 32 {
		return nil, errors.New("vl1: ticket key must be 32 bytes (AES-256)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if ttl <= 0 {
		ttl = ticketDefaultTTL
	}
	return &TicketStore{
		key:        append([]byte(nil), key...),
		ttl:        ttl,
		gcm:        gcm,
		cache:      make(map[aether.NodeID]cachedTicket),
		cacheOrder: make([]aether.NodeID, 0, DefaultTicketCacheSize),
		cacheMax:   DefaultTicketCacheSize,
	}, nil
}

// RotateKey replaces the ticket encryption key. The previous key is kept for
// one rotation period to decrypt tickets issued before the rotation.
func (ts *TicketStore) RotateKey(newKey []byte) error {
	if len(newKey) != 32 {
		return errors.New("vl1: ticket key must be 32 bytes")
	}
	block, err := aes.NewCipher(newKey)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	ts.mu.Lock()
	ts.prevKey = ts.key
	ts.prevGCM = ts.gcm
	ts.key = append([]byte(nil), newKey...)
	ts.gcm = gcm
	ts.mu.Unlock()
	return nil
}

// IssueTicket creates an encrypted session ticket from the current cipher state.
// Called by the responder after a successful handshake to offer resumption.
//
// Safe-copy discipline: `send.UnsafeKey()` returns a direct reference to the
// flynn/noise CipherState's internal 32-byte buffer. The name warns that the
// slice must not be retained after the CipherState mutates (e.g. after a
// rekey). We copy into the struct's [32]byte fields immediately; the
// snapshot is then independent of future cipher-state changes.
//
// Callers must only invoke IssueTicket BEFORE any messages have been sent
// on the session — rekeying invalidates an earlier-issued ticket silently
// at resumption time. The Nonce()==0 guard enforces this contract.
func (ts *TicketStore) IssueTicket(peerID aether.NodeID, send, recv *fnoise.CipherState, caps uint32) ([]byte, error) {
	ts.mu.RLock()
	gcm := ts.gcm
	ts.mu.RUnlock()
	if gcm == nil {
		return nil, ErrNoTicketKey
	}
	// Reject issuance after the first rekey: the captured keys would be
	// stale and resumption would fail silently (decrypt error presented
	// as "wrong key" rather than the real "ticket from before rekey" cause).
	if send.Nonce() > 0 || recv.Nonce() > 0 {
		return nil, errors.New("vl1: IssueTicket must be called before any messages are sent (nonce != 0)")
	}

	ticket := sessionTicket{
		ExpiresAt: time.Now().Add(ts.ttl),
		PeerID:    peerID,
		SendNonce: send.Nonce(),
		RecvNonce: recv.Nonce(),
		Caps:      caps,
	}
	// UnsafeKey() returns a [32]byte value (by value, not by reference),
	// so assigning it here takes a full copy. The "Unsafe" in the name
	// refers to the fact that it exposes the key bytes at all — the
	// copy is inherent in Go's array value semantics.
	ticket.SendKey = send.UnsafeKey()
	ticket.RecvKey = recv.UnsafeKey()

	plaintext := make([]byte, ticketPlaintextSize)
	binary.BigEndian.PutUint64(plaintext[0:8], uint64(ticket.ExpiresAt.UnixNano()))
	copy(plaintext[8:40], []byte(ticket.PeerID))
	copy(plaintext[40:72], ticket.SendKey[:])
	binary.BigEndian.PutUint64(plaintext[72:80], ticket.SendNonce)
	copy(plaintext[80:112], ticket.RecvKey[:])
	binary.BigEndian.PutUint64(plaintext[112:120], ticket.RecvNonce)
	binary.BigEndian.PutUint32(plaintext[120:124], ticket.Caps)

	nonce := make([]byte, ticketNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	encrypted := gcm.Seal(nonce, nonce, plaintext, nil)
	return encrypted, nil
}

// DecryptTicket decrypts and validates a session ticket.
// Tries the current key first, then the previous key (rotation overlap).
func (ts *TicketStore) DecryptTicket(encrypted []byte) (*sessionTicket, error) {
	if len(encrypted) < ticketNonceSize+ticketTagSize {
		return nil, ErrTicketInvalid
	}

	nonce := encrypted[:ticketNonceSize]
	ciphertext := encrypted[ticketNonceSize:]

	// Try current key
	ts.mu.RLock()
	gcm := ts.gcm
	prevGCM := ts.prevGCM
	ts.mu.RUnlock()

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil && prevGCM != nil {
		// Try previous key (rotation overlap)
		plaintext, err = prevGCM.Open(nil, nonce, ciphertext, nil)
	}
	if err != nil {
		return nil, ErrTicketDecrypt
	}

	if len(plaintext) != ticketPlaintextSize {
		return nil, ErrTicketInvalid
	}

	ticket := &sessionTicket{
		ExpiresAt: time.Unix(0, int64(binary.BigEndian.Uint64(plaintext[0:8]))),
		PeerID:    aether.NodeID(plaintext[8:40]),
		SendNonce: binary.BigEndian.Uint64(plaintext[72:80]),
		RecvNonce: binary.BigEndian.Uint64(plaintext[112:120]),
		Caps:      binary.BigEndian.Uint32(plaintext[120:124]),
	}
	copy(ticket.SendKey[:], plaintext[40:72])
	copy(ticket.RecvKey[:], plaintext[80:112])

	if time.Now().After(ticket.ExpiresAt) {
		return nil, ErrTicketExpired
	}

	return ticket, nil
}

// CacheTicket stores a ticket for a peer (client-side). Bounded by
// cacheMax with FIFO eviction; replaces an existing entry without
// shifting its order position.
func (ts *TicketStore) CacheTicket(peerID aether.NodeID, ticket []byte) {
	ts.cacheMu.Lock()
	defer ts.cacheMu.Unlock()
	cp := append([]byte(nil), ticket...)
	if _, existed := ts.cache[peerID]; !existed {
		// New entry — enforce cap first.
		if ts.cacheMax > 0 && len(ts.cacheOrder) >= ts.cacheMax {
			oldest := ts.cacheOrder[0]
			ts.cacheOrder = ts.cacheOrder[1:]
			delete(ts.cache, oldest)
		}
		ts.cacheOrder = append(ts.cacheOrder, peerID)
	}
	ts.cache[peerID] = cachedTicket{
		bytes:   cp,
		expires: time.Now().Add(ts.ttl),
	}
}

// LookupTicket retrieves a cached ticket for a peer (client-side).
// Returns nil if the entry is absent OR has expired (expired entries are
// lazily evicted on lookup).
func (ts *TicketStore) LookupTicket(peerID aether.NodeID) []byte {
	ts.cacheMu.RLock()
	entry, ok := ts.cache[peerID]
	ts.cacheMu.RUnlock()
	if !ok {
		return nil
	}
	if !entry.expires.IsZero() && time.Now().After(entry.expires) {
		ts.EvictTicket(peerID)
		return nil
	}
	return entry.bytes
}

// EvictTicket removes a cached ticket (e.g., after failed resumption).
func (ts *TicketStore) EvictTicket(peerID aether.NodeID) {
	ts.cacheMu.Lock()
	defer ts.cacheMu.Unlock()
	if _, ok := ts.cache[peerID]; !ok {
		return
	}
	delete(ts.cache, peerID)
	for i, id := range ts.cacheOrder {
		if id == peerID {
			ts.cacheOrder = append(ts.cacheOrder[:i], ts.cacheOrder[i+1:]...)
			break
		}
	}
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// aether.TicketCapable implementation on NoiseTransport
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// Compile-time interface check.
var _ aether.TicketCapable = (*NoiseTransport)(nil)

// IssueTicket creates an encrypted session ticket from an active session's
// cipher state. The session must be a Noise session with an underlying noiseConn.
func (t *NoiseTransport) IssueTicket(sess aether.Connection) ([]byte, error) {
	if t.ticketStore == nil {
		return nil, errors.New("vl1: session tickets not enabled")
	}
	nc, err := extractNoiseConn(sess)
	if err != nil {
		return nil, err
	}
	caps := capExplicitNonce
	return t.ticketStore.IssueTicket(nc.remoteNode, nc.send, nc.recv, caps)
}

// ResumeSession attempts to resume a session from an encrypted ticket.
// Session resumption is initiated during Dial -- the ticket is sent as part of
// the handshake to skip the full XX/XK exchange. Standalone resumption without
// a dial target is not possible because the ticket contains cipher state but
// not the peer's network address.
func (t *NoiseTransport) ResumeSession(ticket []byte) (aether.Connection, error) {
	return nil, aether.WrapOp("resume", aether.ProtoNoise, "", errors.New("use Dial with ticket metadata"))
}
