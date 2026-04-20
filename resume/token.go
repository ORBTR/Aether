/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

// Package resume implements 0-RTT session resumption for Aether.
// When a peer disconnects, it stores a resume token containing a session
// identifier and HMAC. On reconnection, the peer sends this token in a
// HANDSHAKE(SessionResume) frame to skip the full handshake.
//
// Security: only idempotent operations (gossip, PING) are allowed in 0-RTT.
// Non-idempotent (RPC) waits for 1-RTT confirmation.
package resume

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

// TokenSize is the total size of a resume token.
// [SessionID:8][Timestamp:8][HMAC-SHA256:32] = 48 bytes
const TokenSize = 48

// MaxTokenAge is the maximum age for a resume token (24 hours).
const MaxTokenAge = 24 * time.Hour

// Token represents a session resume token.
type Token struct {
	SessionID [8]byte  // random identifier from original session
	Timestamp uint64   // unix seconds when token was created
	HMAC      [32]byte // HMAC-SHA256 over SessionID || Timestamp, keyed with session key
}

// GenerateToken creates a resume token for a session.
// The session key is the shared secret from the Noise/TLS handshake.
func GenerateToken(sessionKey []byte) (*Token, error) {
	t := &Token{
		Timestamp: uint64(time.Now().Unix()),
	}

	// Random SessionID
	if _, err := rand.Read(t.SessionID[:]); err != nil {
		return nil, fmt.Errorf("resume: generate SessionID: %w", err)
	}

	// Compute HMAC
	t.HMAC = computeTokenHMAC(t.SessionID, t.Timestamp, sessionKey)
	return t, nil
}

// Encode serializes a token to bytes.
func (t *Token) Encode() []byte {
	data := make([]byte, TokenSize)
	copy(data[0:8], t.SessionID[:])
	binary.BigEndian.PutUint64(data[8:16], t.Timestamp)
	copy(data[16:48], t.HMAC[:])
	return data
}

// DecodeToken deserializes a token from bytes.
func DecodeToken(data []byte) (*Token, error) {
	if len(data) < TokenSize {
		return nil, fmt.Errorf("resume: token too short (%d < %d)", len(data), TokenSize)
	}
	t := &Token{
		Timestamp: binary.BigEndian.Uint64(data[8:16]),
	}
	copy(t.SessionID[:], data[0:8])
	copy(t.HMAC[:], data[16:48])
	return t, nil
}

// Validate checks the token's HMAC and age.
func (t *Token) Validate(sessionKey []byte) error {
	// Check age
	created := time.Unix(int64(t.Timestamp), 0)
	if time.Since(created) > MaxTokenAge {
		return fmt.Errorf("resume: token expired (age %v > %v)", time.Since(created), MaxTokenAge)
	}

	// Verify HMAC
	expected := computeTokenHMAC(t.SessionID, t.Timestamp, sessionKey)
	if !hmac.Equal(t.HMAC[:], expected[:]) {
		return fmt.Errorf("resume: HMAC verification failed")
	}

	return nil
}

// DeriveNewKey derives a new session key from the old key + fresh randomness.
// new_key = HKDF-Expand(PRK=old_key, info="aether-resume-v1"||newRandom, L=32)
func DeriveNewKey(oldKey []byte) ([]byte, []byte, error) {
	// Generate fresh randomness
	newRandom := make([]byte, 32)
	if _, err := rand.Read(newRandom); err != nil {
		return nil, nil, fmt.Errorf("resume: generate random: %w", err)
	}

	// HKDF
	info := append([]byte("aether-resume-v1"), newRandom...)
	hkdfReader := hkdf.New(sha256.New, oldKey, nil, info)
	newKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, newKey); err != nil {
		return nil, nil, fmt.Errorf("resume: derive key: %w", err)
	}

	return newKey, newRandom, nil
}

// computeTokenHMAC computes HMAC-SHA256 over SessionID || Timestamp.
func computeTokenHMAC(sessionID [8]byte, timestamp uint64, key []byte) [32]byte {
	data := make([]byte, 16)
	copy(data[0:8], sessionID[:])
	binary.BigEndian.PutUint64(data[8:16], timestamp)

	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	sum := mac.Sum(nil)

	var result [32]byte
	copy(result[:], sum)
	return result
}

// ────────────────────────────────────────────────────────────────────────────
// Token Store (persistent across restarts)
// ────────────────────────────────────────────────────────────────────────────

// Store persists resume tokens for 0-RTT reconnection.
// Implementations can use file, SQLite, or memory storage.
type Store interface {
	Save(peerID string, token *Token, sessionKey []byte) error
	Load(peerID string) (*Token, []byte, error) // returns token + session key
	Delete(peerID string) error
}

// MemoryStore is an in-memory token store (lost on restart).
type MemoryStore struct {
	mu     sync.RWMutex
	tokens map[string]*storedToken
}

type storedToken struct {
	token      *Token
	sessionKey []byte
}

// NewMemoryStore creates an in-memory token store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{tokens: make(map[string]*storedToken)}
}

func (s *MemoryStore) Save(peerID string, token *Token, sessionKey []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[peerID] = &storedToken{token: token, sessionKey: sessionKey}
	return nil
}

func (s *MemoryStore) Load(peerID string) (*Token, []byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.tokens[peerID]
	if !ok {
		return nil, nil, fmt.Errorf("resume: no token for peer %s", peerID)
	}
	return st.token, st.sessionKey, nil
}

func (s *MemoryStore) Delete(peerID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, peerID)
	return nil
}
