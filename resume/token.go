/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
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

// Validate checks the token's HMAC and age ONLY.
//
// AE-P-29: Validate does NOT provide replay / single-use protection — a
// captured, still-valid token passes Validate on every presentation for the
// full MaxTokenAge window. Any 0-RTT path that wires this Store/Token
// mechanism MUST call ValidateOnce with a shared SeenTokenSet instead, so a
// replayed token is rejected (the production noise/session_resume.go path
// already enforces this via seenTicketCache.MarkOrReject).
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

// ValidateOnce verifies the token (age + HMAC, via Validate) and then enforces
// single-use by consuming the token's SessionID against a bounded, TTL-evicting
// seen-set. A token that verifies but whose SessionID has already been consumed
// (a replay) is rejected. The SessionID is a fresh 8-byte random value per
// GenerateToken, so it serves as the de-dup nonce without a wire-format change.
//
// AE-P-29: this is the replay-safe entry point wired 0-RTT resumption must use.
// seen is retained/pruned by token expiry (created+MaxTokenAge), never by a
// blind count, so the 24h capability is preserved and a full window of live
// tokens cannot be silently forgotten (fail-closed when full).
func (t *Token) ValidateOnce(sessionKey []byte, seen *SeenTokenSet) error {
	if err := t.Validate(sessionKey); err != nil {
		return err
	}
	if seen == nil {
		return fmt.Errorf("resume: ValidateOnce requires a non-nil SeenTokenSet")
	}
	created := time.Unix(int64(t.Timestamp), 0)
	if !seen.markOrReject(t.SessionID, created.Add(MaxTokenAge)) {
		return fmt.Errorf("resume: token replay rejected (SessionID already consumed)")
	}
	return nil
}

// DefaultSeenTokenSetSize bounds the single-use resume-token seen-set.
const DefaultSeenTokenSetSize = 16384

// SeenTokenSet records consumed resume-token SessionIDs to enforce single-use.
// It is bounded and evicts only entries whose tokens have already expired
// (forgetting an expired token can never enable a replay — Validate rejects it
// on age); when full of still-live entries it fails closed (rejects) rather
// than forget a live one. Mirrors noise/session_resume.go's seenTicketCache.
type SeenTokenSet struct {
	mu    sync.Mutex
	seen  map[[8]byte]time.Time
	order [][8]byte
	max   int
}

// NewSeenTokenSet creates a bounded single-use seen-set. max<=0 uses the default.
func NewSeenTokenSet(max int) *SeenTokenSet {
	if max <= 0 {
		max = DefaultSeenTokenSetSize
	}
	return &SeenTokenSet{seen: make(map[[8]byte]time.Time), max: max}
}

// markOrReject records sessionID as consumed. Returns true if it was novel
// (admit) and false if already consumed or the set is full of unexpired
// entries (reject). expiresAt retains the entry until the token can no longer
// pass the age check.
func (s *SeenTokenSet) markOrReject(sessionID [8]byte, expiresAt time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.seen[sessionID]; ok {
		return false
	}
	if len(s.order) >= s.max {
		s.evictExpiredLocked()
		if len(s.order) >= s.max {
			return false // full of live entries — refuse rather than forget one
		}
	}
	s.order = append(s.order, sessionID)
	s.seen[sessionID] = expiresAt
	return true
}

// evictExpiredLocked drops entries whose tokens have already expired. Caller
// holds s.mu.
func (s *SeenTokenSet) evictExpiredLocked() {
	now := time.Now()
	kept := s.order[:0]
	for _, k := range s.order {
		if exp, ok := s.seen[k]; ok && now.Before(exp) {
			kept = append(kept, k)
		} else {
			delete(s.seen, k)
		}
	}
	s.order = kept
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

	// List returns the peer IDs with currently-stored resume tokens.
	// Order is unspecified. Callers typically use this on boot to
	// kick off 0-RTT reconnection attempts against previously-known
	// peers before waiting on gossip discovery.
	List() ([]string, error)
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

// List returns the peer IDs with currently-stored tokens.
func (s *MemoryStore) List() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.tokens))
	for id := range s.tokens {
		out = append(out, id)
	}
	return out, nil
}
