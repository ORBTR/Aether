/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

// Build-tag agnostic: AcceptOverConn (dial_conn.go) compiles on every
// target, and its AcceptConnConfig.TicketNonces field needs
// TicketNonceCache, which is built on seenTicketCache, on each of them.

package noise

import (
	"crypto/ed25519"
	"errors"
	"sync"
	"time"
)

// DefaultSeenTicketCacheSize is the bound a seenTicketCache takes when it
// is built with max <= 0: the transport's resume replay guard
// (NoiseTransport.seenTickets) and NewTicketNonceCache use it.
const DefaultSeenTicketCacheSize = 16384

// seenTicketCache records ticket nonces, each until its ticket's expiry,
// so each ticket is admitted once. The responder's resume path
// (handleResumePacket through NoiseTransport.seenTickets) and
// TicketNonceCache each hold one.
type seenTicketCache struct {
	mu    sync.Mutex
	seen  map[string]time.Time
	order []string
	max   int
}

func newSeenTicketCache(max int) *seenTicketCache {
	if max <= 0 {
		max = DefaultSeenTicketCacheSize
	}
	return &seenTicketCache{
		seen: make(map[string]time.Time),
		max:  max,
	}
}

// MarkOrReject records nonce until expiresAt and returns true if it was
// not recorded before. It returns false for a recorded nonce, and for a
// new one when the cache holds max nonces whose tickets are all still
// live.
//
// A full cache evicts only expired entries, never by arrival order: a
// forgotten live nonce would re-admit its ticket, and a replayed resume
// packet would then make handleResumePacket overwrite the peer's live
// byNodeID mapping in connection_map.go. Refusing instead sends the
// resuming peer to a full handshake.
func (c *seenTicketCache) MarkOrReject(nonce []byte, expiresAt time.Time) bool {
	key := string(nonce)
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.seen[key]; ok {
		return false
	}
	if len(c.order) >= c.max {
		c.evictExpiredLocked()
		if len(c.order) >= c.max {
			return false // full of live nonces — refuse rather than evict one
		}
	}
	c.order = append(c.order, key)
	c.seen[key] = expiresAt
	return true
}

// has reports whether nonce is recorded, expired or not. TicketNonceCache
// reads it to refuse a replayed grant before the handshake runs and to
// tell a replay from a full cache after MarkOrReject refuses.
func (c *seenTicketCache) has(nonce []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.seen[string(nonce)]
	return ok
}

// evictExpiredLocked drops nonces whose tickets have already expired.
// Forgetting them cannot re-admit a ticket: the resume path's
// DecryptTicket and an accepter's ValidateTicketFn refuse an expired one.
// Caller holds c.mu.
func (c *seenTicketCache) evictExpiredLocked() {
	now := time.Now()
	kept := c.order[:0]
	for _, k := range c.order {
		if exp, ok := c.seen[k]; ok && now.Before(exp) {
			kept = append(kept, k)
		} else {
			delete(c.seen, k)
		}
	}
	c.order = kept
}

// ErrTicketNonceReplayed is AcceptOverConn's refusal of a verified ticket
// whose nonce its AcceptConnConfig.TicketNonces already holds.
var ErrTicketNonceReplayed = errors.New("noise: ticket nonce already used")

// ErrTicketNonceCacheFull is AcceptOverConn's refusal of a new nonce when
// TicketNonces holds its bound of nonces whose tickets are all still
// admitted. Forgetting one of them would let its ticket open a second
// connection, so the new ticket is refused instead.
var ErrTicketNonceCacheFull = errors.New("noise: ticket nonce cache full of live nonces")

// TicketNonceCache holds the nonces of the tickets one accepter has
// admitted, each until its ticket's expiry, keyed by the signer key that
// verified the ticket and the nonce. A signer keeps its own nonces unique
// and no other signer's, so an accepter that trusts several signers
// (TrustedTicketSignerFn) would otherwise refuse one signer's ticket
// because another's carried the same nonce. AcceptOverConn consults it
// through AcceptConnConfig.TicketNonces; the accepter builds one with
// NewTicketNonceCache and passes the same pointer to every accept. It
// keeps seenTicketCache's eviction rule, so a full cache refuses rather
// than forgets, and it is safe for concurrent accepts.
type TicketNonceCache struct {
	seen *seenTicketCache
}

// NewTicketNonceCache returns a cache bounded at max live nonces; max <= 0
// takes DefaultSeenTicketCacheSize.
func NewTicketNonceCache(max int) *TicketNonceCache {
	return &TicketNonceCache{seen: newSeenTicketCache(max)}
}

// check refuses a nonce that is empty, whose expiry is not in the future
// (the cache would forget it at once, so it would guard nothing), or that
// signer's tickets have already recorded. It records nothing.
func (c *TicketNonceCache) check(signer ed25519.PublicKey, nonce []byte, expiresAt time.Time) error {
	if len(nonce) == 0 {
		return errors.New("noise: ticket carries no nonce")
	}
	if !time.Now().Before(expiresAt) {
		return errors.New("noise: ticket nonce expiry is not in the future")
	}
	if c.seen.has(nonceKey(signer, nonce)) {
		return ErrTicketNonceReplayed
	}
	return nil
}

// use records signer's nonce until expiresAt after the same refusals as
// check. Of two accepts presenting one signer's nonce, MarkOrReject admits
// exactly one.
func (c *TicketNonceCache) use(signer ed25519.PublicKey, nonce []byte, expiresAt time.Time) error {
	if err := c.check(signer, nonce, expiresAt); err != nil {
		return err
	}
	key := nonceKey(signer, nonce)
	if c.seen.MarkOrReject(key, expiresAt) {
		return nil
	}
	if c.seen.has(key) {
		return ErrTicketNonceReplayed
	}
	return ErrTicketNonceCacheFull
}

// nonceKey is the cache key for signer's nonce. An Ed25519 public key has
// one length, so no signer and nonce pair shares a key with another.
func nonceKey(signer ed25519.PublicKey, nonce []byte) []byte {
	key := make([]byte, 0, len(signer)+len(nonce))
	return append(append(key, signer...), nonce...)
}
