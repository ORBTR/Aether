/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 *
 * PeerKeyCache stores Curve25519 static public keys for known peers.
 * After a successful Noise XX handshake, the peer's static key is cached
 * so subsequent reconnections can use Noise XK (faster, encrypted msg1).
 * Extracted from NoiseTransport for clean lifecycle management and TTL eviction.
 */
package crypto

import (
	"sync"
	"time"

	aether "github.com/ORBTR/aether"
)

// PeerKeyCacheMaxEntries hard-caps the number of cached peer static keys so a
// flood of distinct peer identities cannot grow the map without bound (AE-L-06).
// Sized to match noise.SourceLimitMaxEntries (~100-150 B/entry => ~10-15 MB at
// cap). Eviction is oldest-first, so hot peers are retained; the only cost of
// an eviction is that peer's next reconnect falls back from XK to a full XX
// handshake (no correctness loss).
const PeerKeyCacheMaxEntries = 100000

type cachedKey struct {
	key      []byte
	cachedAt time.Time
}

// PeerKeyCache stores Curve25519 static public keys for known peers.
// Thread-safe. Supports TTL-based eviction to handle key rotation.
type PeerKeyCache struct {
	mu         sync.RWMutex
	keys       map[aether.NodeID]*cachedKey
	maxAge     time.Duration // 0 = no TTL eviction
	maxEntries int           // AE-L-06: hard cap on map cardinality; 0 = unbounded
}

// NewPeerKeyCache creates a cache. maxAge controls TTL-based eviction
// (0 = entries never expire, must be manually evicted).
func NewPeerKeyCache(maxAge time.Duration) *PeerKeyCache {
	return &PeerKeyCache{
		keys:       make(map[aether.NodeID]*cachedKey),
		maxAge:     maxAge,
		maxEntries: PeerKeyCacheMaxEntries, // AE-L-06: hard-bound the map
	}
}

// Get returns the cached Curve25519 static key for a peer, or nil if not cached
// or expired. Thread-safe.
func (c *PeerKeyCache) Get(id aether.NodeID) []byte {
	c.mu.RLock()
	ck := c.keys[id]
	if ck == nil {
		c.mu.RUnlock()
		return nil
	}
	if c.maxAge > 0 && time.Since(ck.cachedAt) > c.maxAge {
		c.mu.RUnlock()
		// AE-L-06: lazily drop the expired entry so dead keys are reclaimed on
		// access instead of lingering (Prune historically had no caller). Take
		// the write lock only on the rare expiry path; never hold RLock+Lock at
		// once. The pointer re-check ensures a concurrent Put refresh isn't lost.
		c.mu.Lock()
		if cur := c.keys[id]; cur == ck {
			delete(c.keys, id)
		}
		c.mu.Unlock()
		return nil // expired
	}
	key := ck.key
	c.mu.RUnlock()
	return key
}

// Put stores a peer's Curve25519 static key. Makes a defensive copy.
func (c *PeerKeyCache) Put(id aether.NodeID, curvePublic []byte) {
	key := make([]byte, len(curvePublic))
	copy(key, curvePublic)
	c.mu.Lock()
	// AE-L-06: bound the map. Enforce only for a genuinely NEW id (refreshing an
	// existing peer's key doesn't change cardinality). Reclaim expired entries
	// first (giving Prune's logic the hot-path caller it never had), then evict
	// the oldest survivor if still at cap, so growth is hard-bounded under any
	// churn or fresh-identity flood.
	if _, exists := c.keys[id]; !exists && c.maxEntries > 0 && len(c.keys) >= c.maxEntries {
		if c.pruneLocked(); len(c.keys) >= c.maxEntries {
			c.evictOldestLocked()
		}
	}
	c.keys[id] = &cachedKey{key: key, cachedAt: time.Now()}
	c.mu.Unlock()
}

// Evict removes a cached key (e.g., after XK handshake failure due to key rotation).
func (c *PeerKeyCache) Evict(id aether.NodeID) {
	c.mu.Lock()
	delete(c.keys, id)
	c.mu.Unlock()
}

// Prune removes all expired entries. Returns count of evicted entries.
// No-op if maxAge is 0 (no TTL configured).
func (c *PeerKeyCache) Prune() int {
	if c.maxAge <= 0 {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pruneLocked()
}

// pruneLocked removes all expired entries and returns the count. Caller MUST
// hold c.mu. No-op if maxAge is 0. Shared by Prune and Put's cap path. (AE-L-06)
func (c *PeerKeyCache) pruneLocked() int {
	if c.maxAge <= 0 {
		return 0
	}
	cutoff := time.Now().Add(-c.maxAge)
	pruned := 0
	for id, ck := range c.keys {
		if ck.cachedAt.Before(cutoff) {
			delete(c.keys, id)
			pruned++
		}
	}
	return pruned
}

// evictOldestLocked removes the single oldest entry (by cachedAt) to free a slot
// when the map is at capacity. Caller MUST hold c.mu. Loss-free: the evicted
// peer's next reconnect simply uses XX instead of XK. (AE-L-06)
func (c *PeerKeyCache) evictOldestLocked() {
	var oldestID aether.NodeID
	var oldestAt time.Time
	found := false
	for id, ck := range c.keys {
		if !found || ck.cachedAt.Before(oldestAt) {
			oldestID, oldestAt, found = id, ck.cachedAt, true
		}
	}
	if found {
		delete(c.keys, oldestID)
	}
}

// Count returns the number of cached keys.
func (c *PeerKeyCache) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.keys)
}
