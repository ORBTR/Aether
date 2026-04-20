/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
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

type cachedKey struct {
	key      []byte
	cachedAt time.Time
}

// PeerKeyCache stores Curve25519 static public keys for known peers.
// Thread-safe. Supports TTL-based eviction to handle key rotation.
type PeerKeyCache struct {
	mu     sync.RWMutex
	keys   map[aether.NodeID]*cachedKey
	maxAge time.Duration // 0 = no eviction
}

// NewPeerKeyCache creates a cache. maxAge controls TTL-based eviction
// (0 = entries never expire, must be manually evicted).
func NewPeerKeyCache(maxAge time.Duration) *PeerKeyCache {
	return &PeerKeyCache{
		keys:   make(map[aether.NodeID]*cachedKey),
		maxAge: maxAge,
	}
}

// Get returns the cached Curve25519 static key for a peer, or nil if not cached
// or expired. Thread-safe.
func (c *PeerKeyCache) Get(id aether.NodeID) []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	ck := c.keys[id]
	if ck == nil {
		return nil
	}
	if c.maxAge > 0 && time.Since(ck.cachedAt) > c.maxAge {
		return nil // expired
	}
	return ck.key
}

// Put stores a peer's Curve25519 static key. Makes a defensive copy.
func (c *PeerKeyCache) Put(id aether.NodeID, curvePublic []byte) {
	key := make([]byte, len(curvePublic))
	copy(key, curvePublic)
	c.mu.Lock()
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
	cutoff := time.Now().Add(-c.maxAge)
	c.mu.Lock()
	defer c.mu.Unlock()
	pruned := 0
	for id, ck := range c.keys {
		if ck.cachedAt.Before(cutoff) {
			delete(c.keys, id)
			pruned++
		}
	}
	return pruned
}

// Count returns the number of cached keys.
func (c *PeerKeyCache) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.keys)
}
