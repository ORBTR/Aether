//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package noise

import (
	"net"
	"sync"
	"time"
)

// tokenBucket implements the token bucket rate limiting algorithm.
// Token-bucket rate limiter for handshake throttling.
type tokenBucket struct {
	mu         sync.Mutex
	capacity   float64
	tokens     float64
	refillRate float64
	lastRefill time.Time
}

func newTokenBucket(capacity, refillRate float64, interval time.Duration) *tokenBucket {
	refillPerSecond := refillRate / interval.Seconds()
	return &tokenBucket{
		capacity:   capacity,
		tokens:     capacity,
		refillRate: refillPerSecond,
		lastRefill: time.Now(),
	}
}

func (tb *tokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tb.tokens += elapsed * tb.refillRate
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}
	tb.lastRefill = now
}

func (tb *tokenBucket) Allow(cost float64) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.refill()
	if tb.tokens >= cost {
		tb.tokens -= cost
		return true
	}
	return false
}

// ────────────────────────────────────────────────────────────────────────────
// Per-source rate limiter (Concern S6 — _SECURITY.md §3.1)
// ────────────────────────────────────────────────────────────────────────────
//
// The global token bucket above prevents the listener as a whole from being
// flooded, but a single attacker hammering from one IP can still consume the
// entire global budget and starve legitimate peers. This per-source limiter
// fronts the global one with a per-IP bucket: each source IP gets its own
// small allowance (default: 10 burst, 1/sec refill), well below the global
// cap. Sources over their per-IP limit are dropped before any global tokens
// are spent.

const (
	// SourceLimitDefaultBurst is the per-source handshake burst allowance.
	SourceLimitDefaultBurst = 10
	// SourceLimitDefaultRate is the per-source refill rate (per second).
	SourceLimitDefaultRate = 1.0
	// SourceLimitMaxEntries caps the LRU map of per-IP buckets to avoid
	// unbounded memory if attacker spoofs millions of source IPs.
	SourceLimitMaxEntries = 10000
)

// sourceLimiter tracks per-source-IP token buckets with FIFO eviction
// when the entry cap is reached.
type sourceLimiter struct {
	mu         sync.Mutex
	burst      float64
	refillRate float64
	maxEntries int
	buckets    map[string]*tokenBucket
	order      []string // FIFO eviction order
}

func newSourceLimiter(burst, refillRate float64, maxEntries int) *sourceLimiter {
	if burst <= 0 {
		burst = SourceLimitDefaultBurst
	}
	if refillRate <= 0 {
		refillRate = SourceLimitDefaultRate
	}
	if maxEntries <= 0 {
		maxEntries = SourceLimitMaxEntries
	}
	return &sourceLimiter{
		burst:      burst,
		refillRate: refillRate,
		maxEntries: maxEntries,
		buckets:    make(map[string]*tokenBucket, maxEntries),
		order:      make([]string, 0, maxEntries),
	}
}

// Allow returns true if a handshake from `addr` is within its per-source
// rate budget. The key is the IP only (not IP+port) so an attacker can't
// bypass by rolling source ports.
//
// On hit, the entry's LRU position is refreshed to the back of `order` so
// active legitimate peers don't get evicted ahead of bursty strangers.
// Without this refresh, a long-lived peer that happened to be registered
// early would remain at the front of `order` indefinitely and be evicted
// first under pressure — inverting the intent of the LRU policy.
func (sl *sourceLimiter) Allow(addr net.Addr) bool {
	if sl == nil {
		return true
	}
	key := sourceKey(addr)
	if key == "" {
		return true // unknown address shape — let it through
	}
	sl.mu.Lock()
	defer sl.mu.Unlock()

	bucket, ok := sl.buckets[key]
	if !ok {
		// Evict oldest if at capacity.
		if len(sl.order) >= sl.maxEntries {
			oldest := sl.order[0]
			sl.order = sl.order[1:]
			delete(sl.buckets, oldest)
		}
		bucket = newTokenBucket(sl.burst, sl.refillRate, time.Second)
		sl.buckets[key] = bucket
		sl.order = append(sl.order, key)
	} else {
		// Refresh LRU position: remove the old slot and append to the back.
		// O(N) scan but N ≤ maxEntries and the call rate is bounded by
		// the global handshake rate limit — not a hot path.
		for i, k := range sl.order {
			if k == key {
				sl.order = append(sl.order[:i], sl.order[i+1:]...)
				break
			}
		}
		sl.order = append(sl.order, key)
	}
	return bucket.Allow(1)
}

// sourceKey extracts the IP portion of a UDP address as a map key.
// Returns "" if the address doesn't carry an IP.
func sourceKey(addr net.Addr) string {
	if u, ok := addr.(*net.UDPAddr); ok {
		return u.IP.String()
	}
	return addr.String()
}
