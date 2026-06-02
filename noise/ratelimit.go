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
	// SourceLimitMaxEntries caps the per-IP bucket map. Sized at 100k
	// so a spoofed-IP attacker constrained by the global 1000/s
	// ceiling cannot cycle through the cap within the idle TTL window:
	// sustained 100k+/sec for >5 minutes would be required, well above
	// the global accept rate. Paired with TTL-based eviction (NOT
	// FIFO) so active peers are never displaced in favour of stale or
	// hostile sources.
	SourceLimitMaxEntries = 100000
	// SourceLimitEntryTTL is the idle timeout before a per-IP bucket
	// is eligible for eviction. Legitimate peers re-handshake more
	// frequently than this so their bucket state is preserved; an
	// attacker spoofing fresh IPs gets fresh buckets that expire
	// after TTL without disturbing legit peer state.
	SourceLimitEntryTTL = 5 * time.Minute
	// SourceLimitSweepInterval is how often the background sweep
	// removes expired entries. One pass per minute keeps the working
	// set small in steady state without blocking the hot path.
	SourceLimitSweepInterval = 1 * time.Minute
)

// sourceEntry is one per-IP bucket plus its last-seen timestamp.
// lastSeen is updated atomically on every Allow hit (the per-source
// limiter's primary mutex serialises updates, so the read in the
// background sweeper is consistent without further synchronisation).
type sourceEntry struct {
	bucket   *tokenBucket
	lastSeen time.Time
}

// sourceLimiter tracks per-source-IP token buckets with TTL-based
// eviction when the entry cap is reached.
//
// Eviction policy: legitimate peers whose lastSeen is within TTL are
// protected from being displaced by spoofed-IP traffic. On cache-full,
// a single-pass scan finds the oldest entry; it is evicted only if
// past TTL — otherwise the new (likely spoofed) request is rejected.
// A background sweeper runs every SourceLimitSweepInterval to keep
// the working set bounded under steady-state load. Stop() must be
// called on shutdown to terminate the sweeper goroutine.
type sourceLimiter struct {
	mu         sync.Mutex
	burst      float64
	refillRate float64
	maxEntries int
	ttl        time.Duration
	buckets    map[string]*sourceEntry

	stopOnce sync.Once
	stopCh   chan struct{}
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
	sl := &sourceLimiter{
		burst:      burst,
		refillRate: refillRate,
		maxEntries: maxEntries,
		ttl:        SourceLimitEntryTTL,
		buckets:    make(map[string]*sourceEntry, 1024), // grow on demand; cap at maxEntries
		stopCh:     make(chan struct{}),
	}
	go sl.sweepLoop()
	return sl
}

// Stop terminates the background sweeper goroutine. Idempotent.
func (sl *sourceLimiter) Stop() {
	if sl == nil {
		return
	}
	sl.stopOnce.Do(func() { close(sl.stopCh) })
}

// sweepLoop periodically evicts entries past TTL so the working set
// reflects only recently-active source IPs.
func (sl *sourceLimiter) sweepLoop() {
	t := time.NewTicker(SourceLimitSweepInterval)
	defer t.Stop()
	for {
		select {
		case <-sl.stopCh:
			return
		case <-t.C:
			sl.sweepExpired()
		}
	}
}

func (sl *sourceLimiter) sweepExpired() {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	cutoff := time.Now().Add(-sl.ttl)
	for k, e := range sl.buckets {
		if e.lastSeen.Before(cutoff) {
			delete(sl.buckets, k)
		}
	}
}

// Allow returns true if a handshake from `addr` is within its per-source
// rate budget. The key is the IP only (not IP+port) so an attacker can't
// bypass by rolling source ports.
//
// Eviction is TTL-based. On cache-full, only entries older than
// SourceLimitEntryTTL are evicted to make room; if every entry is
// fresh, the new (likely spoofed) request is dropped. This makes the
// cache cycle-attack-resistant: an attacker rolling spoofed IPs cannot
// displace legitimate peers within the TTL window, regardless of
// attack rate.
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

	now := time.Now()
	e, ok := sl.buckets[key]
	if ok {
		e.lastSeen = now
		return e.bucket.Allow(1)
	}

	// New source. If at capacity, only evict if oldest entry is past TTL.
	if len(sl.buckets) >= sl.maxEntries {
		cutoff := now.Add(-sl.ttl)
		var oldestKey string
		var oldestTime time.Time
		for k, v := range sl.buckets {
			if oldestKey == "" || v.lastSeen.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.lastSeen
			}
		}
		if oldestTime.After(cutoff) {
			// Every cached entry is recently active. Refuse the new
			// request — prevents cycle-attack displacement of legit peers.
			return false
		}
		delete(sl.buckets, oldestKey)
	}

	bucket := newTokenBucket(sl.burst, sl.refillRate, time.Second)
	sl.buckets[key] = &sourceEntry{bucket: bucket, lastSeen: now}
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
