//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package noise

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrTenantSessionLimit = errors.New("relay: scope session limit exceeded")
	ErrTenantRelayLimit   = errors.New("relay: scope relay rate limit exceeded")
	ErrTenantPairLimit    = errors.New("relay: scope relay pair limit exceeded")
)

// ScopeLimiterConfig configures per-scope rate limiting for relay traffic.
//
// The limiter supports two enforcement modes, applied in order:
//
//  1. **Per-scope soft cap** (`MaxRelayPairs`): when a scope hits its own
//     pair limit, we evict its own LRU pair so the scope churns rather
//     than stalls — protects quiet scopes from being starved by their
//     own noisy tenants.
//
//  2. **Global hard cap with cross-scope WFQ preemption** (`MaxTotalPairs`):
//     when the whole limiter is at capacity and a new pair arrives, we
//     find the most-over-committed scope (usage / weight highest) and
//     evict its LRU pair. This is the WFQ arbiter from S9 — a busy
//     scope that's consuming more than its weighted share yields to a
//     quiet scope's incoming request, not the other way around.
//
// Leaving `MaxTotalPairs = 0` disables global arbitration (per-scope
// semantics only). Setting it enables true cross-scope fairness.
type ScopeLimiterConfig struct {
	Enabled       bool // Whether per-scope limiting is active
	MaxSessions   int  // Maximum concurrent sessions per scope (0 = unlimited)
	MaxRelayRate  int  // Maximum relay packets per second per scope (0 = unlimited)
	MaxRelayPairs int  // Maximum active relay source→target pairs per scope (0 = unlimited)

	// MaxTotalPairs caps the total pairs the limiter tracks across all
	// scopes. When set (> 0), at-capacity admissions trigger cross-scope
	// WFQ eviction (see package doc above). 0 disables global arbitration.
	MaxTotalPairs int

	// ScopeWeights assigns relative fair-share weights per scope ID.
	// Weight 2 gets 2× the fair share of weight 1. Unmapped scopes get
	// DefaultScopeWeight. Only consulted when MaxTotalPairs > 0.
	ScopeWeights map[string]int
}

// DefaultScopeWeight is the weight assigned to scopes not listed in
// ScopeLimiterConfig.ScopeWeights. Keeps behaviour simple when operators
// don't bother tuning per-scope weights — every scope gets equal share.
const DefaultScopeWeight = 1

// DefaultTenantLimiterConfig returns sensible defaults for shared relay nodes.
func DefaultTenantLimiterConfig() ScopeLimiterConfig {
	return ScopeLimiterConfig{
		Enabled:       false,
		MaxSessions:   500,
		MaxRelayRate:  5000, // 5000 relay packets/sec per scope
		MaxRelayPairs: 200,  // 200 active relay pairs per scope
		// MaxTotalPairs unset by default; operators enable global WFQ
		// explicitly when running shared infrastructure.
	}
}

// tenantState tracks rate limiting state for a single scope.
type tenantState struct {
	// Session count is derived from ConnectionMap (not tracked here).
	// Relay rate: token bucket.
	relayTokens    float64
	relayLastCheck time.Time
	// Active relay pairs: pairKey → most-recent-use time (used for LRU
	// eviction under pair-cap pressure — Concern S9).
	relayPairs map[string]time.Time
}

// TenantRelayLimiter enforces per-scope resource limits on relay traffic.
// It tracks relay packet rates and active relay pairs per scope.
// Session counts are derived from the noiseListener's ConnectionMap scope index.
//
// Thread-safe: all methods acquire their own lock.
type TenantRelayLimiter struct {
	mu     sync.Mutex
	config ScopeLimiterConfig
	state  map[string]*tenantState // scopeID → state

	// pairsEvicted counts pairs displaced by LRU when MaxRelayPairs would
	// otherwise reject a new pair (per-scope LRU eviction). S9.
	pairsEvicted uint64

	// relayEvictions counts cross-scope WFQ evictions — when the global
	// MaxTotalPairs cap forces us to evict from *another* scope's
	// pairs to admit a request. Separated from pairsEvicted so operators
	// can distinguish "this scope is noisy" (pairsEvicted++) from "this
	// scope exceeded its fair share and lost a slot" (relayEvictions++).
	relayEvictions uint64
}

// PairsEvictedCount returns the number of relay pairs evicted under
// per-scope LRU pressure. Observability hook for S9.
func (l *TenantRelayLimiter) PairsEvictedCount() uint64 {
	return atomic.LoadUint64(&l.pairsEvicted)
}

// RelayEvictions returns the count of cross-scope WFQ evictions — pairs
// displaced from over-committed scopes to admit requests on under-
// committed scopes. Zero unless MaxTotalPairs is set. S9 metric.
func (l *TenantRelayLimiter) RelayEvictions() uint64 {
	return atomic.LoadUint64(&l.relayEvictions)
}

// totalPairsLocked returns the global pair count across all scopes.
// Caller must hold l.mu.
func (l *TenantRelayLimiter) totalPairsLocked() int {
	n := 0
	for _, s := range l.state {
		n += len(s.relayPairs)
	}
	return n
}

// scopeWeight returns the WFQ weight for a scope ID. Lookup is config-
// driven; unmapped scopes receive DefaultScopeWeight so operators only
// need to list scopes that deserve non-default shares.
func (l *TenantRelayLimiter) scopeWeight(scopeID string) int {
	if w, ok := l.config.ScopeWeights[scopeID]; ok && w > 0 {
		return w
	}
	return DefaultScopeWeight
}

// pickBusiestScopeLocked finds the scope whose current pair count most
// exceeds its weighted fair share (i.e. highest `count / weight` ratio).
// Returns "" if no scope holds any pairs (nothing to preempt). Caller
// must hold l.mu.
//
// Fair-share logic: every scope is entitled to weight_i / sum_weights of
// MaxTotalPairs. A scope using more than its entitlement is "busy." We
// pick the one most over-committed relative to its weight — that's the
// scope whose eviction restores the best fairness delta.
func (l *TenantRelayLimiter) pickBusiestScopeLocked() string {
	var bestID string
	var bestRatio float64
	first := true
	for id, s := range l.state {
		n := len(s.relayPairs)
		if n == 0 {
			continue
		}
		w := l.scopeWeight(id)
		if w <= 0 {
			w = DefaultScopeWeight
		}
		ratio := float64(n) / float64(w)
		if first || ratio > bestRatio {
			bestID = id
			bestRatio = ratio
			first = false
		}
	}
	return bestID
}

// NewTenantRelayLimiter creates a limiter with the provided configuration.
func NewTenantRelayLimiter(cfg ScopeLimiterConfig) *TenantRelayLimiter {
	return &TenantRelayLimiter{
		config: cfg,
		state:  make(map[string]*tenantState),
	}
}

// Config returns the current limiter configuration.
func (l *TenantRelayLimiter) Config() ScopeLimiterConfig {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.config
}

// UpdateConfig replaces the limiter configuration at runtime.
func (l *TenantRelayLimiter) UpdateConfig(cfg ScopeLimiterConfig) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.config = cfg
}

// getOrCreate returns the state for a scope, creating it if needed. Caller must hold l.mu.
func (l *TenantRelayLimiter) getOrCreate(scopeID string) *tenantState {
	s, ok := l.state[scopeID]
	if !ok {
		s = &tenantState{
			relayTokens:    float64(l.config.MaxRelayRate), // start full
			relayLastCheck: time.Now(),
			relayPairs:     make(map[string]time.Time),
		}
		l.state[scopeID] = s
	}
	return s
}

// CheckSessionLimit returns an error if adding another session for scopeID
// would exceed the configured limit. currentCount is the number of sessions
// the scope currently has (caller provides from ConnectionMap).
func (l *TenantRelayLimiter) CheckSessionLimit(scopeID string, currentCount int) error {
	if scopeID == "" {
		return nil // Dedicated mode — no limits
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.config.Enabled || l.config.MaxSessions <= 0 {
		return nil
	}

	if currentCount >= l.config.MaxSessions {
		return ErrTenantSessionLimit
	}
	return nil
}

// AllowRelay checks whether a relay packet is allowed for the given scope.
// Uses a token bucket algorithm: tokens refill at MaxRelayRate per second.
// Returns nil if allowed, ErrTenantRelayLimit if rate exceeded.
func (l *TenantRelayLimiter) AllowRelay(scopeID string) error {
	if scopeID == "" {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.config.Enabled || l.config.MaxRelayRate <= 0 {
		return nil
	}

	s := l.getOrCreate(scopeID)

	// Refill tokens
	now := time.Now()
	elapsed := now.Sub(s.relayLastCheck).Seconds()
	s.relayTokens += elapsed * float64(l.config.MaxRelayRate)
	maxTokens := float64(l.config.MaxRelayRate) // cap = 1 second burst
	if s.relayTokens > maxTokens {
		s.relayTokens = maxTokens
	}
	s.relayLastCheck = now

	// Consume one token
	if s.relayTokens < 1.0 {
		return ErrTenantRelayLimit
	}
	s.relayTokens -= 1.0
	return nil
}

// CheckRelayPair checks whether a relay pair (source→target) is allowed.
// If the pair already exists, refresh its LRU stamp and allow.
//
// Admission order:
//  1. If pair already tracked → refresh, allow.
//  2. If scope is at its own MaxRelayPairs → evict the scope's LRU pair
//     (per-scope self-churn), admit new one.
//  3. If global MaxTotalPairs set and total at cap → find the busiest
//     scope (highest count/weight ratio) and evict *its* LRU pair
//     (cross-scope WFQ preemption, S9).
//
// Step 3 runs in addition to step 2, so a scope that's both over its own
// cap AND the global cap will see its own eviction (step 2) rather than
// evicting another scope's traffic unnecessarily.
func (l *TenantRelayLimiter) CheckRelayPair(scopeID, pairKey string) error {
	if scopeID == "" {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.config.Enabled {
		return nil
	}

	s := l.getOrCreate(scopeID)

	// (1) Refresh existing pair.
	if _, exists := s.relayPairs[pairKey]; exists {
		s.relayPairs[pairKey] = time.Now()
		return nil
	}

	// (2) Self-churn: scope hit its own cap.
	if l.config.MaxRelayPairs > 0 && len(s.relayPairs) >= l.config.MaxRelayPairs {
		l.evictOldestLocked(scopeID, s, false /* crossScope */)
	}

	// (3) Global WFQ preemption: total at cap → evict from busiest scope.
	if l.config.MaxTotalPairs > 0 && l.totalPairsLocked() >= l.config.MaxTotalPairs {
		busiest := l.pickBusiestScopeLocked()
		if busiest != "" && busiest != scopeID {
			l.evictOldestLocked(busiest, l.state[busiest], true /* crossScope */)
		} else if busiest == scopeID {
			// The calling scope itself is the busiest — if step 2
			// already ran, we've made room; otherwise self-evict now.
			if l.config.MaxRelayPairs <= 0 {
				l.evictOldestLocked(scopeID, s, false)
			}
		}
	}

	return nil
}

// evictOldestLocked drops the least-recently-used pair from a scope.
// crossScope=true credits the WFQ counter; false credits the per-scope
// LRU counter. Caller must hold l.mu.
func (l *TenantRelayLimiter) evictOldestLocked(scopeID string, s *tenantState, crossScope bool) {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, t := range s.relayPairs {
		if first || t.Before(oldestTime) {
			oldestKey = k
			oldestTime = t
			first = false
		}
	}
	if oldestKey != "" {
		delete(s.relayPairs, oldestKey)
		if crossScope {
			atomic.AddUint64(&l.relayEvictions, 1)
		} else {
			atomic.AddUint64(&l.pairsEvicted, 1)
		}
	}
}

// TrackRelayPair registers an active relay pair for the scope, stamping it
// with the current time for LRU bookkeeping.
// Call this after CheckRelayPair succeeds and the relay is established.
func (l *TenantRelayLimiter) TrackRelayPair(scopeID, pairKey string) {
	if scopeID == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	s := l.getOrCreate(scopeID)
	s.relayPairs[pairKey] = time.Now()
}

// RemoveRelayPair removes a relay pair when a session closes.
func (l *TenantRelayLimiter) RemoveRelayPair(scopeID, pairKey string) {
	if scopeID == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if s, ok := l.state[scopeID]; ok {
		delete(s.relayPairs, pairKey)
	}
}

// RelayPairCount returns the number of active relay pairs for a scope.
func (l *TenantRelayLimiter) RelayPairCount(scopeID string) int {
	l.mu.Lock()
	defer l.mu.Unlock()

	if s, ok := l.state[scopeID]; ok {
		return len(s.relayPairs)
	}
	return 0
}

// Cleanup removes state for tenants with no active relay pairs.
// Call periodically to prevent unbounded memory growth.
func (l *TenantRelayLimiter) Cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()

	for scopeID, s := range l.state {
		if len(s.relayPairs) == 0 {
			delete(l.state, scopeID)
		}
	}
}
