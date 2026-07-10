//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package noise

import (
	"fmt"
	"testing"
	"time"
)

// aep21NewListener builds a bare noiseListener with only the handshake map
// initialised — enough to exercise evictOldestHandshakeLocked in isolation.
func aep21NewListener() *noiseListener {
	return &noiseListener{handshakes: make(map[string]*listenerHandshake)}
}

// aep21Insert adds an incomplete handshake with a deterministic created time so
// the oldest-eviction ordering is fully controlled by the test.
func aep21Insert(l *noiseListener, key string, created time.Time) {
	l.handshakes[key] = &listenerHandshake{created: created}
}

// TestAEP21_EvictOldestHandshake_NoOpBelowCap verifies the cap guard is a pure
// no-op while the map is below maxIncompleteHandshakes: nothing is evicted.
func TestAEP21_EvictOldestHandshake_NoOpBelowCap(t *testing.T) {
	l := aep21NewListener()
	base := time.Now()
	const n = 5
	for i := 0; i < n; i++ {
		aep21Insert(l, fmt.Sprintf("k%d", i), base.Add(time.Duration(i)*time.Millisecond))
	}

	l.mu.Lock()
	l.evictOldestHandshakeLocked()
	got := len(l.handshakes)
	l.mu.Unlock()

	if got != n {
		t.Fatalf("below-cap evict should be a no-op: len=%d want %d", got, n)
	}
}

// TestAEP21_EvictOldestHandshake_CapEnforced fills the map to exactly the cap
// with strictly increasing created times, then asserts a single evict removes
// exactly the oldest-created entry ("k0") and drops the count by one.
func TestAEP21_EvictOldestHandshake_CapEnforced(t *testing.T) {
	l := aep21NewListener()
	base := time.Now()
	for i := 0; i < maxIncompleteHandshakes; i++ {
		aep21Insert(l, fmt.Sprintf("k%d", i), base.Add(time.Duration(i)*time.Millisecond))
	}
	if len(l.handshakes) != maxIncompleteHandshakes {
		t.Fatalf("setup: len=%d want %d", len(l.handshakes), maxIncompleteHandshakes)
	}

	l.mu.Lock()
	l.evictOldestHandshakeLocked()
	got := len(l.handshakes)
	_, oldestStillPresent := l.handshakes["k0"]
	_, newestStillPresent := l.handshakes[fmt.Sprintf("k%d", maxIncompleteHandshakes-1)]
	l.mu.Unlock()

	if got != maxIncompleteHandshakes-1 {
		t.Fatalf("at-cap evict should drop one entry: len=%d want %d", got, maxIncompleteHandshakes-1)
	}
	if oldestStillPresent {
		t.Fatalf("oldest-created entry k0 should have been evicted, but it is still present")
	}
	if !newestStillPresent {
		t.Fatalf("newest entry must be retained; oldest, not newest, must be evicted")
	}
}

// TestAEP21_HandshakeMapNeverExceedsCap mimics the real insertion sequence at
// the two call sites (evictOldestHandshakeLocked immediately before the map
// write) under sustained inserts and asserts the map size never exceeds the
// cap, and that a just-inserted key is never the eviction victim.
func TestAEP21_HandshakeMapNeverExceedsCap(t *testing.T) {
	l := aep21NewListener()
	base := time.Now()
	const overflow = 2000
	total := maxIncompleteHandshakes + overflow

	var lastKey string
	for i := 0; i < total; i++ {
		lastKey = fmt.Sprintf("k%d", i)
		created := base.Add(time.Duration(i) * time.Millisecond)

		l.mu.Lock()
		l.evictOldestHandshakeLocked() // matches the guarded insertion site
		l.handshakes[lastKey] = &listenerHandshake{created: created}
		size := len(l.handshakes)
		_, justInsertedPresent := l.handshakes[lastKey]
		l.mu.Unlock()

		if size > maxIncompleteHandshakes {
			t.Fatalf("map exceeded cap at iteration %d: len=%d cap=%d", i, size, maxIncompleteHandshakes)
		}
		if !justInsertedPresent {
			t.Fatalf("iteration %d: just-inserted key %q was evicted; the new arrival must always be accepted", i, lastKey)
		}
	}

	l.mu.Lock()
	finalSize := len(l.handshakes)
	l.mu.Unlock()
	if finalSize != maxIncompleteHandshakes {
		t.Fatalf("after sustained overflow the map should sit exactly at cap: len=%d want %d", finalSize, maxIncompleteHandshakes)
	}
}
