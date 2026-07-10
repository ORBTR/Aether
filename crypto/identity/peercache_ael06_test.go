/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 *
 * Regression tests for AE-L-06: PeerKeyCache grew without bound because Put()
 * had no size cap, Get() only masked expired entries (left them in the map),
 * and Prune() had no caller. These tests prove the map is now hard-bounded and
 * that expired entries are actually reclaimed.
 */
package crypto

import (
	"strconv"
	"testing"
	"time"

	aether "github.com/ORBTR/aether"
)

// ael06NodeID builds a distinct NodeID per index for flood simulation.
func ael06NodeID(i int) aether.NodeID {
	return aether.NodeID("ael06-node-" + strconv.Itoa(i))
}

// ael06Key returns a fixed-length 32-byte Curve25519-shaped key.
func ael06Key(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

// TestAEL06_CapBoundsGrowth proves a flood of distinct peer identities cannot
// grow the map past maxEntries, and that eviction is oldest-first (the most
// recent Put is retained).
func TestAEL06_CapBoundsGrowth(t *testing.T) {
	c := NewPeerKeyCache(time.Hour)
	c.maxEntries = 100

	var lastID aether.NodeID
	for i := 0; i < 1000; i++ {
		lastID = ael06NodeID(i)
		c.Put(lastID, ael06Key(byte(i)))
	}

	if got := c.Count(); got > 100 {
		t.Fatalf("cap not enforced: Count()=%d, want <= 100", got)
	}
	if c.Get(lastID) == nil {
		t.Fatalf("most-recently-Put id was evicted; eviction should be oldest-first, not newest")
	}
}

// TestAEL06_GetLazilyEvictsExpired proves Get() deletes the expired entry it
// finds instead of merely returning nil while leaving it in the map.
func TestAEL06_GetLazilyEvictsExpired(t *testing.T) {
	c := NewPeerKeyCache(5 * time.Millisecond)
	id := ael06NodeID(0)
	c.Put(id, ael06Key(0x11))

	time.Sleep(15 * time.Millisecond)

	if got := c.Get(id); got != nil {
		t.Fatalf("expected nil for expired entry, got %v", got)
	}
	if got := c.Count(); got != 0 {
		t.Fatalf("expired entry not reclaimed by Get: Count()=%d, want 0", got)
	}
}

// TestAEL06_PutPrunesExpiredAtCap proves that when the map is at capacity Put()
// reclaims expired entries (via pruneLocked) before inserting, so a churn of
// expired-then-new identities stays bounded and fresh keys still resolve.
func TestAEL06_PutPrunesExpiredAtCap(t *testing.T) {
	c := NewPeerKeyCache(5 * time.Millisecond)
	c.maxEntries = 50

	// Fill to capacity.
	for i := 0; i < 50; i++ {
		c.Put(ael06NodeID(i), ael06Key(byte(i)))
	}
	if got := c.Count(); got != 50 {
		t.Fatalf("setup: Count()=%d, want 50", got)
	}

	// Let the first batch expire.
	time.Sleep(15 * time.Millisecond)

	// Insert 50 more distinct ids; the cap path must prune the expired batch.
	var lastID aether.NodeID
	for i := 50; i < 100; i++ {
		lastID = ael06NodeID(i)
		c.Put(lastID, ael06Key(byte(i)))
	}

	if got := c.Count(); got > 50 {
		t.Fatalf("cap path did not reclaim expired entries: Count()=%d, want <= 50", got)
	}
	if c.Get(lastID) == nil {
		t.Fatalf("freshly-Put id did not resolve after cap-path prune")
	}
}
