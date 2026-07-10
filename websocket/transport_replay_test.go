/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package websocket

import (
	"testing"
	"time"
)

// TestDialReplayGuardRejectsReplayAndStale exercises the AE-M-16 anti-replay
// guard directly: first use of a nonce is admitted, a second use within the
// freshness window is rejected as a replay, a distinct nonce is admitted, and
// an entry whose expiry has passed is pruned so the nonce can be re-admitted.
func TestDialReplayGuardRejectsReplayAndStale(t *testing.T) {
	g := newDialReplayGuard()
	now := time.Now()
	exp := now.Add(dialFreshnessWindow)

	if !g.checkAndRecord("nonceA", now, exp) {
		t.Fatal("first use of nonceA should be accepted")
	}
	if g.checkAndRecord("nonceA", now, exp) {
		t.Fatal("replay of nonceA within the freshness window must be rejected")
	}
	if !g.checkAndRecord("nonceB", now, exp) {
		t.Fatal("distinct nonceB should be accepted")
	}

	// Advance the clock beyond nonceA's expiry: the pruning pass must evict the
	// stale entry so the same nonce value is re-admitted (retention is bounded
	// by expiry, not a fixed cap).
	later := now.Add(2 * dialFreshnessWindow)
	if !g.checkAndRecord("nonceA", later, later.Add(dialFreshnessWindow)) {
		t.Fatal("nonceA should be re-admitted once its prior entry has expired")
	}
}

// TestDialFreshnessHeaderConstant guards the new AE-M-16 timestamp header value
// that is bound into the dial signature alongside the nonce.
func TestDialFreshnessHeaderConstant(t *testing.T) {
	if TimestampHeader != "X-ORBTR-Timestamp" {
		t.Errorf("TimestampHeader should be X-ORBTR-Timestamp, got %s", TimestampHeader)
	}
	if dialFreshnessWindow <= 0 {
		t.Errorf("dialFreshnessWindow must be positive, got %v", dialFreshnessWindow)
	}
}
