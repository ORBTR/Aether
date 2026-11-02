/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package abuse

import (
	"testing"
	"time"
)

// blacklistPeer trips the cool-off breaker for peer by feeding enough
// ACK-validation hits (DefaultWeight 25 each) to cross DefaultThreshold
// (100). Five hits = 125, comfortably over threshold even after the
// negligible in-loop exponential decay, so the assertion is not boundary
// -sensitive.
func blacklistPeer(t *testing.T, s *Score[string], peer string) {
	t.Helper()
	for i := 0; i < 5; i++ {
		s.Record(peer, ReasonACKValidation)
	}
	if !s.IsBlacklisted(peer) {
		t.Fatalf("setup: peer %q should be blacklisted after 5 ACK-validation hits", peer)
	}
}

// TestAbuseCoolOff_PersistsAcrossSessions_AndGates pins the registry
// behaviour the consumer that accepts sessions (outside this repository)
// relies on. The cool-off only escalates against a reconnecting peer when
// callers share ONE node-scoped registry across sessions: the blacklist and
// score must survive a new session (a second consumer of the same registry)
// rather than resetting to 0, and IsBlacklisted must answer as the predicate
// that consumer's accept path refuses on. A fresh per-session registry
// carries no prior blacklist, so only the shared registry lets the accept
// path refuse a reconnecting peer.
func TestAbuseCoolOff_PersistsAcrossSessions_AndGates(t *testing.T) {
	const remote = "vl1_abuse_m04_peer"
	shared := New[string](DefaultConfig())

	// Session A trips the breaker on the shared, node-scoped registry.
	blacklistPeer(t, shared, remote)
	if got := shared.Current(remote); got < DefaultThreshold {
		t.Fatalf("session A score = %v, want >= %v", got, float64(DefaultThreshold))
	}

	// Session B is a NEW session for the SAME remote but the SAME shared
	// registry. The score must NOT reset to 0 and the peer must still read
	// as blacklisted. A fresh per-session registry reads 0 /
	// not-blacklisted here, which lets the peer escape the cool-off by
	// reconnecting.
	if !shared.IsBlacklisted(remote) {
		t.Fatal("shared registry: remote should still be blacklisted on a new session")
	}
	if got := shared.Current(remote); got < DefaultThreshold {
		t.Fatalf("shared registry: score reset across sessions: got %v, want >= %v",
			got, float64(DefaultThreshold))
	}

	// The predicate the consumer's accept path refuses on: true for a
	// blacklisted remote and false for an unknown one, so well-behaved
	// peers are admitted.
	if !shared.IsBlacklisted(remote) {
		t.Fatal("accept gate: blacklisted remote must be refused")
	}
	if shared.IsBlacklisted("vl1_unknown_peer") {
		t.Fatal("accept gate: unknown remote must NOT be refused")
	}

	// Contrast: a FRESH per-session registry does not inherit the
	// blacklist from another registry, which is why the registry must be
	// node-scoped/shared.
	fresh := New[string](DefaultConfig())
	if fresh.IsBlacklisted(remote) {
		t.Fatal("fresh registry must not inherit blacklist from another registry")
	}
	if got := fresh.Current(remote); got != 0 {
		t.Fatalf("fresh registry score = %v, want 0", got)
	}
}

// TestAbuseCoolOff_AutoClearsAndReArms verifies the cool-off auto-clears
// once BlacklistTTL lapses, so IsBlacklisted stops refusing the peer and it
// earns a fresh chance — the re-arm behaviour the consumer's accept path
// relies on.
func TestAbuseCoolOff_AutoClearsAndReArms(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BlacklistTTL = 10 * time.Millisecond
	s := New[string](cfg)
	const remote = "vl1_abuse_m04_ttl"

	blacklistPeer(t, s, remote)
	if !s.IsBlacklisted(remote) {
		t.Fatal("peer should be blacklisted immediately after tripping the breaker")
	}

	// After the TTL lapses, IsBlacklisted must auto-clear so the consumer's
	// accept path stops refusing the peer.
	time.Sleep(25 * time.Millisecond)
	if s.IsBlacklisted(remote) {
		t.Fatal("blacklist should auto-clear after BlacklistTTL")
	}
}

// TestAEP09_ReArmsAfterCoolOffWhenStillOverThreshold covers the
// circuit-breaker bypass Record's re-arm closes: a peer whose (decayed)
// score stays >= threshold across a cool-off window must re-arm the breaker
// on its next event once the blacklist TTL has lapsed, and never be
// permanently re-admitted.
//
// HalfLife is deliberately long (10s) so the score does NOT decay below
// threshold during the short (10ms) cool-off — the "stays above threshold"
// case a guard that blacklists only on a below->over transition never
// re-fires for.
func TestAEP09_ReArmsAfterCoolOffWhenStillOverThreshold(t *testing.T) {
	s := New[string](Config{
		Threshold:    DefaultThreshold,
		HalfLife:     10 * time.Second,
		BlacklistTTL: 10 * time.Millisecond,
	})
	const aep09Peer = "vl1_aep09_still_over"

	// Burst well past 2x threshold (10 * weight-25 = 250) in a tight loop.
	aep09Exceeded := 0
	for i := 0; i < 10; i++ {
		if _, exceeded := s.Record(aep09Peer, ReasonACKValidation); exceeded {
			aep09Exceeded++
		}
	}
	if aep09Exceeded != 1 {
		t.Fatalf("expected exactly one exceeded during burst, got %d", aep09Exceeded)
	}
	if !s.IsBlacklisted(aep09Peer) {
		t.Fatal("peer should be blacklisted after burst")
	}

	// Let the short cool-off lapse. The long HalfLife keeps the score over
	// threshold, so IsBlacklisted auto-clears the flag but not the score.
	time.Sleep(25 * time.Millisecond)

	if s.IsBlacklisted(aep09Peer) {
		t.Fatal("cool-off should have auto-cleared after TTL expiry")
	}
	if got := s.Current(aep09Peer); got < DefaultThreshold {
		t.Fatalf("precondition: score should still be >= threshold, got %v", got)
	}

	// The still-abusive peer records another event. Record re-arms on the
	// post-decay state (nowOver && !p.blacklisted); a below->over transition
	// test against a pre-decay snapshot would read over both times and never
	// re-fire here.
	if _, exceeded := s.Record(aep09Peer, ReasonACKValidation); !exceeded {
		t.Fatal("AE-P-09: breaker must re-arm for a peer still over threshold after cool-off")
	}
	if !s.IsBlacklisted(aep09Peer) {
		t.Fatal("AE-P-09: peer must be re-blacklisted after re-arm")
	}
}

// TestAEP09_DoesNotReFireWithinCoolOff guards the other direction: the
// state-based re-arm must NOT double-fire while a cool-off is still active.
// A sustained abuser pays exactly one GoAway per BlacklistTTL, not one per
// event.
func TestAEP09_DoesNotReFireWithinCoolOff(t *testing.T) {
	s := New[string](DefaultConfig()) // 5-minute BlacklistTTL
	const aep09Peer = "vl1_aep09_no_refire"

	aep09Exceeded := 0
	for i := 0; i < 20; i++ {
		if _, exceeded := s.Record(aep09Peer, ReasonACKValidation); exceeded {
			aep09Exceeded++
		}
	}
	if aep09Exceeded != 1 {
		t.Fatalf("re-arm must not double-fire inside an active cool-off: got %d exceeded", aep09Exceeded)
	}
	if !s.IsBlacklisted(aep09Peer) {
		t.Fatal("peer should remain blacklisted throughout the cool-off")
	}
}
