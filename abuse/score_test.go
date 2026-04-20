/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package abuse

import (
	"testing"
	"time"
)

func TestRecord_BlacklistsAtThreshold(t *testing.T) {
	s := New[string](DefaultConfig())
	// 4 ACK validation hits = 100 score → at threshold.
	for i := 0; i < 3; i++ {
		_, exceeded := s.Record("peer-1", ReasonACKValidation)
		if exceeded {
			t.Fatalf("blacklisted too early at iteration %d", i)
		}
	}
	score, exceeded := s.Record("peer-1", ReasonACKValidation)
	if !exceeded {
		t.Fatalf("should have exceeded at score %v", score)
	}
	if !s.IsBlacklisted("peer-1") {
		t.Fatal("peer should be blacklisted")
	}
}

func TestForgive_ClearsScoreAndBlacklist(t *testing.T) {
	s := New[string](DefaultConfig())
	for i := 0; i < 5; i++ {
		s.Record("peer-1", ReasonACKValidation)
	}
	if !s.IsBlacklisted("peer-1") {
		t.Fatal("peer should be blacklisted before Forgive")
	}
	s.Forgive("peer-1")
	if s.IsBlacklisted("peer-1") {
		t.Fatal("peer should be cleared after Forgive")
	}
	if cur := s.Current("peer-1"); cur != 0 {
		t.Errorf("score after Forgive: %v, want 0", cur)
	}
}

func TestScoreDecays(t *testing.T) {
	cfg := DefaultConfig()
	cfg.HalfLife = 10 * time.Millisecond
	s := New[string](cfg)
	s.Record("peer-1", ReasonACKValidation) // +25
	initial := s.Current("peer-1")
	if initial < 24 || initial > 26 {
		t.Fatalf("initial score out of bounds: %v", initial)
	}
	time.Sleep(30 * time.Millisecond) // ~3 half-lives → ~3.1
	after := s.Current("peer-1")
	if after >= initial/2 {
		t.Errorf("score did not decay enough: initial=%v after=%v", initial, after)
	}
}

func TestPrune_RemovesQuietPeers(t *testing.T) {
	cfg := DefaultConfig()
	cfg.HalfLife = 1 * time.Millisecond
	s := New[string](cfg)
	s.Record("peer-1", ReasonStreamRefused) // small, decays fast
	time.Sleep(50 * time.Millisecond)
	s.Prune(10 * time.Millisecond)
	if cur := s.Current("peer-1"); cur != 0 {
		t.Errorf("pruned peer should have 0 score, got %v", cur)
	}
}
