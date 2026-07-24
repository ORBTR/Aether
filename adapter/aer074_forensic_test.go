//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/abuse"
)

// AER-074 EXTENSION — 3-tier reportAbuse for the guard-covered reasons
// (ack-validation / malformed-frame). These are false-positive-prone on a
// legitimate established session (recovery ACKs / large frames trip the guard),
// and the abuse-score→GOAWAY-close of a healthy grade-A session is redundant
// (the guard already dropped the frame) and IS the ~110s fleet churn.
//
// createdAt is stamped to time.Now() by NewBaseSession and is unexported, so we
// force "past warmup" with a 1ns SessionWarmupGrace — any elapsed time exceeds
// it, so these exercise T2 (established grade-A) and T3 (post-warmup zombie).
// T1 (warmup suppression) is covered by the pre-existing AER-074 warmup tests.

func aer074Session(goAway func(aether.GoAwayReason, string) error, closeErr func(error) error) *NoiseSession {
	s := &NoiseSession{
		BaseSession: aether.NewBaseSession(aether.NodeID("local"), aether.NodeID("aer074-peer"), aether.ProtoNoise),
		streams:     make(map[uint64]*noiseStream),
	}
	s.opts.SessionWarmupGrace = -time.Second // negative ⇒ warmup grace disabled (types.go:217), so T1 never fires
	s.abuseTracker = aether.NewAbuseTracker(
		abuse.New[aether.NodeID](abuse.DefaultConfig()),
		aether.NodeID("aer074-peer"),
		goAway, closeErr, nil,
	)
	return s
}

// T2: established + actively app-DELIVERING (appBytesDelivered>0) → FORENSIC-ONLY.
// Guard-trips are RECORDED (forensicSuppressed) but NOT scored / closed. A real
// delivering peer's recovery ACKs must never reap its own session.
func TestAER074_T2_ForensicOnly_DeliveringPeerNotScored(t *testing.T) {
	for _, r := range []abuse.Reason{abuse.ReasonACKValidation, abuse.ReasonMalformedFrame} {
		s := aer074Session(nil, nil)
		s.appBytesDelivered.Store(1) // established + delivering → T2

		for i := 0; i < 8; i++ { // 8×weight would be >> threshold(100) IF scored
			s.reportAbuse(r)
		}
		if score := s.PeerAbuseScore(); score != 0 {
			t.Fatalf("AER-074 T2 (%s): delivering grade-A session was SCORED (score=%v, want 0 — forensic-only)", r, score)
		}
		if fs := s.ForensicSuppressedCount(); fs != 8 {
			t.Fatalf("AER-074 T2 (%s): forensicSuppressed=%d, want 8 (every guard-trip recorded, none scored)", r, fs)
		}
	}
}

// T3: post-warmup zombie — never delivered app data (a slow-loris that only
// sends garbage) → FULL Report: scores + closes + is blacklisted at the accept
// gate. The forensic-only shelter must NOT cover a non-delivering peer.
func TestAER074_T3_ZombieEnforced_NeverDelivered(t *testing.T) {
	closed := false
	s := aer074Session(
		func(aether.GoAwayReason, string) error { return nil },
		func(error) error { closed = true; return nil },
	)
	// appBytesDelivered stays 0 (never delivered) → T3.
	for i := 0; i < 5; i++ { // 4×weight-25 = 100 crosses threshold
		s.reportAbuse(abuse.ReasonACKValidation)
	}
	if score := s.PeerAbuseScore(); score < 100 {
		t.Fatalf("AER-074 T3: zombie (never-delivered) was NOT enforced (score=%v, want >=100)", score)
	}
	if !closed {
		t.Fatal("AER-074 T3: zombie crossed threshold but closeErr did not fire")
	}
	if fs := s.ForensicSuppressedCount(); fs != 0 {
		t.Fatalf("AER-074 T3: forensicSuppressed=%d, want 0 (zombie is fully enforced, not forensic)", fs)
	}
}

// Non-guard reasons (decrypt-fail / replay / protocol-violation / flow-control)
// are ALWAYS enforced — even on a delivering grade-A session, they are real
// attacks the cheap guard does not neutralize.
func TestAER074_NonGuardReason_AlwaysEnforced(t *testing.T) {
	s := aer074Session(nil, nil)
	s.appBytesDelivered.Store(1) // delivering — T2 would apply to guard reasons

	s.reportAbuse(abuse.ReasonReplayDetected) // NOT a guard reason → must score
	if score := s.PeerAbuseScore(); score == 0 {
		t.Fatal("AER-074: a non-guard reason (replay) was suppressed on a delivering session — must always enforce")
	}
	if fs := s.ForensicSuppressedCount(); fs != 0 {
		t.Fatalf("AER-074: non-guard reason bumped forensicSuppressed=%d, want 0", fs)
	}
}
