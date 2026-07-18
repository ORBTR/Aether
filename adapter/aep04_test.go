//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"testing"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/abuse"
	"github.com/ORBTR/aether/reliability"
)

// AE-P-04 regression — a deeply reordered / legitimately-retransmitted DATA
// frame that lands more than ReplayWindowSize(64) behind an advanced topSeq is
// classified reliability.ResultAncient. The pre-fix dispatch dropped it AND
// charged abuse.ReasonReplayDetected (weight 8) unconditionally; a burst of
// them tore down an otherwise-healthy session — the exact retransmit-churn
// class the ResultDuplicate/ResultAncient split was built to eliminate.
//
// The fix consults the recvWindow's cumulative delivery floor (ExpectedSeqNo)
// rather than topSeq: a SeqNo at/above the floor was never delivered and is
// still needed, so it is routed into the idempotent recvWindow (no drop, no
// abuse); a SeqNo below the floor was already delivered (genuine replay / lost
// -ACK retransmit) so it is still charged (flood defense preserved). WrapAttack
// stays in its own case and is charged unchanged.

func aep04Setup() (*NoiseSession, *noiseStream) {
	s := &NoiseSession{streams: make(map[uint64]*noiseStream)}
	// Fresh single-entry abuse registry so PeerAbuseScore() is observable.
	// nil goAway/closeErr hooks: one weight-8 event never crosses the
	// threshold(100), so the breaker is not exercised here.
	s.abuseTracker = aether.NewAbuseTracker(
		abuse.New[aether.NodeID](abuse.DefaultConfig()),
		aether.NodeID("aep04-peer"),
		nil, nil, nil,
	)
	st := &noiseStream{
		streamID:   1,
		session:    s,
		replay:     reliability.NewReplayWindow(),
		recvWindow: reliability.NewRecvWindow(64),
	}
	s.streams[1] = st
	return s, st
}

// Ancient BUT at/above the delivery floor: must be buffered for delivery with
// NO abuse charged.
func TestAEP04_AncientAboveFloor_DeliveredNoAbuse(t *testing.T) {
	s, st := aep04Setup()

	// Push the replay window's topSeq far ahead so a low SeqNo lands
	// >= ReplayWindowSize(64) behind it and classifies ResultAncient.
	st.replay.Check(100)

	// recvWindow.expected is still 0, so SeqNo 1 is AT/ABOVE the cumulative
	// delivery floor — never delivered, still needed.
	frame := &aether.Frame{StreamID: 1, SeqNo: 1, Payload: []byte("one")}
	s.handleData(frame)

	if score := s.PeerAbuseScore(); score != 0 {
		t.Fatalf("AE-P-04 regressed: still-needed Ancient frame charged abuse (score=%v, want 0)", score)
	}

	// Prove the dispatch ROUTED the frame into the recvWindow (buffered
	// behind the gap at 0) instead of dropping it: filling the gap at 0 must
	// now flush BOTH 0 and the previously-buffered 1.
	delivered := st.recvWindow.Insert(0, []byte("zero"))
	if len(delivered) != 2 {
		t.Fatalf("AE-P-04: above-floor Ancient frame was not buffered by handleData; "+
			"gap-fill flushed %d payloads, want 2", len(delivered))
	}
}

// AER-023: Ancient AND below the delivery floor (already delivered) is a
// legitimate lost-ACK retransmit, NOT abuse. It is eager-ACKed and must NOT
// be charged — a >64-frame burst with a lost cumulative ACK produced ~13 of
// these inside one RTT and tripped the abuse tracker, killing a healthy
// session. Genuine forgeries are still caught by the WrapAttack path.
func TestAEP04_AncientBelowFloor_NotCharged(t *testing.T) {
	s, st := aep04Setup()

	// Advance the recvWindow delivery floor past SeqNo 2 by delivering
	// 0..4 in order (expected -> 5).
	for i := uint32(0); i < 5; i++ {
		st.recvWindow.Insert(i, []byte{byte(i)})
	}
	if got := st.recvWindow.ExpectedSeqNo(); got != 5 {
		t.Fatalf("setup: ExpectedSeqNo = %d, want 5", got)
	}

	// Push topSeq far ahead so SeqNo 2 classifies ResultAncient.
	st.replay.Check(100)

	before := s.PeerAbuseScore()
	frame := &aether.Frame{StreamID: 1, SeqNo: 2, Payload: []byte("two")}
	s.handleData(frame) // 2 < expected(5): below floor

	if after := s.PeerAbuseScore(); after != before {
		t.Fatalf("AER-023: below-floor lost-ACK retransmit charged abuse "+
			"(before=%v after=%v) — must be eager-ACKed, not charged", before, after)
	}
}

// WrapAttack path is preserved unchanged: drop + charge abuse.
func TestAEP04_WrapAttackStillCharged(t *testing.T) {
	s, st := aep04Setup()

	st.replay.Check(100) // init topSeq

	// SeqNo jumping forward past half the uint32 space -> ResultWrapAttack.
	frame := &aether.Frame{StreamID: 1, SeqNo: 100 + (1 << 31) + 1, Payload: []byte("forge")}
	s.handleData(frame)

	if score := s.PeerAbuseScore(); score <= 0 {
		t.Fatalf("AE-P-04: WrapAttack must still charge abuse (score=%v)", score)
	}
}
