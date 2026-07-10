//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"testing"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/congestion"
	"github.com/ORBTR/aether/reliability"
	"github.com/ORBTR/aether/scheduler"
)

// ─── AE-P-08 — BaseACK progress comparison not wrap-safe ────────────────────
//
// handleACK tracks stall-detection progress by CAS-advancing lastBaseACKSeen
// whenever a new BaseACK is larger than the last. The pre-fix guard used a
// plain uint32 `ack.BaseACK <= prev`, which freezes progress for a full
// ~4B-frame cycle after BaseACK wraps past 2^32: a small post-wrap value
// compares <= the near-2^32 prev, so the stall clock never advances while the
// stream is actually progressing, tripping needless probe-before-close /
// ResetCWND. The fix uses RFC-1982 wrap-safe arithmetic: int32(new-prev) <= 0.
func TestAEP08_BaseACKWrapRecordsProgress(t *testing.T) {
	s := &NoiseSession{streams: make(map[uint64]*noiseStream)}
	s.SetCongestionController(congestion.NewCUBICController())
	s.sched = scheduler.NewScheduler()

	eng := reliability.NewEngine(reliability.EngineConfig{StreamID: 1, WindowSize: 64})
	st := &noiseStream{
		streamID:   1,
		session:    s,
		sendWindow: eng.SendWin,
		rtt:        eng.RTT,
		tlp:        congestion.NewTLP(0),
	}
	s.streams[1] = st

	// Pre-wrap state: lastBaseACKSeen just below the uint32 rollover, no
	// progress recorded yet.
	st.lastBaseACKSeen.Store(0xFFFFFFFE)
	st.lastProgressAtUnixNano.Store(0)

	// A small post-wrap BaseACK. Empty bitmap encodes to CompositeACKMinSize
	// and is benign in ProcessCompositeACK (no in-flight → no acked, no abuse),
	// so the progress loop runs.
	s.handleACK(aep08ACKFrame(5))

	if got := st.lastProgressAtUnixNano.Load(); got == 0 {
		t.Fatalf("AE-P-08 regressed: BaseACK wrap (0xFFFFFFFE → 5) recorded no progress; "+
			"a plain uint32 `<=` froze the stall clock across the wrap")
	}
	if got := st.lastBaseACKSeen.Load(); got != 5 {
		t.Fatalf("AE-P-08 regressed: lastBaseACKSeen = %#x, want 5 after wrap", got)
	}

	// Negative control: a genuinely stale/backward BaseACK (50 < prev 100)
	// must STILL be rejected — the wrap-safe check must not over-record.
	st.lastBaseACKSeen.Store(100)
	st.lastProgressAtUnixNano.Store(0)
	s.handleACK(aep08ACKFrame(50))

	if got := st.lastProgressAtUnixNano.Load(); got != 0 {
		t.Fatalf("AE-P-08 regressed: stale BaseACK=50 (< prev=100) recorded progress; "+
			"wrap-safe comparison must still reject real backward/duplicate ACKs")
	}
	if got := st.lastBaseACKSeen.Load(); got != 100 {
		t.Fatalf("AE-P-08 regressed: stale BaseACK advanced lastBaseACKSeen to %d, want 100", got)
	}
}

// aep08ACKFrame builds an empty-bitmap CompositeACK frame on stream 1.
func aep08ACKFrame(baseACK uint32) *aether.Frame {
	payload := aether.EncodeCompositeACK(&aether.CompositeACK{BaseACK: baseACK})
	return &aether.Frame{
		Type:     aether.TypeACK,
		StreamID: 1,
		Length:   uint32(len(payload)),
		Payload:  payload,
	}
}
