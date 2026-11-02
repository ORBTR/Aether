//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"context"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/congestion"
	"github.com/ORBTR/aether/flow"
	"github.com/ORBTR/aether/reliability"
	"github.com/ORBTR/aether/scheduler"
)

// ─── AE-M-01 — peer AckDelay scaled into TLP ──────────────────────────────
//
// handleACK feeds the peer's advertised max_ack_delay (AckDelay field, in
// 8µs wire units) into TLP's PTO EWMA. The buggy decode multiplied only by
// AckDelayGranularity (the untyped constant 8) without `* time.Microsecond`,
// yielding a value 1000x too small (nanoseconds instead of microseconds).
// Over successive ACKs the EWMA decayed maxAckDelay toward ~µs, collapsing
// PTO to the 10ms floor and firing spurious TLP probes on any path whose
// real ACK cadence exceeds ~10ms.
//
// AckDelay=3125 wire units == 3125*8µs == 25ms. With the fix, feeding it
// repeatedly holds maxAckDelay at ~25ms so PTO ≈ 25ms; with the bug PTO
// collapses to the 10ms floor. NewTLP(0) pins srtt=0 (handleACK never
// updates tlp.srtt), so PTO is purely maxAckDelay clamped to [10ms, 1s] —
// a clean discriminator around the 20ms assertion.
func TestHandleACK_PeerAckDelayScaledIntoTLP(t *testing.T) {
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

	// AckDelay=3125 (8µs units) == 25ms. Empty-bitmap CompositeACK encodes to
	// exactly CompositeACKMinSize so it decodes cleanly and ProcessCompositeACK
	// treats it as benign (no in-flight, no abuse).
	payload := aether.EncodeCompositeACK(&aether.CompositeACK{BaseACK: 0, AckDelay: 3125})
	frame := &aether.Frame{
		Type:     aether.TypeACK,
		StreamID: 1,
		Length:   uint32(len(payload)),
		Payload:  payload,
	}

	// Drive the EWMA to steady state.
	for i := 0; i < 50; i++ {
		s.handleACK(frame)
	}

	if pto := st.tlp.Snapshot().PTO; pto < 20*time.Millisecond {
		t.Fatalf("AE-M-01 regressed: TLP PTO = %v, want >= 20ms — peer AckDelay "+
			"decoded 1000x too small (missing * time.Microsecond) collapses PTO "+
			"to the 10ms floor", pto)
	}
}

// ─── AE-M-03 — inbound DATA must not inflate send-side cwnd ────────────────
//
// handleData processes DATA frames arriving FROM the peer. Its final line
// used to call congestion().OnAck(frame.Length, ...) — the acknowledgement-
// of-OUR-sent-data hook, which grows the shared send-side cwnd. Feeding
// received bytes into it inflated cwnd in proportion to how much the peer
// sent us (unrelated to our own in-flight/loss state), letting a later send
// burst past the safe window. The fix removes the call; send-side cwnd is
// advanced solely by ACKs of locally-sent data in handleACK.
func TestHandleData_DoesNotInflateCWND(t *testing.T) {
	s := &NoiseSession{streams: make(map[uint64]*noiseStream), connWindow: flow.NewConnWindow(0)}
	s.SetCongestionController(congestion.NewCUBICController())

	eng := reliability.NewEngine(reliability.EngineConfig{StreamID: 5, WindowSize: 64})
	st := &noiseStream{
		streamID:   5,
		session:    s,
		replay:     eng.Replay,
		recvWindow: eng.RecvWin,
		rtt:        eng.RTT,
		window:     flow.NewStreamWindow(0),
		// recvQ takes the payloads with no consumer reading: none is needed
		// to exercise handleData end-to-end for the cwnd invariant.
		recvQ: newRecvQueue(&s.recvQueued),
	}
	s.streams[5] = st

	before := s.CongestionWindow()

	// Fresh, in-order inbound DATA — all classified ResultNew.
	for seq := uint32(0); seq < 8; seq++ {
		s.handleData(&aether.Frame{
			Type:     aether.TypeDATA,
			StreamID: 5,
			SeqNo:    seq,
			Length:   1200,
			Payload:  make([]byte, 1200),
		})
	}

	if after := s.CongestionWindow(); after != before {
		t.Fatalf("AE-M-03 regressed: inbound DATA grew send-side cwnd: "+
			"before=%d after=%d — handleData must not feed received bytes "+
			"into congestion().OnAck", before, after)
	}
}

// ─── stream delivery never waits on the shared readLoop ─────────────────────
//
// The readLoop serves every stream on the session, so it must never wait on one
// stream's consumer: it would stop draining the noiseConn inbox and inbound
// ACKs for every other stream would be lost behind it. recvQ is what the
// readLoop hands a message to, and enqueueDelivery takes no wait.

// noiseStreamForDelivery is a stream with what enqueueDelivery and Receive read.
func noiseStreamForDelivery(streamID uint64) *noiseStream {
	s := &NoiseSession{
		BaseSession: aether.NewBaseSession("a", "b", aether.ProtoNoise),
		connWindow:  flow.NewConnWindow(0),
	}
	return &noiseStream{
		streamID: streamID,
		session:  s,
		window:   flow.NewStreamWindow(0),
		recvQ:    newRecvQueue(&s.recvQueued),
		recvDone: make(chan struct{}),
	}
}

// TestNoiseEnqueueDeliveryNonBlocking: with no consumer reading, queueing many
// messages returns at once.
func TestNoiseEnqueueDeliveryNonBlocking(t *testing.T) {
	st := noiseStreamForDelivery(1)
	const n = 1000
	start := time.Now()
	for i := 0; i < n; i++ {
		if !st.enqueueDelivery([]byte{byte(i)}) {
			t.Fatalf("enqueueDelivery(%d) returned false within the stream's credit", i)
		}
	}
	// Queueing is microseconds; 500ms is a generous, flake-proof ceiling.
	if elapsed := time.Since(start); elapsed >= 500*time.Millisecond {
		t.Fatalf("enqueuing %d payloads took %v — the readLoop path must not wait", n, elapsed)
	}
}

// TestNoiseRecvQueuePreservesOrder: one producer and one consumer see FIFO
// order, with Receive running ahead of the producer as well as behind it.
func TestNoiseRecvQueuePreservesOrder(t *testing.T) {
	st := noiseStreamForDelivery(1)
	const n = 100
	go func() {
		for i := 0; i < n; i++ {
			if !st.enqueueDelivery([]byte{byte(i)}) {
				t.Errorf("enqueueDelivery(%d) returned false unexpectedly", i)
				return
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for i := 0; i < n; i++ {
		p, err := st.Receive(ctx)
		if err != nil {
			t.Fatalf("receive %d: %v", i, err)
		}
		if len(p) != 1 || p[0] != byte(i) {
			t.Fatalf("out-of-order delivery: got %v want [%d]", p, i)
		}
	}
}
