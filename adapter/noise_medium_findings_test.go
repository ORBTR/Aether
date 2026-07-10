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
	"github.com/ORBTR/aether/congestion"
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
	s := &NoiseSession{streams: make(map[uint64]*noiseStream)}
	s.SetCongestionController(congestion.NewCUBICController())

	eng := reliability.NewEngine(reliability.EngineConfig{StreamID: 5, WindowSize: 64})
	st := &noiseStream{
		streamID:   5,
		session:    s,
		replay:     eng.Replay,
		recvWindow: eng.RecvWin,
		rtt:        eng.RTT,
		// deliverCh buffered large enough that enqueueDelivery (AE-M-02)
		// succeeds without a running deliverLoop — no consumer needed to
		// exercise handleData end-to-end for the cwnd invariant.
		deliverCh: make(chan []byte, 64),
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

// ─── AE-M-02 — stream delivery moved off the shared readLoop ───────────────
//
// DeliverToRecvChWithSignals blocks the caller up to stream1MaxBackpressure
// (1s) on a full stream-1 recvCh. Running it directly on the single readLoop
// stalled the whole session — the readLoop stopped draining the noiseConn
// inbox and silently dropped inbound ACKs for every other stream. The fix
// hands each payload to a per-stream deliverLoop goroutine via a non-blocking
// enqueueDelivery, so a slow consumer blocks only that goroutine.

// TestNoiseEnqueueDeliveryNonBlocking proves the readLoop path (enqueueDelivery)
// never blocks: with no consumer draining, buffering N payloads returns
// immediately. The pre-fix direct DeliverToRecvChWithSignals on stream 1 with
// a full recvCh would have blocked ~1s on the very first payload.
func TestNoiseEnqueueDeliveryNonBlocking(t *testing.T) {
	s := &NoiseSession{}
	st := &noiseStream{
		streamID:  1,
		session:   s,
		recvCh:    make(chan []byte, 1), // tiny — the OLD path would stall here
		deliverCh: make(chan []byte, 8), // enqueue buffers here instead
	}

	const n = 8
	start := time.Now()
	for i := 0; i < n; i++ {
		if !st.enqueueDelivery([]byte{byte(i)}) {
			t.Fatalf("enqueueDelivery(%d) returned false while deliverCh had room", i)
		}
	}
	elapsed := time.Since(start)

	// The old stream-1 path would have paid ~1s per payload once recvCh
	// filled (>= 7s total). Non-blocking enqueue is microseconds; 500ms is a
	// generous, flake-proof ceiling that is still far below one 1s stall.
	if elapsed >= 500*time.Millisecond {
		t.Fatalf("AE-M-02 regressed: enqueuing %d payloads took %v — the readLoop "+
			"path must not block on stream-1 backpressure", n, elapsed)
	}
}

// TestNoiseDeliverLoopPreservesOrder exercises the real async delivery hop:
// the deliverLoop goroutine drains deliverCh (fed in-order by the "readLoop")
// into recvCh. Single producer + single consumer must preserve FIFO order.
func TestNoiseDeliverLoopPreservesOrder(t *testing.T) {
	s := &NoiseSession{}
	st := &noiseStream{
		streamID:  1,
		session:   s,
		recvCh:    make(chan []byte, 128),
		deliverCh: make(chan []byte, 128),
	}
	go st.deliverLoop()
	defer st.teardown() // closes deliverCh → deliverLoop exits

	const n = 100
	for i := 0; i < n; i++ {
		if !st.enqueueDelivery([]byte{byte(i)}) {
			t.Fatalf("enqueueDelivery(%d) returned false unexpectedly", i)
		}
	}
	for i := 0; i < n; i++ {
		select {
		case p := <-st.recvCh:
			if len(p) != 1 || p[0] != byte(i) {
				t.Fatalf("AE-M-02 regressed: out-of-order delivery: got %v want [%d]", p, i)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for payload %d via deliverLoop", i)
		}
	}
}
