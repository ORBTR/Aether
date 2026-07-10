/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package scheduler

import (
	"testing"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/metrics"
)

func TestScheduler_SingleStream(t *testing.T) {
	s := NewScheduler()
	s.Register(1, 128, 0)

	f := &aether.Frame{Type: aether.TypeDATA, StreamID: 1, Length: 10, Payload: make([]byte, 10)}
	s.Enqueue(1, f)

	got, _ := s.Dequeue()
	if got == nil {
		t.Fatal("expected frame from single stream")
	}
	if got.StreamID != 1 {
		t.Errorf("StreamID: got %d, want %d", got.StreamID, 1)
	}

	// Queue empty now
	if f, _ := s.Dequeue(); f != nil {
		t.Error("should be nil after draining")
	}
}

func TestScheduler_WeightedFairness(t *testing.T) {
	s := NewScheduler()
	// High priority stream (weight 255) vs low priority (weight 16)
	s.Register(100, 255, 0) // high
	s.Register(200, 16, 0)  // low

	// Enqueue equal number of frames
	for i := 0; i < 20; i++ {
		s.Enqueue(100, &aether.Frame{Type: aether.TypeDATA, StreamID: 100, Length: 50, Payload: make([]byte, 50)})
		s.Enqueue(200, &aether.Frame{Type: aether.TypeDATA, StreamID: 200, Length: 50, Payload: make([]byte, 50)})
	}

	// With WFQ, the high-weight stream has lower virtual finish time
	// so it gets served first. Check that the first N frames are predominantly
	// from the high-weight stream.
	first10High := 0
	for i := 0; i < 10; i++ {
		f, _ := s.Dequeue()
		if f == nil {
			break
		}
		if f.StreamID == 100 {
			first10High++
		}
	}

	// Weight ratio is 255:16 = ~16:1. In the first 10 frames, most should be from high.
	if first10High < 8 {
		t.Errorf("first 10 frames should be mostly high-weight: got %d/10 high", first10High)
	}
	t.Logf("First 10 frames: %d/10 from high-weight stream", first10High)
}

func TestScheduler_EmptyQueues(t *testing.T) {
	s := NewScheduler()
	s.Register(1, 128, 0)
	s.Register(2, 128, 0)

	if !s.IsEmpty() {
		t.Error("should be empty with no frames")
	}
	if f, _ := s.Dequeue(); f != nil {
		t.Error("dequeue on empty should return nil")
	}
}

func TestScheduler_Unregister(t *testing.T) {
	s := NewScheduler()
	s.Register(1, 128, 0)
	s.Enqueue(1, &aether.Frame{Type: aether.TypeDATA, StreamID: 1, Length: 0})

	s.Unregister(1)
	if s.StreamCount() != 0 {
		t.Errorf("StreamCount after unregister: got %d, want 0", s.StreamCount())
	}
	if f, _ := s.Dequeue(); f != nil {
		t.Error("dequeue after unregister should return nil")
	}
}

func TestScheduler_SetWeight(t *testing.T) {
	s := NewScheduler()
	s.Register(1, 64, 0)
	s.SetWeight(1, 255)

	// Enqueue and verify it still works
	s.Enqueue(1, &aether.Frame{Type: aether.TypeDATA, StreamID: 1, Length: 0})
	if f, _ := s.Dequeue(); f == nil {
		t.Error("should dequeue after weight change")
	}
}

func TestScheduler_Len(t *testing.T) {
	s := NewScheduler()
	s.Register(1, 128, 0)
	s.Register(2, 128, 0)

	s.Enqueue(1, &aether.Frame{Type: aether.TypeDATA, StreamID: 1, Length: 0})
	s.Enqueue(1, &aether.Frame{Type: aether.TypeDATA, StreamID: 1, Length: 0})
	s.Enqueue(2, &aether.Frame{Type: aether.TypeDATA, StreamID: 2, Length: 0})

	if s.Len() != 3 {
		t.Errorf("Len: got %d, want 3", s.Len())
	}
	if s.QueueLen(1) != 2 {
		t.Errorf("QueueLen(1): got %d, want 2", s.QueueLen(1))
	}
	if s.QueueLen(2) != 1 {
		t.Errorf("QueueLen(2): got %d, want 1", s.QueueLen(2))
	}
}

func TestScheduler_KeepaliveNeverStarved(t *testing.T) {
	s := NewScheduler()
	// Keepalive at max priority, gossip flooding at low priority
	s.Register(2, 255, 0)
	s.Register(0, 16, 0)

	// Flood gossip with 100 frames
	for i := 0; i < 100; i++ {
		s.Enqueue(0, &aether.Frame{Type: aether.TypeDATA, StreamID: 0, Length: 100, Payload: make([]byte, 100)})
	}

	// Add one keepalive
	s.Enqueue(2, &aether.Frame{Type: aether.TypePING, StreamID: 2, Length: 0})

	// Keepalive should be dequeued within the first few frames (not after 100 gossip frames)
	keepaliveSent := false
	for i := 0; i < 10; i++ {
		f, _ := s.Dequeue()
		if f == nil {
			break
		}
		if f.StreamID == 2 {
			keepaliveSent = true
			break
		}
	}

	if !keepaliveSent {
		t.Error("keepalive should be sent within first 10 frames — it's being starved")
	}
}

// TestScheduler_DepthHistogram verifies OBS-9 wiring: the scheduler's
// queueDepth atomic counter tracks Enqueue / Dequeue / Unregister
// transitions, and signalWake + ObserveDepth push samples into the
// wired metrics.Uint32Ring. Together those two sampling points cover
// both the "work arrives" and "queue drained, idle" faces of the
// distribution the audit OBS-9 fix was asked to surface.
func TestScheduler_DepthHistogram(t *testing.T) {
	s := NewScheduler()
	var ring metrics.Uint32Ring
	s.SetDepthHist(&ring)

	// ObserveDepth with no traffic records a zero sample — the
	// drained-idle face is non-trivial even at start-of-life.
	s.ObserveDepth()
	if got, want := ring.Count(), 1; got != want {
		t.Fatalf("ObserveDepth: count = %d, want %d", got, want)
	}

	s.Register(1, 128, 0)
	s.Register(2, 128, 0)

	// Three enqueues — each fires signalWake which records a sample.
	// After each Enqueue the depth observed should reflect the
	// post-increment value (1, 2, 3 respectively).
	s.Enqueue(1, &aether.Frame{Type: aether.TypeDATA, StreamID: 1, Length: 10, Payload: make([]byte, 10)})
	s.Enqueue(1, &aether.Frame{Type: aether.TypeDATA, StreamID: 1, Length: 10, Payload: make([]byte, 10)})
	s.Enqueue(2, &aether.Frame{Type: aether.TypeDATA, StreamID: 2, Length: 10, Payload: make([]byte, 10)})

	if got, want := ring.Count(), 4; got != want {
		t.Fatalf("after 3 enqueues + 1 observe: count = %d, want %d", got, want)
	}

	// Drain one — Dequeue must decrement queueDepth. We can't read
	// the ring's individual samples directly, but a follow-up
	// ObserveDepth lands a depth-2 entry.
	frame, _ := s.Dequeue()
	if frame == nil {
		t.Fatal("Dequeue returned nil with 3 frames queued")
	}
	s.ObserveDepth()

	// Drain the rest.
	for {
		f, _ := s.Dequeue()
		if f == nil {
			break
		}
	}
	s.ObserveDepth() // depth = 0 sample

	// A second external Wake() with no frames lands another sample —
	// signalWake fires regardless of whether the wake-channel was
	// already pending, because it's the depth observation that
	// matters for OBS-9.
	s.Wake()

	// Final sanity: the ring's percentile readout must produce some
	// non-decreasing pair (p50 ≤ p99). Zero ⇒ no samples, which
	// would mean the wiring never fired.
	p50, p99 := ring.PercentileSnapshot()
	if p50 > p99 {
		t.Fatalf("ring percentiles inverted: p50=%d > p99=%d", p50, p99)
	}
	if ring.Count() == 0 {
		t.Fatal("ring captured zero samples — OBS-9 wiring is dark")
	}
}

// TestScheduler_DepthHistogram_NilSafe asserts that a scheduler with
// no depth histogram wired (the default for unit tests and non-noise
// adapters) treats every Enqueue / Dequeue / ObserveDepth / Wake as a
// no-op for sampling purposes — i.e. we have not introduced a nil
// deref on the hot path.
func TestScheduler_DepthHistogram_NilSafe(t *testing.T) {
	s := NewScheduler()
	s.Register(1, 128, 0)
	// No SetDepthHist call → depthHist is nil.
	s.Enqueue(1, &aether.Frame{Type: aether.TypeDATA, StreamID: 1, Length: 1, Payload: make([]byte, 1)})
	s.ObserveDepth()
	s.Wake()
	_, _ = s.Dequeue()
	// If we got here without panicking, nil-safety holds.
}

// AE-H-05 regression: a capped REALTIME class must be DEMOTED into the
// INTERACTIVE round rather than dropped from every round. The two tests below
// lock in (1) a REALTIME-only connection no longer stalls once it trips the
// 10% cap, and (2) a capped REALTIME stream loses its absolute priority but
// still makes forward progress under contention.

// newDataFrameH05 builds a minimally-valid DATA frame of the given payload
// length tagged with its owning stream ID so a drained frame can be classified
// back to its stream. The scheduler only reads Length/Type, so Payload is nil.
func newDataFrameH05(streamID uint64, length uint32) *aether.Frame {
	return &aether.Frame{
		StreamID: streamID,
		Type:     aether.TypeDATA,
		Length:   length,
	}
}

// TestRealtimeCapDoesNotStallRealtimeOnly is the core AE-H-05 regression: with
// only REALTIME work queued, the >10% bandwidth cap trips after the first frame
// (bytesOut = HeaderSize + 1200 pins the ratio at 100%). Pre-fix the loop
// dropped capped REALTIME from every round, so every Dequeue after the first
// returned nil and the connection stalled forever. Post-fix the capped class is
// demoted into the INTERACTIVE round and every frame drains.
func TestRealtimeCapDoesNotStallRealtimeOnly(t *testing.T) {
	s := NewScheduler()
	const rtID = uint64(1)
	s.RegisterWithClass(rtID, DefaultWeight, 0, aether.ClassREALTIME)

	const n = 50
	for i := 0; i < n; i++ {
		// Length 1200 => bytesOut 1250; the very first frame consumes 100% of
		// the window so the cap trips from the second Dequeue onward.
		s.Enqueue(rtID, newDataFrameH05(rtID, 1200))
	}

	drained := 0
	// Bound the loop so a regression (permanent nil) fails fast instead of
	// hanging the test.
	for i := 0; i < n*4; i++ {
		frame, _ := s.Dequeue()
		if frame == nil {
			break
		}
		drained++
	}

	if drained != n {
		t.Fatalf("REALTIME-only connection stalled under the 10%% cap: drained %d of %d frames (want all %d)", drained, n, n)
	}
	if !s.IsEmpty() {
		t.Fatalf("scheduler still reports queued frames after draining; cap left work stranded")
	}
}

// TestRealtimeCapDemotesRealtimePriority proves the cap still does its job: once
// REALTIME exceeds its share it is folded into the INTERACTIVE round and
// competes there via WFQ instead of retaining absolute priority. With a REALTIME
// stream and an INTERACTIVE stream both loaded, (a) both classes fully drain
// (REALTIME not stalled, INTERACTIVE not starved) and (b) REALTIME frames are
// interleaved with INTERACTIVE frames during the capped period rather than the
// REALTIME stream monopolising every round.
//
// NOTE (deviation from the original test plan, which paired REALTIME with a
// BULK stream): the fix folds a capped REALTIME class into the *INTERACTIVE*
// round, which still ranks above BULK — so a demoted REALTIME stream keeps its
// priority over BULK and the two never interleave. INTERACTIVE is therefore the
// class that genuinely contends with a demoted REALTIME stream, so this test
// pairs REALTIME with INTERACTIVE to exercise the demotion faithfully.
func TestRealtimeCapDemotesRealtimePriority(t *testing.T) {
	s := NewScheduler()
	const (
		rtID = uint64(1)
		inID = uint64(2)
	)
	s.RegisterWithClass(rtID, DefaultWeight, 0, aether.ClassREALTIME)
	s.RegisterWithClass(inID, DefaultWeight, 0, aether.ClassINTERACTIVE)

	const perStream = 20
	for i := 0; i < perStream; i++ {
		s.Enqueue(rtID, newDataFrameH05(rtID, 1200))
		s.Enqueue(inID, newDataFrameH05(inID, 1200))
	}

	var rtSeen, inSeen int
	lastInteractiveIdx := -1
	// Record the drain order so we can prove interleaving. Bound the loop as a
	// stall guard.
	seq := make([]uint64, 0, perStream*2)
	for i := 0; i < perStream*8; i++ {
		frame, _ := s.Dequeue()
		if frame == nil {
			break
		}
		seq = append(seq, frame.StreamID)
		switch frame.StreamID {
		case rtID:
			rtSeen++
		case inID:
			inSeen++
			lastInteractiveIdx = len(seq) - 1
		default:
			t.Fatalf("dequeued frame with unexpected StreamID %d", frame.StreamID)
		}
	}

	// (a) Both classes fully drain.
	if rtSeen != perStream {
		t.Fatalf("REALTIME stream did not fully drain under cap: served %d of %d", rtSeen, perStream)
	}
	if inSeen != perStream {
		t.Fatalf("INTERACTIVE stream did not fully drain: served %d of %d", inSeen, perStream)
	}

	// (b) REALTIME lost its absolute priority: many REALTIME frames were served
	// interleaved with INTERACTIVE frames (before the final INTERACTIVE frame),
	// rather than the REALTIME stream monopolising every round. Pre-fix, capped
	// REALTIME was dropped from every round, so no REALTIME frame could be
	// served while INTERACTIVE work remained.
	rtBeforeLastInteractive := 0
	for i, id := range seq {
		if id == rtID && i < lastInteractiveIdx {
			rtBeforeLastInteractive++
		}
	}
	if rtBeforeLastInteractive < 5 {
		t.Fatalf("REALTIME frames were not interleaved with INTERACTIVE under the cap: only %d REALTIME frames served before the last INTERACTIVE frame (want >= 5); drain order=%v", rtBeforeLastInteractive, seq)
	}
}
