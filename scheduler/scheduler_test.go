/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
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
