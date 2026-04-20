/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package scheduler

import (
	"testing"

	"github.com/ORBTR/aether"
)

func TestScheduler_SingleStream(t *testing.T) {
	s := NewScheduler()
	s.Register(1, 128, 0)

	f := &aether.Frame{Type: aether.TypeDATA, StreamID: 1, Length: 10, Payload: make([]byte, 10)}
	s.Enqueue(1, f)

	got := s.Dequeue()
	if got == nil {
		t.Fatal("expected frame from single stream")
	}
	if got.StreamID != 1 {
		t.Errorf("StreamID: got %d, want %d", got.StreamID, 1)
	}

	// Queue empty now
	if s.Dequeue() != nil {
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
		f := s.Dequeue()
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
	if s.Dequeue() != nil {
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
	if s.Dequeue() != nil {
		t.Error("dequeue after unregister should return nil")
	}
}

func TestScheduler_SetWeight(t *testing.T) {
	s := NewScheduler()
	s.Register(1, 64, 0)
	s.SetWeight(1, 255)

	// Enqueue and verify it still works
	s.Enqueue(1, &aether.Frame{Type: aether.TypeDATA, StreamID: 1, Length: 0})
	if s.Dequeue() == nil {
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
		f := s.Dequeue()
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
