/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package scheduler

import (
	"testing"

	"github.com/ORBTR/aether"
)

func dataFrame(id uint64, seq uint32) *aether.Frame {
	return &aether.Frame{Type: aether.TypeDATA, StreamID: id, SeqNo: seq, Length: 4, Payload: make([]byte, 4)}
}

// TestScheduler_DequeueNamesTheRegistrationAFrameCameFrom: a frame and a probe come
// out with the registration they were queued under, and the ID's next registration
// is a different one, so a frame of the earlier registration is told from the later's.
func TestScheduler_DequeueNamesTheRegistrationAFrameCameFrom(t *testing.T) {
	s := NewScheduler()
	first := s.Register(7, 128, 0)
	if first == 0 {
		t.Fatal("a registration is named by a non-zero Registration")
	}
	s.Enqueue(7, dataFrame(7, 1))
	f, isProbe, reg := s.DequeueFrom()
	if f == nil || isProbe || reg != first {
		t.Fatalf("DequeueFrom = %v, probe %v, registration %d; want the frame of registration %d", f, isProbe, reg, first)
	}
	s.EnqueueProbe(7, dataFrame(7, 1))
	if p, reg := s.DequeueProbeFrom(); p == nil || reg != first {
		t.Fatalf("DequeueProbeFrom = %v, registration %d; want the probe of registration %d", p, reg, first)
	}

	s.Unregister(7)
	second := s.Register(7, 128, 0)
	if second == first {
		t.Fatalf("the ID's second registration is named %d, as its first was", second)
	}
	s.Enqueue(7, dataFrame(7, 1))
	if _, _, reg := s.DequeueFrom(); reg != second {
		t.Fatalf("a frame queued under the second registration came out as %d, want %d", reg, second)
	}
	if f, _, reg := s.DequeueFrom(); f != nil || reg != 0 {
		t.Fatalf("an empty scheduler handed out %v under %d", f, reg)
	}
}

// TestScheduler_AnEndedRegistrationLeavesItsSuccessorRegistered: the ID's next stream
// registers before the stream that held it unregisters, as NoiseSession's peer-opened
// stream can. The second registration replaces the first, dropping what the first had
// queued, and the first's UnregisterRegistration leaves the second and its frames.
func TestScheduler_AnEndedRegistrationLeavesItsSuccessorRegistered(t *testing.T) {
	s := NewScheduler()
	first := s.Register(9, 128, 0)
	s.Enqueue(9, dataFrame(9, 1))
	s.EnqueueProbe(9, dataFrame(9, 1))
	second := s.Register(9, 128, 0)
	if got := s.Len(); got != 0 {
		t.Fatalf("the replaced registration's frames are still queued: %d", got)
	}
	if got := s.queueDepth.Load(); got != 0 {
		t.Fatalf("depth %d after the replaced registration's frames were dropped", got)
	}
	if got := len(s.order); got != 1 {
		t.Fatalf("the ID is %d times in the round-robin order", got)
	}
	if !s.Enqueue(9, dataFrame(9, 1)) {
		t.Fatal("the second registration took no frame")
	}
	if dropped, probe := s.UnregisterRegistration(9, first); dropped != nil || probe != nil {
		t.Fatalf("the ended registration's exit dropped %d frames and probe %v of its successor's", len(dropped), probe)
	}
	if got := s.StreamCount(); got != 1 {
		t.Fatalf("%d registrations after the ended one's exit, want its successor's", got)
	}
	if _, _, reg := s.DequeueFrom(); reg != second {
		t.Fatalf("the successor's frame came out as %d, want %d", reg, second)
	}
	if dropped, _ := s.UnregisterRegistration(9, second); dropped != nil {
		t.Fatalf("dropped %d frames from an empty registration", len(dropped))
	}
	if got := s.StreamCount(); got != 0 {
		t.Fatalf("%d registrations after the successor's own exit", got)
	}
}
