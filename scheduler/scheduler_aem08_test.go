/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package scheduler

import (
	"testing"

	"github.com/ORBTR/aether"
)

// TestScheduler_NewStreamDoesNotStarveEstablished_AEM08 is the AE-M-08
// regression: a newly-registered (or re-registered) stream must not
// monopolise its latency class by entering WFQ at deficit=0 while established
// same-class streams have accumulated a large virtual finish time.
// dequeueFromClass selects the minimum-finish stream, so a zero-deficit
// newcomer would win every Dequeue in its class until its deficit climbed to
// match — starving the established streams for that catch-up window. The fix
// seeds an idle/new stream up to the class's current virtual start time on the
// empty→backlogged edge, so the newcomer competes fairly from the start.
//
// Pre-fix, stream 2 (deficit 0) wins all 40 dequeues and established stream 1
// (deficit ~156) is starved (served1 == 0), so this test fails — proving the
// bug. Post-fix the two equal-weight streams share the class roughly evenly.
// Fully deterministic: equal weights, equal frame sizes, no concurrency.
func TestScheduler_NewStreamDoesNotStarveEstablished_AEM08(t *testing.T) {
	s := NewScheduler()
	s.RegisterWithClass(1, DefaultWeight, 0, aether.ClassBULK)

	// Phase 1 — grow stream 1's virtual finish time (deficit) by sending a
	// long run of frames one at a time (enqueue then drain), leaving stream 1
	// at a large deficit with an empty queue at the end.
	const warmup = 200
	for i := 0; i < warmup; i++ {
		s.Enqueue(1, newDataFrameH05(1, 50))
		if f, _ := s.Dequeue(); f == nil {
			t.Fatalf("warmup dequeue %d returned nil", i)
		}
	}
	establishedDeficit := s.streams[1].deficit
	if establishedDeficit <= 0 {
		t.Fatalf("stream 1 deficit did not grow during warmup: got %v", establishedDeficit)
	}

	// A fresh same-class stream registers at deficit 0 (RegisterWithClass
	// deliberately leaves zero-init; the Enqueue-edge seed subsumes it).
	s.RegisterWithClass(2, DefaultWeight, 0, aether.ClassBULK)
	if got := s.streams[2].deficit; got != 0 {
		t.Fatalf("newly registered stream 2 should start at deficit 0, got %v", got)
	}

	// Phase 2 — backlog both streams. The first Enqueue(2) fires on the
	// empty→backlogged edge with stream 1 already backlogged, so AE-M-08 seeds
	// stream 2 up to stream 1's virtual time.
	const perStream = 40
	for i := 0; i < perStream; i++ {
		s.Enqueue(1, newDataFrameH05(1, 50))
		s.Enqueue(2, newDataFrameH05(2, 50))
	}

	// The newcomer must have been seeded to (at least) the class virtual start
	// time — never left at 0 to grief the established stream.
	if got := s.streams[2].deficit; got < establishedDeficit {
		t.Fatalf("AE-M-08: stream 2 was not seeded to the class virtual start: deficit=%v, want >= %v", got, establishedDeficit)
	}

	// Drain and count who is served.
	var served1, served2 int
	for i := 0; i < perStream*2; i++ {
		f, _ := s.Dequeue()
		if f == nil {
			break
		}
		switch f.StreamID {
		case 1:
			served1++
		case 2:
			served2++
		default:
			t.Fatalf("unexpected StreamID %d", f.StreamID)
		}
	}

	// Pre-fix, stream 2 (deficit 0) wins every dequeue and stream 1 is starved.
	if served1 == 0 {
		t.Fatalf("AE-M-08: established stream 1 was starved by the new stream (served1=0, served2=%d)", served2)
	}
	// With the fix the two equal-weight, equal-size streams share the class
	// roughly evenly (~20/20).
	if served1 < perStream/4 {
		t.Fatalf("AE-M-08: established stream 1 under-served: served1=%d, served2=%d (want served1 >= %d)", served1, served2, perStream/4)
	}
}

// TestScheduler_ReRegisterCannotResetVirtualTime_AEM08 locks in the griefing
// lever the finding calls out: re-registering an established stream resets its
// deficit to 0, but the Enqueue-edge seed re-raises it to the class virtual
// start on the next backlog, so the reset cannot be used to jump the WFQ queue.
func TestScheduler_ReRegisterCannotResetVirtualTime_AEM08(t *testing.T) {
	s := NewScheduler()
	s.RegisterWithClass(1, DefaultWeight, 0, aether.ClassBULK)
	s.RegisterWithClass(2, DefaultWeight, 0, aether.ClassBULK)

	// Advance stream 1's virtual time and keep it backlogged so it defines the
	// class virtual start.
	for i := 0; i < 50; i++ {
		s.Enqueue(1, newDataFrameH05(1, 50))
		if f, _ := s.Dequeue(); f == nil {
			t.Fatalf("warmup dequeue %d returned nil", i)
		}
	}
	s.Enqueue(1, newDataFrameH05(1, 50)) // leave stream 1 backlogged
	classStart := s.streams[1].deficit
	if classStart <= 0 {
		t.Fatalf("stream 1 deficit did not grow: got %v", classStart)
	}

	// Re-register stream 2 (deficit reset to 0), then Enqueue — the seed must
	// re-raise it to the current class virtual start rather than letting it
	// re-enter ahead of the backlogged front-runner.
	s.RegisterWithClass(2, DefaultWeight, 0, aether.ClassBULK)
	if got := s.streams[2].deficit; got != 0 {
		t.Fatalf("re-register should reset stream 2 to deficit 0, got %v", got)
	}
	s.Enqueue(2, newDataFrameH05(2, 50))
	if got := s.streams[2].deficit; got < classStart {
		t.Fatalf("AE-M-08: re-registered stream 2 kept a reset (below-min) deficit %v, want >= %v", got, classStart)
	}
}
