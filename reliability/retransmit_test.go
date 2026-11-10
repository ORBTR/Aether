/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package reliability

import (
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

func TestRetransmitQueue_EnqueueDequeue(t *testing.T) {
	rtt := NewRTTEstimator()
	rtt.Update(50 * time.Millisecond) // RTO ~300ms

	q := NewRetransmitQueue(rtt, 0) // unlimited retries

	f := &aether.Frame{Type: aether.TypeDATA, SeqNo: 1, Payload: []byte("hello")}
	q.Enqueue(f)

	if q.Len() != 1 {
		t.Errorf("Len: got %d, want 1", q.Len())
	}

	// Not due yet
	frame := q.Dequeue()
	if frame != nil {
		t.Error("should not be due immediately (RTO ~300ms)")
	}

	// Wait for RTO
	time.Sleep(350 * time.Millisecond)
	frame = q.Dequeue()
	if frame == nil {
		t.Fatal("should be due after RTO")
	}
	if frame.SeqNo != 1 {
		t.Errorf("SeqNo: got %d, want 1", frame.SeqNo)
	}

	// Should have been re-enqueued with doubled RTO
	if q.Len() != 1 {
		t.Errorf("after dequeue, Len: got %d, want 1 (re-enqueued)", q.Len())
	}
}

func TestRetransmitQueue_Remove(t *testing.T) {
	rtt := NewRTTEstimator()
	rtt.Update(50 * time.Millisecond)

	q := NewRetransmitQueue(rtt, 0)
	q.Enqueue(&aether.Frame{Type: aether.TypeDATA, SeqNo: 10})
	q.Enqueue(&aether.Frame{Type: aether.TypeDATA, SeqNo: 20})

	if q.Len() != 2 {
		t.Fatalf("Len: got %d, want 2", q.Len())
	}

	q.Remove(10)
	if q.Len() != 1 {
		t.Errorf("after remove: got %d, want 1", q.Len())
	}

	// Remove non-existent — should be no-op
	q.Remove(99)
	if q.Len() != 1 {
		t.Errorf("after remove non-existent: got %d, want 1", q.Len())
	}
}

func TestRetransmitQueue_MaxRetries(t *testing.T) {
	rtt := newRTTEstimatorWithParams(10*time.Millisecond, time.Second)
	rtt.Update(5 * time.Millisecond) // very short RTO

	q := NewRetransmitQueue(rtt, 2) // max 2 retries
	q.Enqueue(&aether.Frame{Type: aether.TypeDATA, SeqNo: 1})

	// Dequeue 3 times — 1st and 2nd should succeed, 3rd should drop
	time.Sleep(20 * time.Millisecond)
	f1 := q.Dequeue()
	if f1 == nil {
		t.Fatal("1st dequeue should succeed")
	}

	time.Sleep(30 * time.Millisecond)
	f2 := q.Dequeue()
	if f2 == nil {
		t.Fatal("2nd dequeue should succeed")
	}

	time.Sleep(70 * time.Millisecond)
	f3 := q.Dequeue()
	if f3 != nil {
		t.Error("3rd dequeue should return nil (max retries exceeded)")
	}
}

func TestRetransmitQueue_NextDueIn(t *testing.T) {
	rtt := NewRTTEstimator()
	rtt.Update(100 * time.Millisecond) // RTO ~500ms

	q := NewRetransmitQueue(rtt, 0)

	// Empty queue
	d := q.NextDueIn()
	if d < time.Minute {
		t.Errorf("empty queue NextDueIn should be large, got %v", d)
	}

	q.Enqueue(&aether.Frame{Type: aether.TypeDATA, SeqNo: 1})

	d = q.NextDueIn()
	if d <= 0 || d > time.Second {
		t.Errorf("NextDueIn should be 0 < d < 1s, got %v", d)
	}
}

func TestRetransmitQueue_Ordering(t *testing.T) {
	rtt := newRTTEstimatorWithParams(10*time.Millisecond, time.Second)
	rtt.Update(5 * time.Millisecond)

	q := NewRetransmitQueue(rtt, 0)

	// Enqueue 3 frames — all should have similar NextRetry
	q.Enqueue(&aether.Frame{Type: aether.TypeDATA, SeqNo: 1})
	time.Sleep(5 * time.Millisecond)
	q.Enqueue(&aether.Frame{Type: aether.TypeDATA, SeqNo: 2})
	time.Sleep(5 * time.Millisecond)
	q.Enqueue(&aether.Frame{Type: aether.TypeDATA, SeqNo: 3})

	// Wait for all to be due
	time.Sleep(50 * time.Millisecond)

	// Should dequeue in order of NextRetry (earliest first = SeqNo 1)
	f := q.Dequeue()
	if f == nil || f.SeqNo != 1 {
		t.Errorf("first dequeue: got SeqNo %v, want 1", f)
	}
}

// TestRetransmitQueue_ClearDropsEveryEntry: Clear empties the queue, its byte count and
// its index, calls no eviction hook, and the queue takes entries again afterwards.
func TestRetransmitQueue_ClearDropsEveryEntry(t *testing.T) {
	rtt := NewRTTEstimator()
	q := NewRetransmitQueue(rtt, 0)
	evicted := 0
	q.SetOnEvict(func(*RetransmitEntry) { evicted++ })
	q.Enqueue(&aether.Frame{Type: aether.TypeDATA, SeqNo: 1, Payload: []byte("one")})
	q.Enqueue(&aether.Frame{Type: aether.TypeDATA, SeqNo: 2, Payload: []byte("two")})
	if got := q.Clear(); got != 2 {
		t.Fatalf("Clear reported %d, want 2", got)
	}
	if q.Len() != 0 || q.BufferedBytes() != 0 || q.NextDueIn() != time.Hour || evicted != 0 {
		t.Fatalf("after Clear: Len %d, BufferedBytes %d, NextDueIn %s, evicted %d", q.Len(), q.BufferedBytes(), q.NextDueIn(), evicted)
	}
	q.Remove(1)
	q.Enqueue(&aether.Frame{Type: aether.TypeDATA, SeqNo: 1, Payload: []byte("again")})
	if q.Len() != 1 || q.BufferedBytes() != 5 {
		t.Fatalf("after a new Enqueue: Len %d, BufferedBytes %d", q.Len(), q.BufferedBytes())
	}
	q.Remove(1)
	if q.Len() != 0 {
		t.Fatalf("Remove after Clear left %d entries", q.Len())
	}
}
