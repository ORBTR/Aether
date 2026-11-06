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

// ageQueuedFrame moves the retransmit queue's one entry into the past: due now,
// and enqueued an hour ago.
func ageQueuedFrame(t *testing.T, q *RetransmitQueue) {
	t.Helper()
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.queue.Len() != 1 {
		t.Fatalf("premise: %d entries queued, want 1", q.queue.Len())
	}
	e := q.queue.data[0]
	e.NextRetry = time.Now().Add(-time.Second)
	e.EnqueuedAt = time.Now().Add(-time.Hour)
}

// TestNewEngine_MaxAgeReachesBothQueues: EngineConfig.MaxAge, which a NoiseSession
// fills from the stream's aether.StreamConfig.MaxAge, bounds a frame's age on the
// receive window (a buffered frame older than it comes back Expired when its turn
// comes) and on the retransmit queue (the RTO path gives an older frame to onEvict
// and resends nothing). With MaxAge zero both deliver and resend whatever the age.
func TestNewEngine_MaxAgeReachesBothQueues(t *testing.T) {
	for _, tc := range []struct {
		name   string
		maxAge time.Duration
	}{{"a positive MaxAge", 5 * time.Millisecond}, {"no MaxAge", 0}} {
		t.Run(tc.name, func(t *testing.T) {
			bounded := tc.maxAge > 0
			e := NewEngine(EngineConfig{StreamID: 1, Reliability: aether.ReliableOrdered, WindowSize: 16, MaxAge: tc.maxAge})

			if _, ok := e.RecvWin.InsertMarked(1, []byte("late"), false); !ok {
				t.Fatal("premise: the frame after a gap was not buffered")
			}
			time.Sleep(20 * time.Millisecond)
			got, _ := e.RecvWin.InsertMarked(0, []byte("gap"), false)
			if len(got) != 2 || got[0].Expired {
				t.Fatalf("filling the gap delivered %+v, want the gap and the buffered frame", got)
			}
			if got[1].Expired != bounded {
				t.Fatalf("the buffered frame, 20 ms old: Expired %v, want %v", got[1].Expired, bounded)
			}

			var evicted int
			e.RetransmitQ.SetOnEvict(func(*RetransmitEntry) { evicted++ })
			frame := &aether.Frame{StreamID: 1, Type: aether.TypeDATA, Length: 4, Payload: []byte("data")}
			e.Send(frame)
			ageQueuedFrame(t, e.RetransmitQ)
			resent := e.RetransmitQ.Dequeue()
			if bounded && (resent != nil || evicted != 1) {
				t.Fatalf("an hour-old frame under MaxAge: resent %v, evicted %d; want nothing resent and one eviction", resent != nil, evicted)
			}
			if !bounded && (resent != frame || evicted != 0) {
				t.Fatalf("an hour-old frame with no MaxAge: resent %v, evicted %d; want it resent", resent != nil, evicted)
			}
		})
	}
}
