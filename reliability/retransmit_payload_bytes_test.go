/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package reliability

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// commitAtWriteBoundary does to a queued frame what the adapter's writeFrame
// does under its writeMu after the frame was enqueued here: it swaps Payload
// for a shorter compressed form and then for the ciphertext that is 16 bytes
// longer than that, and sets Length to match. The queue must not read the
// frame after Enqueue, so what it holds for the frame stays the payload
// bytes the sender handed over.
func commitAtWriteBoundary(f *aether.Frame, committed int) {
	f.Payload = bytes.Repeat([]byte{0xC0}, committed)
	f.Length = uint32(committed)
	f.Flags = f.Flags.Set(aether.FlagCOMPRESSED).Set(aether.FlagENCRYPTED)
}

func dueQueue(t *testing.T, maxRetries int) *RetransmitQueue {
	t.Helper()
	rtt := newRTTEstimatorWithParams(time.Millisecond, time.Second)
	rtt.Update(time.Millisecond)
	return NewRetransmitQueue(rtt, maxRetries)
}

func bufferedBytes(t *testing.T, q *RetransmitQueue) int64 {
	t.Helper()
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.bufferedBytes
}

// waitDue sleeps until the queue's earliest entry is due, so the next
// Dequeue acts on it instead of returning nil for "not due yet".
func waitDue(t *testing.T, q *RetransmitQueue) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for q.NextDueIn() > 0 {
		if time.Now().After(deadline) {
			t.Fatal("the queue's earliest entry did not come due within 2 s")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestRetransmitQueue_ByteCountIsTheEntrysOwnFixedAtEnqueue: the payload byte
// count the queue adds at Enqueue is the count it subtracts when the entry
// leaves, on every leaving path, however the write boundary has changed the
// frame's Payload in between; so the sum returns to 0 when the queue is empty
// and the cap compares against the payload bytes the queue holds.
func TestRetransmitQueue_ByteCountIsTheEntrysOwnFixedAtEnqueue(t *testing.T) {
	const sent, committed = 300, 40
	newFrame := func(seq uint32) *aether.Frame {
		return &aether.Frame{Type: aether.TypeDATA, SeqNo: seq, Length: sent, Payload: bytes.Repeat([]byte{'a'}, sent)}
	}

	t.Run("Remove after the write boundary committed the frame", func(t *testing.T) {
		q := dueQueue(t, 0)
		f := newFrame(1)
		q.Enqueue(f)
		if got := bufferedBytes(t, q); got != sent {
			t.Fatalf("after Enqueue bufferedBytes=%d, want %d", got, sent)
		}
		commitAtWriteBoundary(f, committed)
		q.Remove(1)
		if got := bufferedBytes(t, q); got != 0 {
			t.Fatalf("after Remove bufferedBytes=%d, want 0 (the entry added %d and must subtract %d, not the committed %d)", got, sent, sent, committed)
		}
	})

	t.Run("BufferedBytes reads the same sum", func(t *testing.T) {
		q := dueQueue(t, 0)
		f := newFrame(1)
		q.Enqueue(f)
		commitAtWriteBoundary(f, committed)
		if got := q.BufferedBytes(); got != sent {
			t.Fatalf("BufferedBytes=%d, want %d", got, sent)
		}
	})

	t.Run("eviction for room subtracts the evicted entry's own count", func(t *testing.T) {
		q := dueQueue(t, 0)
		q.SetMaxBytes(500)
		a := newFrame(1)
		q.Enqueue(a)
		commitAtWriteBoundary(a, committed)
		var evicted []uint32
		q.SetOnEvict(func(e *RetransmitEntry) { evicted = append(evicted, e.Frame.SeqNo) })
		q.Enqueue(newFrame(2)) // 300+300 > 500: the oldest entry goes
		if len(evicted) != 1 || evicted[0] != 1 {
			t.Fatalf("evicted %v, want [1]", evicted)
		}
		if got := bufferedBytes(t, q); got != sent {
			t.Fatalf("after eviction bufferedBytes=%d, want %d (the one entry left)", got, sent)
		}
	})

	t.Run("Dequeue drops after max retries subtract the entry's own count", func(t *testing.T) {
		q := dueQueue(t, 1)
		f := newFrame(1)
		q.Enqueue(f)
		commitAtWriteBoundary(f, committed)
		waitDue(t, q)
		if got := q.Dequeue(); got == nil {
			t.Fatal("first Dequeue: want the frame, got nil")
		}
		if got := bufferedBytes(t, q); got != sent {
			t.Fatalf("after a retransmit bufferedBytes=%d, want %d (the entry is still queued)", got, sent)
		}
		waitDue(t, q)
		if got := q.Dequeue(); got != nil {
			t.Fatalf("second Dequeue: want nil (max retries 1 exceeded), got seq %d", got.SeqNo)
		}
		if n := q.Len(); n != 0 {
			t.Fatalf("after the max-retries drop Len=%d, want 0", n)
		}
		if got := bufferedBytes(t, q); got != 0 {
			t.Fatalf("after the max-retries drop bufferedBytes=%d, want 0", got)
		}
	})

	t.Run("Dequeue drops an acked entry by its own count", func(t *testing.T) {
		q := dueQueue(t, 0)
		f := newFrame(1)
		se := &SendEntry{Frame: f}
		q.EnqueueFromSend(se)
		commitAtWriteBoundary(f, committed)
		se.Acked = true
		waitDue(t, q)
		if got := q.Dequeue(); got != nil {
			t.Fatalf("Dequeue of an acked entry: want nil, got seq %d", got.SeqNo)
		}
		if n := q.Len(); n != 0 {
			t.Fatalf("after the acked drop Len=%d, want 0", n)
		}
		if got := bufferedBytes(t, q); got != 0 {
			t.Fatalf("after the acked drop bufferedBytes=%d, want 0", got)
		}
	})
}

// TestRetransmitQueue_NeverReadsTheFrameAfterEnqueue runs Dequeue and Remove
// while another goroutine commits the frame the way the adapter's write loop
// does under its own lock, which the queue does not take. The queue must
// read nothing of the frame after Enqueue but SeqNo, which is never written
// after the send window numbers it; a read of Payload or Length here is a
// data race the race detector reports.
func TestRetransmitQueue_NeverReadsTheFrameAfterEnqueue(t *testing.T) {
	for round := 0; round < 20; round++ {
		q := dueQueue(t, 0)
		f := &aether.Frame{Type: aether.TypeDATA, SeqNo: 7, Length: 300, Payload: bytes.Repeat([]byte{'a'}, 300)}
		q.Enqueue(f)
		waitDue(t, q)
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			commitAtWriteBoundary(f, 40)
		}()
		close(start)
		if got := q.Dequeue(); got == nil {
			t.Fatalf("round %d: Dequeue: want the due frame, got nil", round)
		}
		q.Remove(7)
		wg.Wait()
		if got := bufferedBytes(t, q); got != 0 {
			t.Fatalf("round %d: bufferedBytes=%d, want 0", round, got)
		}
	}
}
