/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package reliability

import (
	"sync/atomic"
	"testing"

	"github.com/ORBTR/aether"
)

// The session counter a SendWindow is wired to is charged HeaderSize plus the
// frame's Length as the frame is at Add. The adapter's writeFrame then
// shortens Frame.Payload and Frame.Length on the same *Frame at the write
// boundary (compression, and the ciphertext's tag), so every path that
// removes an entry must subtract what the entry was charged, never the
// frame's length at removal time. commitShorter stands in for that write
// boundary.

func commitShorter(f *aether.Frame, n int) {
	f.Payload = f.Payload[:n]
	f.Length = uint32(n)
}

func newWiredWindow(t *testing.T) (*SendWindow, *atomic.Int64) {
	t.Helper()
	w := NewSendWindow(64)
	var counter atomic.Int64
	w.SetSessionInFlightCounter(&counter)
	return w, &counter
}

func addFrames(t *testing.T, w *SendWindow, n int, length int) []*aether.Frame {
	t.Helper()
	frames := make([]*aether.Frame, 0, n)
	for i := 0; i < n; i++ {
		f := &aether.Frame{Type: aether.TypeDATA, StreamID: 7, Length: uint32(length), Payload: make([]byte, length)}
		w.Add(f)
		frames = append(frames, f)
	}
	return frames
}

// TestSendWindow_InFlightCounterReturnsToZeroWhenCommittedFramesAreAcked:
// each removal path subtracts the count the entry was charged, so the counter
// returns to 0 although every frame's Length was shortened after Add.
func TestSendWindow_InFlightCounterReturnsToZeroWhenCommittedFramesAreAcked(t *testing.T) {
	const plain = 512
	charged := int64(aether.HeaderSize) + int64(plain)

	t.Run("Ack", func(t *testing.T) {
		w, counter := newWiredWindow(t)
		frames := addFrames(t, w, 1, plain)
		if got := counter.Load(); got != charged {
			t.Fatalf("after Add: counter %d, want %d", got, charged)
		}
		commitShorter(frames[0], 9)
		if w.Ack(frames[0].SeqNo) == nil {
			t.Fatal("Ack found no entry")
		}
		if got := counter.Load(); got != 0 {
			t.Fatalf("after Ack of a shortened frame: counter %d, want 0", got)
		}
	})

	t.Run("AckRange", func(t *testing.T) {
		w, counter := newWiredWindow(t)
		frames := addFrames(t, w, 4, plain)
		for _, f := range frames {
			commitShorter(f, 9)
		}
		if n := w.AckRange(frames[0].SeqNo, frames[3].SeqNo); n != 4 {
			t.Fatalf("AckRange acked %d, want 4", n)
		}
		if got := counter.Load(); got != 0 {
			t.Fatalf("after AckRange of shortened frames: counter %d, want 0", got)
		}
	})

	t.Run("ProcessCompositeACK cumulative, bitmap, extended and dropped ranges", func(t *testing.T) {
		w, counter := newWiredWindow(t)
		// seq 0..1 cumulative; seq 2 missing, 3 by bitmap; 4..5 missing; 6..7
		// extended range beyond a 4-byte bitmap window (32 bits from BaseACK+1,
		// so the extended range must start past seq 1+32); 2 dropped.
		frames := addFrames(t, w, 40, plain)
		for _, f := range frames {
			commitShorter(f, 9)
		}
		bitmap := make([]byte, 4)
		bitmap[0] |= 1 << 1 // seq 3 = BaseACK+1+1
		acked, _ := w.ProcessCompositeACK(&aether.CompositeACK{
			BaseACK:       1,
			Bitmap:        bitmap,
			ExtRanges:     []aether.SACKBlock{{Start: 34, End: 39}},
			DroppedRanges: []aether.SACKBlock{{Start: 2, End: 2}},
		}, ReorderThreshold)
		if len(acked) != 2+1+6 {
			t.Fatalf("acked %d entries, want 9", len(acked))
		}
		// 40 added; 2 cumulative + 1 bitmap + 6 extended acked; 1 dropped: 30 left.
		want := 30 * charged
		if got := counter.Load(); got != want {
			t.Fatalf("after the composite ACK: counter %d, want %d (30 entries still charged)", got, want)
		}
		if got := w.InFlightBytes(); got != want {
			t.Fatalf("InFlightBytes() %d, want %d: it sums what the entries were charged", got, want)
		}
		if n := w.AckRange(4, 33); n != 30 {
			t.Fatalf("AckRange acked %d, want 30", n)
		}
		if got := counter.Load(); got != 0 {
			t.Fatalf("after every entry left: counter %d, want 0", got)
		}
	})
}
