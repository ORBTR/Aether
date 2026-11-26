/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package reliability

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// The session counter a SendWindow is wired to is charged the count MarkWritten
// is given at the frame's first write. The adapter's writeFrame rewrites
// Frame.Payload and Frame.Length on the same *Frame at the write boundary
// (compression, and the ciphertext's tag), so every path that removes an entry
// must subtract what the entry was charged, never the frame's length at removal
// time. commitShorter stands in for that rewrite.

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
		w.MarkWritten(f, int64(aether.HeaderSize)+int64(length), time.Now(), nil)
		frames = append(frames, f)
	}
	return frames
}

// TestSendWindow_AFrameIsChargedAtItsWriteAndOnlyThere: Add charges nothing and
// starts no clock; the first MarkWritten charges its count; a retransmit changes
// neither the charge nor the recorded count; an entry acked unwritten gives back
// nothing and a later write of its frame charges nothing.
func TestSendWindow_AFrameIsChargedAtItsWriteAndOnlyThere(t *testing.T) {
	w, counter := newWiredWindow(t)
	f := &aether.Frame{Type: aether.TypeDATA, StreamID: 7, Length: 512, Payload: make([]byte, 512)}
	seq := w.Add(f)
	if got := counter.Load(); got != 0 {
		t.Fatalf("after Add: counter %d, want 0", got)
	}
	if got := len(w.SnapshotEntries()); got != 0 {
		t.Fatalf("after Add: %d entries visible to RACK, want 0", got)
	}
	if w.WrittenFrame(seq) != nil {
		t.Fatal("after Add: WrittenFrame found the frame")
	}
	if fr, _ := w.HighestWritten(); fr != nil {
		t.Fatal("after Add: HighestWritten found the frame")
	}

	recorded, payload, first := w.MarkWritten(f, 300, time.Now(), nil)
	if recorded != 300 || payload != 512 || !first {
		t.Fatalf("first write: recorded %d, payload %d, first %v", recorded, payload, first)
	}
	if got := counter.Load(); got != 300 {
		t.Fatalf("after the first write: counter %d, want 300", got)
	}
	e := w.GetEntry(seq)
	if e == nil || e.SentAt.IsZero() {
		t.Fatal("after the first write: no send time")
	}
	sentAt := e.SentAt

	later := sentAt.Add(time.Second)
	recorded, _, first = w.MarkWritten(f, 280, later, nil)
	if recorded != 300 || first {
		t.Fatalf("retransmit: recorded %d, first %v; want the first count", recorded, first)
	}
	if got := counter.Load(); got != 300 {
		t.Fatalf("after a retransmit: counter %d, want 300", got)
	}
	if !e.SentAt.Equal(sentAt) || !e.XmitTime.Equal(later) {
		t.Fatalf("retransmit moved SentAt to %v or XmitTime to %v", e.SentAt, e.XmitTime)
	}
	if w.Ack(seq) == nil {
		t.Fatal("Ack found no entry")
	}
	if got := counter.Load(); got != 0 {
		t.Fatalf("after Ack: counter %d, want 0", got)
	}

	unwritten := &aether.Frame{Type: aether.TypeDATA, StreamID: 7, Length: 512, Payload: make([]byte, 512)}
	useq := w.Add(unwritten)
	if got := w.Ack(useq); got == nil || got.InFlightBytes != 0 || got.Written {
		t.Fatalf("acked unwritten entry: %+v", got)
	}
	if recorded, _, first := w.MarkWritten(unwritten, 300, time.Now(), nil); recorded != 0 || first {
		t.Fatalf("write after its ACK: recorded %d, first %v", recorded, first)
	}
	if got := counter.Load(); got != 0 {
		t.Fatalf("a frame written after its ACK charged the counter: %d", got)
	}

	// A frame beside the window that happens to carry a tracked SeqNo charges nothing.
	tracked := &aether.Frame{Type: aether.TypeDATA, StreamID: 7, Length: 1, Payload: []byte{1}}
	tseq := w.Add(tracked)
	beside := &aether.Frame{Type: aether.TypeFEC_REPAIR, SeqNo: tseq}
	if recorded, _, first := w.MarkWritten(beside, 99, time.Now(), nil); recorded != 0 || first {
		t.Fatalf("a frame beside the window: recorded %d, first %v", recorded, first)
	}
}

// TestSendWindow_InFlightCounterReturnsToZeroWhenCommittedFramesAreAcked:
// each removal path subtracts the count the entry was charged, so the counter
// returns to 0 although every frame's Length was shortened after its write.
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
