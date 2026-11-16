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

// TestSendWindow_OldestWrittenIsTheOldestUnackedFrameAndItsLastWrite: OldestWritten
// names the lowest written entry still held, skipping an unwritten one, and moves to
// the next once that entry is acknowledged; the time it reports is the entry's last
// write, which a retransmit's write moves and BumpXmitTime, a retransmit only queued,
// does not.
func TestSendWindow_OldestWrittenIsTheOldestUnackedFrameAndItsLastWrite(t *testing.T) {
	w := NewSendWindow(64)
	frames := make([]*aether.Frame, 4)
	for i := range frames {
		frames[i] = &aether.Frame{Type: aether.TypeDATA, Payload: []byte("x"), Length: 1}
		w.Add(frames[i])
	}
	if f, _, _ := w.OldestWritten(); f != nil {
		t.Fatalf("no frame is written, OldestWritten gave SeqNo %d", f.SeqNo)
	}
	t0 := time.Now().Add(-time.Second)
	w.MarkWritten(frames[1], 60, t0, nil)
	w.MarkWritten(frames[2], 60, t0, nil)
	f, seq, at := w.OldestWritten()
	if f != frames[1] || seq != frames[1].SeqNo || !at.Equal(t0) {
		t.Fatalf("OldestWritten = SeqNo %d at %v, want the written SeqNo %d at %v, the unwritten SeqNo %d skipped", seq, at, frames[1].SeqNo, t0, frames[0].SeqNo)
	}

	w.BumpXmitTime(frames[1].SeqNo, time.Now())
	if _, _, at := w.OldestWritten(); !at.Equal(t0) {
		t.Fatalf("a retransmit only queued moved the last write to %v, want %v", at, t0)
	}
	t1 := t0.Add(500 * time.Millisecond)
	w.MarkWritten(frames[1], 60, t1, nil)
	if _, _, at := w.OldestWritten(); !at.Equal(t1) {
		t.Fatalf("a retransmit's write left the last write at %v, want %v", at, t1)
	}

	w.Ack(frames[1].SeqNo)
	if f, seq, _ := w.OldestWritten(); f != frames[2] {
		t.Fatalf("after SeqNo %d is acknowledged OldestWritten = SeqNo %d, want %d", frames[1].SeqNo, seq, frames[2].SeqNo)
	}
}
