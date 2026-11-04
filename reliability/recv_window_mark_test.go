/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package reliability

import (
	"testing"
	"time"
)

func deliveriesEqual(t *testing.T, label string, got []RecvDelivery, want []RecvDelivery) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: %d deliveries, want %d (%+v)", label, len(got), len(want), got)
	}
	for i := range want {
		if string(got[i].Payload) != string(want[i].Payload) || got[i].Marked != want[i].Marked {
			t.Fatalf("%s: delivery %d = {%q %v}, want {%q %v}", label, i,
				got[i].Payload, got[i].Marked, want[i].Payload, want[i].Marked)
		}
	}
}

// TestRecvWindowMarkTravelsWithItsFrame: the mark a caller attaches to a frame
// comes back with that frame's payload whether it is delivered at once, after
// waiting in the reorder buffer, or by Drain, and a re-inserted buffered frame
// keeps the mark of its latest insert.
func TestRecvWindowMarkTravelsWithItsFrame(t *testing.T) {
	w := NewRecvWindow(16)
	if got, ok := w.InsertMarked(2, []byte("c"), true); !ok || got != nil {
		t.Fatalf("buffered insert: %+v, %v", got, ok)
	}
	if got, ok := w.InsertMarked(1, []byte("b"), false); !ok || got != nil {
		t.Fatalf("buffered insert: %+v, %v", got, ok)
	}
	if _, ok := w.InsertMarked(1, []byte("b"), true); !ok {
		t.Fatalf("re-insert of a buffered frame refused")
	}
	got, ok := w.InsertMarked(0, []byte("a"), false)
	if !ok {
		t.Fatalf("in-order insert refused")
	}
	deliveriesEqual(t, "flush", got, []RecvDelivery{{Payload: []byte("a"), Marked: false}, {Payload: []byte("b"), Marked: true}, {Payload: []byte("c"), Marked: true}})

	// Drain hands back what is still buffered, each with its mark.
	w.InsertMarked(5, []byte("f"), true)
	w.InsertMarked(4, []byte("e"), false)
	deliveriesEqual(t, "drain", w.DrainMarked(), []RecvDelivery{{Payload: []byte("e"), Marked: false}, {Payload: []byte("f"), Marked: true}})

	// The unmarked entry points report every frame unmarked.
	w2 := NewRecvWindow(16)
	w2.InsertMarked(1, []byte("y"), true)
	if d := w2.Insert(0, []byte("x")); len(d) != 2 {
		t.Fatalf("Insert delivered %d payloads, want 2", len(d))
	}
}

// TestRecvWindowMarkExpiresWithItsFrame: a frame that outwaits SetMaxAge comes
// back Expired with its mark and its payload, so the caller can settle its charge,
// and the next frame is not reported marked. The unmarked entry point reads no
// Expired frame as a message and counts it.
func TestRecvWindowMarkExpiresWithItsFrame(t *testing.T) {
	w := NewRecvWindow(16)
	w.SetMaxAge(time.Millisecond)
	w.InsertMarked(1, []byte("old"), true)
	time.Sleep(5 * time.Millisecond)
	got, _ := w.InsertMarked(0, []byte("a"), false)
	deliveriesEqual(t, "expired frame", got, []RecvDelivery{{Payload: []byte("a")}, {Payload: []byte("old"), Marked: true}})
	if got[0].Expired || !got[1].Expired {
		t.Fatalf("expired flags = %v, %v; want the buffered frame's alone", got[0].Expired, got[1].Expired)
	}
	got, _ = w.InsertMarked(2, []byte("c"), false)
	deliveriesEqual(t, "after the expired frame", got, []RecvDelivery{{Payload: []byte("c"), Marked: false}})
	if len(w.marked) != 0 {
		t.Fatalf("marks left behind: %v", w.marked)
	}

	w2 := NewRecvWindow(16)
	w2.SetMaxAge(time.Millisecond)
	w2.Insert(1, []byte("old"))
	time.Sleep(5 * time.Millisecond)
	if plain := w2.Insert(0, []byte("a")); len(plain) != 1 || string(plain[0]) != "a" {
		t.Fatalf("Insert returned %q, want only the message", plain)
	}
	if n := w2.ExpiredCount(); n != 1 {
		t.Fatalf("ExpiredCount = %d, want 1", n)
	}
}

// TestRecvWindow_AnEndFrameNeverExpires: a buffered CLOSE, older than SetMaxAge
// when its turn comes, still comes back End: it was acknowledged when it was
// buffered, so nothing would end the receive side after it.
func TestRecvWindow_AnEndFrameNeverExpires(t *testing.T) {
	w := NewRecvWindow(16)
	w.SetMaxAge(time.Millisecond)
	if got, ok := w.InsertEnd(1); !ok || got != nil {
		t.Fatalf("InsertEnd out of order = %v, %v", got, ok)
	}
	time.Sleep(5 * time.Millisecond)
	got, _ := w.InsertMarked(0, []byte("a"), false)
	if len(got) != 2 || got[1].Expired || !got[1].End {
		t.Fatalf("deliveries = %+v, want the message and then End", got)
	}
}

// A CLOSE takes its place in the sequence: it comes back End behind every frame
// before it, however it arrived, and a frame after it stays where it belongs.
func TestRecvWindow_AnEndFrameComesBackBehindEveryFrameBeforeIt(t *testing.T) {
	w := NewRecvWindow(16)
	if got, ok := w.InsertEnd(2); !ok || got != nil {
		t.Fatalf("end ahead of its frames: %+v, %v", got, ok)
	}
	if got, ok := w.InsertMarked(1, []byte("b"), false); !ok || got != nil {
		t.Fatalf("frame behind a gap: %+v, %v", got, ok)
	}
	got, ok := w.InsertMarked(0, []byte("a"), false)
	if !ok || len(got) != 3 || string(got[0].Payload) != "a" || string(got[1].Payload) != "b" || !got[2].End || got[0].End || got[1].End {
		t.Fatalf("fill: %+v, %v", got, ok)
	}
	if w.ExpectedSeqNo() != 3 {
		t.Fatalf("expected %d: the end frame's sequence number is one the ACK engine reads", w.ExpectedSeqNo())
	}
	w = NewRecvWindow(16)
	got, ok = w.InsertEnd(0)
	if !ok || len(got) != 1 || !got[0].End {
		t.Fatalf("end in order: %+v, %v", got, ok)
	}
	// The mark does not stay behind for the next frame on that sequence number.
	w = NewRecvWindow(16)
	w.InsertEnd(1)
	w.InsertMarked(1, []byte("x"), false)
	got, _ = w.InsertMarked(0, []byte("y"), false)
	if len(got) != 2 || got[1].End {
		t.Fatalf("a re-insert as DATA kept the end mark: %+v", got)
	}
}
