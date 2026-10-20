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
	deliveriesEqual(t, "flush", got, []RecvDelivery{{[]byte("a"), false}, {[]byte("b"), true}, {[]byte("c"), true}})

	// Drain hands back what is still buffered, each with its mark.
	w.InsertMarked(5, []byte("f"), true)
	w.InsertMarked(4, []byte("e"), false)
	deliveriesEqual(t, "drain", w.DrainMarked(), []RecvDelivery{{[]byte("e"), false}, {[]byte("f"), true}})

	// The unmarked entry points report every frame unmarked.
	w2 := NewRecvWindow(16)
	w2.InsertMarked(1, []byte("y"), true)
	if d := w2.Insert(0, []byte("x")); len(d) != 2 {
		t.Fatalf("Insert delivered %d payloads, want 2", len(d))
	}
}

// TestRecvWindowMarkExpiresWithItsFrame: a frame the reorder buffer drops for
// age takes its mark with it, so the next frame delivered under that sequence
// number is not reported marked.
func TestRecvWindowMarkExpiresWithItsFrame(t *testing.T) {
	w := NewRecvWindow(16)
	w.SetMaxAge(time.Millisecond)
	w.InsertMarked(1, []byte("old"), true)
	time.Sleep(5 * time.Millisecond)
	got, _ := w.InsertMarked(0, []byte("a"), false)
	deliveriesEqual(t, "expired skip", got, []RecvDelivery{{[]byte("a"), false}})
	got, _ = w.InsertMarked(2, []byte("c"), false)
	deliveriesEqual(t, "after skip", got, []RecvDelivery{{[]byte("c"), false}})
	if len(w.marked) != 0 {
		t.Fatalf("marks left behind: %v", w.marked)
	}
}
