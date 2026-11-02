/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package reliability

import (
	"testing"

	"github.com/ORBTR/aether"
)

// TestSendWindow_ReleaseInFlightReturnsTheCounterToZero: a window whose
// stream leaves the session with entries in flight gives back every entry's
// charge once, and a later ACK of a released seq subtracts nothing.
func TestSendWindow_ReleaseInFlightReturnsTheCounterToZero(t *testing.T) {
	const plain = 512
	w, counter := newWiredWindow(t)
	frames := addFrames(t, w, 5, plain)
	for _, f := range frames {
		commitShorter(f, 9)
	}
	released := w.ReleaseInFlight()
	if want := 5 * (int64(aether.HeaderSize) + int64(plain)); released != want {
		t.Fatalf("ReleaseInFlight returned %d, want %d", released, want)
	}
	if got := counter.Load(); got != 0 {
		t.Fatalf("after ReleaseInFlight: counter %d, want 0", got)
	}
	if got := w.InFlight(); got != 0 {
		t.Fatalf("after ReleaseInFlight: %d entries, want 0", got)
	}
	if w.Ack(frames[2].SeqNo) != nil {
		t.Fatal("Ack after ReleaseInFlight found an entry")
	}
	if got := counter.Load(); got != 0 {
		t.Fatalf("after an ACK of a released seq: counter %d, want 0", got)
	}
	if again := w.ReleaseInFlight(); again != 0 {
		t.Fatalf("second ReleaseInFlight returned %d, want 0", again)
	}
}

// TestSendWindow_AddAfterReleaseInFlightChargesNothing: a frame added after
// the window's stream left the session (a Send that passed the stream's
// state check before the Reset's transition and reached Add after the
// release) is neither stored nor charged, so the counter stays at 0 and no
// entry exists for the seq it was given.
func TestSendWindow_AddAfterReleaseInFlightChargesNothing(t *testing.T) {
	const plain = 512
	w, counter := newWiredWindow(t)
	addFrames(t, w, 2, plain)
	if released := w.ReleaseInFlight(); released == 0 {
		t.Fatal("premise: ReleaseInFlight released nothing")
	}
	late := &aether.Frame{Type: aether.TypeDATA, StreamID: 7, Length: plain, Payload: make([]byte, plain)}
	seq, entry := w.AddEntry(late)
	if entry != nil {
		t.Fatalf("AddEntry after ReleaseInFlight returned an entry (InFlightBytes %d), want nil", entry.InFlightBytes)
	}
	if late.SeqNo != seq {
		t.Fatalf("the late frame carries SeqNo %d, want the assigned %d", late.SeqNo, seq)
	}
	if got := w.GetEntry(seq); got != nil {
		t.Fatalf("GetEntry(%d) found an entry after a released Add", seq)
	}
	if got := counter.Load(); got != 0 {
		t.Fatalf("after a late Add: counter %d, want 0", got)
	}
	if got := w.InFlight(); got != 0 {
		t.Fatalf("after a late Add: %d entries, want 0", got)
	}
	if got := w.InFlightBytes(); got != 0 {
		t.Fatalf("after a late Add: InFlightBytes %d, want 0", got)
	}
}
