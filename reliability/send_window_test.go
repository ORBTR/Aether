/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package reliability

import (
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

func TestSendWindow_AddAndAck(t *testing.T) {
	w := NewSendWindow(10)

	f1 := &aether.Frame{Type: aether.TypeDATA, Payload: []byte("a")}
	f2 := &aether.Frame{Type: aether.TypeDATA, Payload: []byte("b")}

	seq1 := w.Add(f1)
	seq2 := w.Add(f2)

	if seq1 != 0 {
		t.Errorf("first SeqNo: got %d, want 0", seq1)
	}
	if seq2 != 1 {
		t.Errorf("second SeqNo: got %d, want 1", seq2)
	}
	if w.InFlight() != 2 {
		t.Errorf("InFlight: got %d, want 2", w.InFlight())
	}

	entry := w.Ack(0)
	if entry == nil {
		t.Fatal("Ack(0) returned nil")
	}
	if w.InFlight() != 1 {
		t.Errorf("InFlight after ack: got %d, want 1", w.InFlight())
	}
	if w.Base() != 1 {
		t.Errorf("Base after ack: got %d, want 1", w.Base())
	}
}

func TestSendWindow_AckRange(t *testing.T) {
	w := NewSendWindow(10)

	for i := 0; i < 5; i++ {
		w.Add(&aether.Frame{Type: aether.TypeDATA})
	}

	count := w.AckRange(1, 3) // ack SeqNos 1, 2, 3
	if count != 3 {
		t.Errorf("AckRange count: got %d, want 3", count)
	}
	if w.InFlight() != 2 { // 0 and 4 still in flight
		t.Errorf("InFlight: got %d, want 2", w.InFlight())
	}
}

func TestSendWindow_IsFull(t *testing.T) {
	w := NewSendWindow(3)

	w.Add(&aether.Frame{Type: aether.TypeDATA})
	w.Add(&aether.Frame{Type: aether.TypeDATA})
	if w.IsFull() {
		t.Error("should not be full with 2/3")
	}

	w.Add(&aether.Frame{Type: aether.TypeDATA})
	if !w.IsFull() {
		t.Error("should be full with 3/3")
	}

	w.Ack(0)
	if w.IsFull() {
		t.Error("should not be full after ack")
	}
}

func TestSendWindow_Expired(t *testing.T) {
	w := NewSendWindow(10)
	w.Add(&aether.Frame{Type: aether.TypeDATA})

	// Immediately check — should not be expired
	expired := w.Expired(100 * time.Millisecond)
	if len(expired) != 0 {
		t.Errorf("should not be expired immediately, got %d", len(expired))
	}

	// Wait and check
	time.Sleep(150 * time.Millisecond)
	expired = w.Expired(100 * time.Millisecond)
	if len(expired) != 1 {
		t.Errorf("should have 1 expired, got %d", len(expired))
	}
}

func TestSendWindow_GetEntry(t *testing.T) {
	w := NewSendWindow(10)
	w.Add(&aether.Frame{Type: aether.TypeDATA, Payload: []byte("hello")})

	entry := w.GetEntry(0)
	if entry == nil {
		t.Fatal("GetEntry(0) returned nil")
	}
	if string(entry.Frame.Payload) != "hello" {
		t.Errorf("payload: got %q, want %q", entry.Frame.Payload, "hello")
	}

	// Non-existent SeqNo
	if w.GetEntry(99) != nil {
		t.Error("GetEntry(99) should return nil")
	}
}
