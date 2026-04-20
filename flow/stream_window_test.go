/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package flow

import "testing"

func TestStreamWindow_ConsumeAndAvailable(t *testing.T) {
	w := NewStreamWindow(1024)

	if w.Available() != 1024 {
		t.Errorf("initial: got %d, want 1024", w.Available())
	}

	if err := w.Consume(512); err != nil {
		t.Fatalf("consume 512: %v", err)
	}
	if w.Available() != 512 {
		t.Errorf("after 512: got %d, want 512", w.Available())
	}

	// Exhaust
	if err := w.Consume(512); err != nil {
		t.Fatalf("consume remaining: %v", err)
	}
	if w.Available() != 0 {
		t.Errorf("after exhaust: got %d, want 0", w.Available())
	}

	// Small frames within MinGuaranteedWindow are always allowed (deadlock prevention)
	if err := w.Consume(512); err != nil {
		t.Errorf("small frame within MinGuaranteedWindow should be allowed: %v", err)
	}

	// Large over-consume beyond MinGuaranteedWindow should error
	if err := w.Consume(MinGuaranteedWindow + 1); err == nil {
		t.Error("should error on overconsume beyond MinGuaranteedWindow")
	}
}

func TestStreamWindow_ApplyUpdate(t *testing.T) {
	w := NewStreamWindow(1024)
	w.Consume(1024) // exhaust

	w.ApplyUpdate(2048)
	if w.Available() != 2048 {
		t.Errorf("after update: got %d, want 2048", w.Available())
	}
}

func TestStreamWindow_ApplyUpdate_Capped(t *testing.T) {
	w := NewStreamWindow(1024)
	w.ApplyUpdate(DefaultMaxStreamCredit + 1000)
	if w.Available() > DefaultMaxStreamCredit {
		t.Errorf("should cap at max: got %d", w.Available())
	}
}

func TestStreamWindow_ReceiverAutoGrant(t *testing.T) {
	w := NewStreamWindow(1024)

	// Consume less than threshold — no grant
	grant := w.ReceiverConsume(100)
	if grant != 0 {
		t.Errorf("small consume: got grant %d, want 0", grant)
	}

	// Consume past 50% threshold (512 bytes) — should grant
	grant = w.ReceiverConsume(500) // total 600 > 512 threshold
	if grant == 0 {
		t.Error("should grant after exceeding threshold")
	}
	if grant != 600 {
		t.Errorf("grant amount: got %d, want 600", grant)
	}
}

func TestConnWindow_ConsumeAndAvailable(t *testing.T) {
	w := NewConnWindow(4096)

	if err := w.Consume(2048); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if w.Available() != 2048 {
		t.Errorf("after consume: got %d, want 2048", w.Available())
	}

	if err := w.Consume(3000); err == nil {
		t.Error("should error on overconsume")
	}
}

func TestConnWindow_ReceiverAutoGrant(t *testing.T) {
	w := NewConnWindow(4096)

	// Consume past 50% (2048)
	grant := w.ReceiverConsume(3000)
	if grant == 0 {
		t.Error("should grant after exceeding threshold")
	}
}
