/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package flow

import "testing"

// AE-P-14 regression: ConnWindow must cap the receive grant and report
// Available against the true semaphore capacity (maxSize = max(initialCredit,
// DefaultMaxConnCredit)) rather than the hardcoded DefaultMaxConnCredit (16 MB)
// constant. Pre-fix, a window constructed with initialCredit > 16 MB started
// with recvCredit above the constant, so grantLocked computed a negative grant
// and returned 0 forever (the receiver never emitted a WINDOW_UPDATE and the
// peer sender stalled), while Available under-reported the true credit.
//
// Symbol names are AE-P-14-unique (aep14 / TestAEP14_) to avoid collisions with
// concurrently-authored tests in package flow.

const aep14BigCredit int64 = 32 * 1024 * 1024 // 32 MB — strictly above the 16 MB cap.

// TestAEP14_AvailableUsesTrueCapacity asserts Available reports the full
// configured credit for a >16 MB window (pre-fix it returned 16 MB).
func TestAEP14_AvailableUsesTrueCapacity(t *testing.T) {
	w := NewConnWindow(aep14BigCredit)
	if got := w.Available(); got != aep14BigCredit {
		t.Fatalf("Available() = %d, want %d (pre-fix bug returns %d)",
			got, aep14BigCredit, DefaultMaxConnCredit)
	}
}

// TestAEP14_GrantEmittedAboveConstant drives a threshold-crossing consume on a
// 32 MB window and asserts a positive cumulative grant is returned. Pre-fix the
// grant capped against the 16 MB constant, went negative, and returned 0 — the
// window would never emit a WINDOW_UPDATE and the sender would stall.
func TestAEP14_GrantEmittedAboveConstant(t *testing.T) {
	w := NewConnWindow(aep14BigCredit)
	// threshold = 32 MB * AutoGrantThreshold (0.25) = 8 MB; consume 10 MB to
	// cross it decisively in a single payload.
	grant := w.ReceiverConsume(10 * 1024 * 1024)
	if grant <= 0 {
		t.Fatalf("ReceiverConsume returned grant %d, want > 0 (pre-fix pins at 0 for >16 MB windows)", grant)
	}
	// recvCredit must never exceed the true capacity after a grant.
	if rc := w.Stats().RecvCredit; rc > aep14BigCredit {
		t.Fatalf("recvCredit = %d exceeds maxSize %d", rc, aep14BigCredit)
	}
}

// TestAEP14_CommonPathUnchanged is the regression guard for every production
// caller (initialCredit <= 16 MB): capacity == DefaultMaxConnCredit, so
// behavior is byte-identical and no limit is lowered.
func TestAEP14_CommonPathUnchanged(t *testing.T) {
	w := NewConnWindow(DefaultConnCredit)
	if got := w.Available(); got != DefaultConnCredit {
		t.Fatalf("Available() = %d, want %d for the default 4 MB window", got, DefaultConnCredit)
	}
	// Repeated threshold-crossing consumes keep emitting positive grants and
	// never drive recvCredit past the 16 MB cap.
	oneMB := int64(1024 * 1024)
	for i := 0; i < 8; i++ {
		if g := w.ReceiverConsume(oneMB); g <= 0 {
			t.Fatalf("iter %d: grant %d, want > 0", i, g)
		}
		if rc := w.Stats().RecvCredit; rc > DefaultMaxConnCredit {
			t.Fatalf("iter %d: recvCredit %d exceeds maxSize %d", i, rc, DefaultMaxConnCredit)
		}
	}
}

// TestAEP14_BoundaryExactly16MB documents that the trigger is strictly
// > 16 MB: a window built at exactly DefaultMaxConnCredit still emits a
// positive grant on the first threshold-crossing consume.
func TestAEP14_BoundaryExactly16MB(t *testing.T) {
	w := NewConnWindow(DefaultMaxConnCredit)
	if got := w.Available(); got != DefaultMaxConnCredit {
		t.Fatalf("Available() = %d, want %d", got, DefaultMaxConnCredit)
	}
	// threshold = 16 MB * 0.25 = 4 MB; consume exactly 4 MB.
	if g := w.ReceiverConsume(4 * 1024 * 1024); g <= 0 {
		t.Fatalf("grant %d at exactly 16 MB, want > 0", g)
	}
}
