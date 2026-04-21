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

// 1D regression: when a window-credit getter is attached and it returns
// a value larger than the engine's last-emitted credit, the built
// CompositeACK MUST carry CACKHasWindowCredit + the current cumulative
// grant in WindowCredit. Subsequent builds at the same cumulative grant
// MUST NOT re-emit (duplicate suppression via lastEmittedCredit).
func TestACKEngine_BuildCompositeACK_PiggyBacksWindowCredit(t *testing.T) {
	rw := NewRecvWindow(64)
	var sent *aether.CompositeACK
	e := NewACKEngine(rw, DefaultACKPolicy(), func(ack *aether.CompositeACK) {
		sent = ack
	}, func() time.Duration { return 10 * time.Millisecond })

	// No getter installed → WindowCredit must NOT appear.
	ack := e.BuildCompositeACK()
	if ack.Flags&aether.CACKHasWindowCredit != 0 {
		t.Errorf("no getter installed: CACKHasWindowCredit unexpectedly set")
	}

	// Install getter returning 12345. Next build must carry it.
	var currentGrant int64 = 12345
	e.SetWindowCreditFn(func() int64 { return currentGrant })
	ack = e.BuildCompositeACK()
	if ack.Flags&aether.CACKHasWindowCredit == 0 {
		t.Fatal("CACKHasWindowCredit not set on first emit with positive grant")
	}
	if ack.WindowCredit != 12345 {
		t.Errorf("WindowCredit: got %d, want 12345", ack.WindowCredit)
	}

	// Getter returns SAME cumulative value. Second build MUST NOT re-emit.
	ack2 := e.BuildCompositeACK()
	if ack2.Flags&aether.CACKHasWindowCredit != 0 {
		t.Error("duplicate cumulative grant re-emitted (should be suppressed by lastEmittedCredit)")
	}

	// Getter returns LARGER cumulative. Third build must emit again with
	// the new value.
	currentGrant = 99999
	ack3 := e.BuildCompositeACK()
	if ack3.Flags&aether.CACKHasWindowCredit == 0 {
		t.Fatal("new larger cumulative grant not emitted")
	}
	if ack3.WindowCredit != 99999 {
		t.Errorf("WindowCredit: got %d, want 99999", ack3.WindowCredit)
	}

	_ = sent // sendACK callback not exercised here — BuildCompositeACK is direct
}

// 1D: when the window getter returns 0 (no grant yet), the piggyback
// flag MUST NOT be set. Otherwise the peer's ApplyUpdate would be
// called with credit=0 which is a silent no-op but wastes wire space
// + a flag bit on every ACK until the first grant arrives.
func TestACKEngine_BuildCompositeACK_NoCreditOmitsFlag(t *testing.T) {
	rw := NewRecvWindow(64)
	e := NewACKEngine(rw, DefaultACKPolicy(), func(*aether.CompositeACK) {},
		func() time.Duration { return 0 })

	e.SetWindowCreditFn(func() int64 { return 0 })

	ack := e.BuildCompositeACK()
	if ack.Flags&aether.CACKHasWindowCredit != 0 {
		t.Errorf("zero grant should not set CACKHasWindowCredit flag (got Flags=0x%x)", ack.Flags)
	}
	if ack.WindowCredit != 0 {
		t.Errorf("zero grant should leave WindowCredit=0, got %d", ack.WindowCredit)
	}
}

// 1D: SetWindowCreditFn(nil) disables piggybacking — matches the
// "pass nil to disable" contract in the public API.
func TestACKEngine_BuildCompositeACK_NilGetterDisables(t *testing.T) {
	rw := NewRecvWindow(64)
	e := NewACKEngine(rw, DefaultACKPolicy(), func(*aether.CompositeACK) {},
		func() time.Duration { return 0 })

	// First install a real getter + emit.
	e.SetWindowCreditFn(func() int64 { return 5000 })
	ack := e.BuildCompositeACK()
	if ack.Flags&aether.CACKHasWindowCredit == 0 {
		t.Fatal("precondition failed: expected flag set on first emit")
	}

	// Remove getter. Next build must not attempt piggyback.
	e.SetWindowCreditFn(nil)
	ack2 := e.BuildCompositeACK()
	if ack2.Flags&aether.CACKHasWindowCredit != 0 {
		t.Error("nil getter did not disable piggyback")
	}
}
