/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import (
	"sync/atomic"
	"testing"
)

// ael03FakeCompressible implements the existing CompressionCapable interface
// so applyDegradation can toggle a LIVE registered session. AE-L-03.
type ael03FakeCompressible struct {
	enabled atomic.Bool
}

func (f *ael03FakeCompressible) CompressionEnabled() bool     { return f.enabled.Load() }
func (f *ael03FakeCompressible) SetCompressionEnabled(v bool) { f.enabled.Store(v) }

// TestAEL03_DegradesLiveSessions proves the load-shedding ladder now reaches a
// registered session's runtime compression toggle (the exact thing that was
// dead before AE-L-03), and that FEC/scheduler rung decisions are recorded and
// restored with hysteresis.
func TestAEL03_DegradesLiveSessions(t *testing.T) {
	a := NewAdaptiveController()
	s := &ael03FakeCompressible{}
	s.SetCompressionEnabled(true)
	a.Register(s)

	// Above all three rungs: compression must be disabled on the live session.
	a.applyDegradation(95)
	if s.CompressionEnabled() {
		t.Fatal("AE-L-03: expected compression disabled on live session at 95% CPU, got enabled")
	}
	if !a.fecDegraded {
		t.Fatal("AE-L-03: expected fecDegraded=true above 80%")
	}
	if !a.schedDegraded {
		t.Fatal("AE-L-03: expected schedDegraded=true above 90%")
	}

	// Load cleared: compression restored below 65%, rungs cleared.
	a.applyDegradation(10)
	if !s.CompressionEnabled() {
		t.Fatal("AE-L-03: expected compression restored on live session below 65% CPU, got disabled")
	}
	if a.fecDegraded {
		t.Fatal("AE-L-03: expected fecDegraded=false below 75%")
	}
	if a.schedDegraded {
		t.Fatal("AE-L-03: expected schedDegraded=false below 85%")
	}
}

// TestAEL03_UnregisterHonored proves an unregistered session is no longer
// touched by the controller's degrade sweep.
func TestAEL03_UnregisterHonored(t *testing.T) {
	a := NewAdaptiveController()
	s := &ael03FakeCompressible{}
	s.SetCompressionEnabled(true)
	a.Register(s)
	a.Unregister(s)

	a.applyDegradation(95)
	if !s.CompressionEnabled() {
		t.Fatal("AE-L-03: unregistered session must not be degraded; expected compression still enabled")
	}
}
