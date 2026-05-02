/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

package congestion

import (
	"testing"
	"time"
)

// TestCUBICOnLossIdempotenceWithinRecovery — repeated OnLoss calls within
// the same recovery epoch don't compound the cwnd reduction. This is the
// exact bug FLOW-DIAG diagnosed in production: every RTO retransmit was
// triggering a fresh OnLoss, driving cwnd to the floor.
func TestCUBICOnLossIdempotenceWithinRecovery(t *testing.T) {
	c := NewCUBICController()
	// Drive cwnd up via slow-start.
	for i := 0; i < 100; i++ {
		c.OnAck(1400, 20*time.Millisecond)
	}
	preCwnd := c.CWND()
	if preCwnd <= initialCWND {
		t.Skipf("cwnd didn't grow as expected (%d <= %d) — slow-start not driving", preCwnd, initialCWND)
	}

	// First loss — triggers reduction.
	c.OnLossWithPipe(preCwnd)
	afterFirstLoss := c.CWND()
	if afterFirstLoss >= preCwnd {
		t.Errorf("first OnLoss didn't reduce cwnd: %d -> %d", preCwnd, afterFirstLoss)
	}

	// Second + third OnLoss within the same recovery — must not compound.
	c.OnLossWithPipe(preCwnd)
	c.OnLossWithPipe(preCwnd)
	afterRepeated := c.CWND()
	if afterRepeated != afterFirstLoss {
		t.Errorf("repeated OnLoss compounded reduction: %d -> %d (expected stable)",
			afterFirstLoss, afterRepeated)
	}
}

// TestCUBICResetCWNDExitsRecovery — ResetCWND restores cwnd to initial
// and clears recovery state.
func TestCUBICResetCWNDExitsRecovery(t *testing.T) {
	c := NewCUBICController()
	// Drive into fast recovery with a collapsed cwnd.
	for i := 0; i < 50; i++ {
		c.OnAck(1400, 20*time.Millisecond)
	}
	c.OnLossWithPipe(int64(c.cwnd))
	if c.State() != "fast-recovery" {
		t.Fatalf("expected fast-recovery state, got %s", c.State())
	}
	// Drive cwnd to floor by simulating the broken flow that would
	// collapse under repeated OnLoss before the idempotence fix.
	c.cwnd = float64(minCWND) // force-floor for the test

	// ResetCWND should restore to initial and exit fastRecovery.
	c.ResetCWND()
	if c.CWND() != initialCWND {
		t.Errorf("expected cwnd=%d after ResetCWND, got %d", initialCWND, c.CWND())
	}
	if c.State() != "slow-start" {
		t.Errorf("expected slow-start after ResetCWND, got %s", c.State())
	}
}

// TestCUBICPRRDoesntStarveDuringRecovery — during recovery with PRR,
// ACKs grow effective cwnd proportionally so we don't deadlock at
// pipe == cwnd.
func TestCUBICPRRDoesntStarveDuringRecovery(t *testing.T) {
	c := NewCUBICController()
	// Drive up cwnd via slow-start.
	for i := 0; i < 100; i++ {
		c.OnAck(1400, 20*time.Millisecond)
	}
	preCwnd := c.cwnd
	pipeAtLoss := int64(preCwnd) // pipe == cwnd at loss
	c.OnLossWithPipe(pipeAtLoss)

	// Simulate ACKs arriving during recovery, draining inFlight.
	pipe := pipeAtLoss
	cwndCurve := []int64{c.CWND()}
	for i := 0; i < 10; i++ {
		c.OnSend(1400) // send replenishes prr_out
		c.OnAckWithPipe(1400, 20*time.Millisecond, pipe)
		pipe -= 1400
		if pipe < 0 {
			pipe = 0
		}
		cwndCurve = append(cwndCurve, c.CWND())
	}

	// PRR should NOT have driven cwnd to the floor.
	for i, w := range cwndCurve {
		if w == minCWND {
			t.Errorf("PRR collapsed cwnd to floor at step %d: %v", i, cwndCurve)
		}
	}
}

// TestCUBICOnSendTracksPRROut — prr_out grows during recovery only.
func TestCUBICOnSendTracksPRROut(t *testing.T) {
	c := NewCUBICController()

	// Outside recovery: prrOut shouldn't change.
	c.OnSend(1400)
	if c.prrOut != 0 {
		t.Errorf("prrOut grew outside recovery: %d", c.prrOut)
	}

	// Enter recovery.
	c.OnLossWithPipe(int64(c.cwnd))

	// Inside recovery: prrOut accumulates.
	c.OnSend(1400)
	c.OnSend(1400)
	if c.prrOut != 2800 {
		t.Errorf("expected prrOut=2800, got %d", c.prrOut)
	}
}

// TestBBRImplementsExtendedInterface — BBR must satisfy the Controller
// interface including the new PRR-shaped methods (which it forwards
// to its native handlers).
func TestBBRImplementsExtendedInterface(t *testing.T) {
	var _ Controller = (*BBRController)(nil)
	var _ Controller = (*CUBICController)(nil)
}
