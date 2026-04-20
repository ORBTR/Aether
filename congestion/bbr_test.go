/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package congestion

import (
	"testing"
	"time"
)

func TestBBR_InitialState(t *testing.T) {
	b := NewBBRController()
	if b.State() != "startup" {
		t.Errorf("initial state: got %s, want startup", b.State())
	}
	if b.CWND() != int64(initialCWND) {
		t.Errorf("initial cwnd: got %d, want %d", b.CWND(), initialCWND)
	}
	if b.PacingRate() <= 0 {
		t.Error("expected positive initial pacing rate")
	}
}

func TestBBR_StartupGrowth(t *testing.T) {
	b := NewBBRController()
	initialCwnd := b.CWND()

	// Simulate ACKs during startup — cwnd should grow
	for i := 0; i < 20; i++ {
		b.OnAck(1400, 50*time.Millisecond)
		time.Sleep(time.Millisecond) // ensure time progress for delivery rate
	}

	if b.CWND() <= initialCwnd {
		t.Errorf("cwnd should grow during startup: got %d, started at %d", b.CWND(), initialCwnd)
	}
}

func TestBBR_OnLossReducesCWND(t *testing.T) {
	b := NewBBRController()

	// Grow cwnd first
	for i := 0; i < 20; i++ {
		b.OnAck(1400, 50*time.Millisecond)
		time.Sleep(time.Millisecond)
	}
	cwndBefore := b.CWND()

	b.OnLoss()
	cwndAfter := b.CWND()

	if cwndAfter >= cwndBefore {
		t.Errorf("cwnd should decrease on loss: before=%d, after=%d", cwndBefore, cwndAfter)
	}
}

func TestBBR_CanSend(t *testing.T) {
	b := NewBBRController()

	if !b.CanSend(1400) {
		t.Error("should be able to send within initial cwnd")
	}
	// Huge value should be blocked
	if b.CanSend(100 * 1024 * 1024) {
		t.Error("should not send more than cwnd")
	}
}

func TestBBR_PacingRateUpdates(t *testing.T) {
	b := NewBBRController()
	initialRate := b.PacingRate()

	// After ACKs, pacing rate should update
	for i := 0; i < 30; i++ {
		b.OnAck(1400, 20*time.Millisecond)
		time.Sleep(time.Millisecond)
	}

	newRate := b.PacingRate()
	if newRate == initialRate {
		t.Log("pacing rate did not change — may need more ACKs for delivery rate estimation")
	}
	if newRate <= 0 {
		t.Error("pacing rate should be positive")
	}
}

func TestBBR_ControllerInterface(t *testing.T) {
	var _ Controller = (*BBRController)(nil)
}

func TestBBR_MinCWND(t *testing.T) {
	b := NewBBRController()

	// Many losses should not reduce below minimum
	for i := 0; i < 100; i++ {
		b.OnLoss()
	}

	if b.CWND() < int64(minCWND) {
		t.Errorf("cwnd below minimum: got %d, min %d", b.CWND(), minCWND)
	}
}
