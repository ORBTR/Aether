/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package congestion

import (
	"testing"
	"time"
)

func TestCUBIC_InitialState(t *testing.T) {
	c := NewCUBICController()

	if c.CWND() != initialCWND {
		t.Errorf("initial CWND: got %d, want %d", c.CWND(), initialCWND)
	}
	if c.State() != "slow-start" {
		t.Errorf("initial state: got %s, want slow-start", c.State())
	}
	if !c.CanSend(0) {
		t.Error("should be able to send with 0 in-flight")
	}
}

func TestCUBIC_SlowStart(t *testing.T) {
	c := NewCUBICController()
	initial := c.CWND()

	// ACK 1400 bytes — cwnd should grow
	c.OnAck(1400, 50*time.Millisecond)
	if c.CWND() <= initial {
		t.Errorf("cwnd should grow in slow start: got %d, was %d", c.CWND(), initial)
	}

	// Multiple ACKs — exponential growth
	for i := 0; i < 10; i++ {
		c.OnAck(1400, 50*time.Millisecond)
	}
	if c.CWND() <= initial+1400 {
		t.Errorf("cwnd should grow exponentially: got %d", c.CWND())
	}
}

func TestCUBIC_OnLoss(t *testing.T) {
	c := NewCUBICController()

	// Grow cwnd
	for i := 0; i < 20; i++ {
		c.OnAck(1400, 50*time.Millisecond)
	}
	beforeLoss := c.CWND()

	c.OnLoss()
	afterLoss := c.CWND()

	if afterLoss >= beforeLoss {
		t.Errorf("cwnd should decrease on loss: before=%d, after=%d", beforeLoss, afterLoss)
	}

	// Should be approximately beta * beforeLoss (0.7)
	expected := int64(float64(beforeLoss) * cubicBeta)
	tolerance := int64(1400) // 1 segment tolerance
	if afterLoss < expected-tolerance || afterLoss > expected+tolerance {
		t.Errorf("cwnd after loss: got %d, want ~%d (0.7 * %d)", afterLoss, expected, beforeLoss)
	}

	if c.State() != "fast-recovery" {
		t.Errorf("state after loss: got %s, want fast-recovery", c.State())
	}
}

func TestCUBIC_CanSend(t *testing.T) {
	c := NewCUBICController()
	cwnd := c.CWND()

	if !c.CanSend(0) {
		t.Error("should send with 0 in-flight")
	}
	if !c.CanSend(cwnd - 1) {
		t.Error("should send with in-flight < cwnd")
	}
	if c.CanSend(cwnd) {
		t.Error("should not send with in-flight = cwnd")
	}
	if c.CanSend(cwnd + 1000) {
		t.Error("should not send with in-flight > cwnd")
	}
}

func TestCUBIC_MinCWND(t *testing.T) {
	c := NewCUBICController()

	// Repeated losses — cwnd should not go below minCWND
	for i := 0; i < 20; i++ {
		c.OnLoss()
	}

	if c.CWND() < minCWND {
		t.Errorf("cwnd should not go below minCWND: got %d, min %d", c.CWND(), minCWND)
	}
}

func TestCUBIC_Recovery(t *testing.T) {
	c := NewCUBICController()

	// Grow
	for i := 0; i < 50; i++ {
		c.OnAck(1400, 50*time.Millisecond)
	}

	// Loss
	c.OnLoss()
	afterLoss := c.CWND()

	// Recovery — ACKs should grow cwnd again
	for i := 0; i < 50; i++ {
		c.OnAck(1400, 50*time.Millisecond)
	}

	if c.CWND() <= afterLoss {
		t.Errorf("cwnd should recover after loss: got %d, was %d", c.CWND(), afterLoss)
	}
}

func TestCUBIC_PacingRate(t *testing.T) {
	c := NewCUBICController()
	if c.PacingRate() != 0 {
		t.Errorf("CUBIC should not pace: got %f", c.PacingRate())
	}
}
