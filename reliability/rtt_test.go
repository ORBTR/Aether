/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package reliability

import (
	"testing"
	"time"
)

func TestRTTEstimator_FirstSample(t *testing.T) {
	e := NewRTTEstimator()
	if e.isInitialized() {
		t.Error("should not be initialized before first sample")
	}

	e.Update(100 * time.Millisecond)

	if !e.isInitialized() {
		t.Error("should be initialized after first sample")
	}
	// After first sample: SRTT = R, RTTVAR = R/2
	if e.SRTT() != 100*time.Millisecond {
		t.Errorf("SRTT: got %v, want 100ms", e.SRTT())
	}
	if e.rttVar() != 50*time.Millisecond {
		t.Errorf("RTTVar: got %v, want 50ms", e.rttVar())
	}
	// RTO = SRTT + max(G, 4*RTTVAR) = 100 + max(1, 200) = 300ms
	if e.RTO() != 300*time.Millisecond {
		t.Errorf("RTO: got %v, want 300ms", e.RTO())
	}
}

func TestRTTEstimator_ConvergesToStable(t *testing.T) {
	e := NewRTTEstimator()

	// Feed stable 50ms samples
	for i := 0; i < 20; i++ {
		e.Update(50 * time.Millisecond)
	}

	// SRTT should converge near 50ms
	srtt := e.SRTT()
	if srtt < 45*time.Millisecond || srtt > 55*time.Millisecond {
		t.Errorf("SRTT should converge near 50ms, got %v", srtt)
	}

	// RTTVAR should be small (stable RTT = low variance)
	rttvar := e.rttVar()
	if rttvar > 10*time.Millisecond {
		t.Errorf("rttVar should be small for stable RTT, got %v", rttvar)
	}
}

func TestRTTEstimator_MinRTO(t *testing.T) {
	e := NewRTTEstimator()

	// Very fast RTT — RTO should clamp to minRTO (200ms)
	for i := 0; i < 10; i++ {
		e.Update(1 * time.Millisecond)
	}

	if e.RTO() < 200*time.Millisecond {
		t.Errorf("RTO should not go below minRTO (200ms), got %v", e.RTO())
	}
}

func TestRTTEstimator_MaxRTO(t *testing.T) {
	e := NewRTTEstimator()
	e.Update(100 * time.Millisecond)

	// Backoff repeatedly
	for i := 0; i < 20; i++ {
		e.BackoffRTO()
	}

	if e.RTO() > 60*time.Second {
		t.Errorf("RTO should not exceed maxRTO (60s), got %v", e.RTO())
	}
	if e.RTO() != 60*time.Second {
		t.Errorf("RTO should be exactly maxRTO after many backoffs, got %v", e.RTO())
	}
}

func TestRTTEstimator_BackoffRTO(t *testing.T) {
	e := NewRTTEstimator()
	e.Update(100 * time.Millisecond) // RTO = 300ms

	rto1 := e.BackoffRTO()
	if rto1 != 600*time.Millisecond {
		t.Errorf("first backoff: got %v, want 600ms", rto1)
	}

	rto2 := e.BackoffRTO()
	if rto2 != 1200*time.Millisecond {
		t.Errorf("second backoff: got %v, want 1200ms", rto2)
	}
}

func TestRTTEstimator_JitterResponse(t *testing.T) {
	e := NewRTTEstimator()

	// Alternate between 30ms and 70ms — RTTVAR should grow
	for i := 0; i < 20; i++ {
		if i%2 == 0 {
			e.Update(30 * time.Millisecond)
		} else {
			e.Update(70 * time.Millisecond)
		}
	}

	// RTTVAR should be significant (high jitter)
	if e.rttVar() < 5*time.Millisecond {
		t.Errorf("rttVar should be significant with jitter, got %v", e.rttVar())
	}
}

func TestRTTEstimator_DefaultRTO(t *testing.T) {
	e := NewRTTEstimator()
	// Before any samples, RTO should be 1s (RFC 6298 initial)
	if e.RTO() != time.Second {
		t.Errorf("initial RTO: got %v, want 1s", e.RTO())
	}
}
