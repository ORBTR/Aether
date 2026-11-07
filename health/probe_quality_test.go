/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package health

import (
	"testing"
	"time"
)

// TestProbeLossFollowsTheKeepalivesAnswers: probe loss starts at zero, rises with each
// probe a later answer shows was lost, falls with each probe answered first time, and
// stays a fraction.
func TestProbeLossFollowsTheKeepalivesAnswers(t *testing.T) {
	m := NewMonitor(0)
	if got := m.ProbeLoss(); got != 0 {
		t.Fatalf("a new monitor's probe loss = %v, want 0", got)
	}
	m.RecordKeepaliveAnswer(0)
	if got := m.ProbeLoss(); got != 0 {
		t.Fatalf("after one probe answered first time, probe loss = %v, want 0", got)
	}
	m.RecordKeepaliveAnswer(3)
	lossy := m.ProbeLoss()
	if lossy <= 0.25 || lossy >= 1 {
		t.Fatalf("after three probes lost before an answer, probe loss = %v, want above 0.25 and below 1", lossy)
	}
	for range 5 {
		m.RecordKeepaliveAnswer(0)
	}
	if got := m.ProbeLoss(); got >= lossy || got <= 0 {
		t.Errorf("after five clean answers, probe loss = %v, want below %v and above 0", got, lossy)
	}
	for range 200 {
		m.RecordKeepaliveAnswer(4)
	}
	// Read just after an answer, the smoothed loss sits below the path's 0.8: the
	// answer is the latest of the five observations.
	if got := m.ProbeLoss(); got < 0.7 || got > 1 {
		t.Errorf("on a path losing four probes in five, probe loss = %v, want at least 0.7 and at most 1", got)
	}
}

// TestInstabilityFollowsTheRoundTrips: a path whose pong round trips hold steady reads
// as stable; one whose round trips jump between consecutive samples reads as unstable,
// and the reading stays a fraction.
func TestInstabilityFollowsTheRoundTrips(t *testing.T) {
	steady := NewMonitor(0)
	for i := range 20 {
		doPingPong(steady, uint32(i+1), 100*time.Millisecond)
	}
	if got := steady.Instability(); got > 0.05 {
		t.Errorf("a steady 100 ms path's instability = %v, want near 0", got)
	}

	jumpy := NewMonitor(0)
	for i := range 20 {
		rtt := 50 * time.Millisecond
		if i%2 == 1 {
			rtt = 250 * time.Millisecond
		}
		doPingPong(jumpy, uint32(i+1), rtt)
	}
	got := jumpy.Instability()
	if got < 0.3 || got > 1 {
		t.Errorf("a path alternating 50 ms and 250 ms reads instability %v, want at least 0.3 and at most 1", got)
	}
	if one := NewMonitor(0); func() float64 { doPingPong(one, 1, time.Second); return one.Instability() }() != 0 {
		t.Error("one sample read as unstable: instability needs two")
	}
}
