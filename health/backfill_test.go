/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 *
 * Regression coverage for health.Monitor: constructor alpha selection,
 * ping/pong seq correlation, RTT/RTO delegation to rtt.Estimator, and
 * the activity/missed-ping/closed state machine.
 */
package health

import (
	"testing"
	"time"

	"github.com/ORBTR/aether/rtt"
)

// doPingPong runs one correlated ping/pong cycle so the estimator
// consumes a sample of approximately `approx`. sentAt is placed `approx`
// in the past, so the RTT the Monitor computes is `approx` plus the
// (microsecond-scale) time to reach RecordPongRecv. Callers that assert
// on absolute RTT use generous bounds; callers that assert on relations
// between derived values (SRTT==lastRTT, RTTVar==lastRTT/2) are exact
// because those come from the same internal sample.
func doPingPong(m *Monitor, seq uint32, approx time.Duration) {
	m.RecordPingSent(seq)
	m.RecordPongRecv(seq, time.Now().Add(-approx))
}

// TestNewMonitorInitialState pins the freshly-constructed state that
// every downstream accessor and the keepalive subsystem depend on.
func TestNewMonitorInitialState(t *testing.T) {
	m := NewMonitor(0)

	if got := m.MissedPings(); got != 0 {
		t.Errorf("MissedPings: got %d want 0", got)
	}
	if m.IsClosed() {
		t.Error("IsClosed true on fresh monitor")
	}
	if got := m.SampleCount(); got != 0 {
		t.Errorf("SampleCount: got %d want 0", got)
	}
	if last, avg := m.RTT(); last != 0 || avg != 0 {
		t.Errorf("RTT pre-sample: got (%v,%v) want (0,0)", last, avg)
	}
	if got := m.SRTT(); got != 0 {
		t.Errorf("SRTT pre-sample: got %v want 0", got)
	}
	if got := m.AvgRTT(); got != 0 {
		t.Errorf("AvgRTT pre-sample: got %v want 0", got)
	}
	if got := m.RTTVar(); got != 0 {
		t.Errorf("RTTVar pre-sample: got %v want 0", got)
	}
	// Estimator built with a zero InitialRTO falls back to the rtt
	// package default of 1s before any sample is recorded.
	if got := m.RTO(); got != time.Second {
		t.Errorf("RTO pre-sample: got %v want 1s (InitialRTO default)", got)
	}
	// lastPingSent is never touched by the constructor.
	if ps := m.PingSentAt(); !ps.IsZero() {
		t.Errorf("PingSentAt pre-ping: got %v want zero time", ps)
	}
	// lastActivity/lastPongRecv are seeded to construction time.
	if la := m.LastActivity(); la.IsZero() {
		t.Error("LastActivity zero on fresh monitor")
	}
	if lp := m.LastPongReceived(); lp.IsZero() {
		t.Error("LastPongReceived zero on fresh monitor")
	}
	if !m.IsAlive(time.Hour) {
		t.Error("fresh monitor not alive within 1h")
	}
}

// TestNewMonitorAlphaSelection verifies the constructor's alpha gate:
// a valid alpha in (0,1] is forwarded to the estimator, while 0 or an
// out-of-range value falls back to the RFC 6298 default (smoothing).
// Detection: with alpha==1 the SRTT tracks the latest sample exactly
// (SRTT==lastRTT); with any smoothing alpha the SRTT lags a large
// downward step, so SRTT>lastRTT.
func TestNewMonitorAlphaSelection(t *testing.T) {
	tests := []struct {
		name     string
		alpha    float64
		smoothed bool // true => expect SRTT != lastRTT after the step
	}{
		{"alpha_one_no_smoothing", 1.0, false},
		{"alpha_zero_defaults", 0, true},
		{"alpha_default_rfc", 0.125, true},
		{"alpha_above_range_defaults", 2.0, true},
		{"alpha_negative_defaults", -0.5, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := NewMonitor(tc.alpha)
			// First sample ~100ms establishes SRTT, then a large
			// downward step to ~20ms.
			doPingPong(m, 1, 100*time.Millisecond)
			doPingPong(m, 2, 20*time.Millisecond)

			last, avg := m.RTT()
			if tc.smoothed {
				// Smoothing keeps SRTT well above the fresh 20ms
				// sample. Require a comfortable margin so scheduler
				// jitter on the tiny sample can never flip the sign.
				if avg <= last+10*time.Millisecond {
					t.Errorf("expected smoothing: SRTT=%v should exceed lastRTT=%v by a margin", avg, last)
				}
			} else {
				// alpha==1: SRTT is exactly the latest sample.
				if avg != last {
					t.Errorf("alpha=1 should track latest: SRTT=%v lastRTT=%v", avg, last)
				}
			}
		})
	}
}

// TestRecordActivityUpdatesTimestamp confirms RecordActivity stamps a
// fresh now-ish time (>= the reference captured just before the call),
// distinguishing it from the older construction timestamp.
func TestRecordActivityUpdatesTimestamp(t *testing.T) {
	m := NewMonitor(0)
	before := time.Now()
	m.RecordActivity()
	la := m.LastActivity()
	if la.Before(before) {
		t.Errorf("LastActivity %v predates RecordActivity call time %v", la, before)
	}
	if la.After(time.Now()) {
		t.Errorf("LastActivity %v is in the future", la)
	}
}

// TestIsAliveBoundaries covers the timeout comparison at its edges.
func TestIsAliveBoundaries(t *testing.T) {
	m := NewMonitor(0)
	if m.IsAlive(0) {
		t.Error("IsAlive(0) should be false: elapsed is never < 0")
	}
	if m.IsAlive(-time.Second) {
		t.Error("IsAlive(negative) should be false")
	}
	if !m.IsAlive(time.Hour) {
		t.Error("IsAlive(1h) should be true immediately after construction")
	}
}

// TestRecordPingSentTimestamp checks the ping timestamp accessor moves
// from zero to a fresh time on RecordPingSent.
func TestRecordPingSentTimestamp(t *testing.T) {
	m := NewMonitor(0)
	if !m.PingSentAt().IsZero() {
		t.Fatal("PingSentAt not zero before any ping")
	}
	before := time.Now()
	m.RecordPingSent(7)
	ps := m.PingSentAt()
	if ps.Before(before) || ps.After(time.Now()) {
		t.Errorf("PingSentAt %v not within [%v, now]", ps, before)
	}
}

// TestRecordPongRecvCorrelated exercises the happy path: a pong whose
// seq matches the pending ping consumes exactly one sample, resets the
// missed-ping counter, advances lastPongRecv, and populates the RTT
// derivations consistently (first-sample RFC 6298: SRTT==R, RTTVar==R/2).
func TestRecordPongRecvCorrelated(t *testing.T) {
	m := NewMonitor(0)
	// Pre-load a missed-ping count that the correlated pong must clear.
	m.IncrementMissedPings()
	m.IncrementMissedPings()

	before := time.Now()
	doPingPong(m, 42, 50*time.Millisecond)

	if got := m.SampleCount(); got != 1 {
		t.Errorf("SampleCount after one pong: got %d want 1", got)
	}
	if got := m.MissedPings(); got != 0 {
		t.Errorf("MissedPings not reset by correlated pong: got %d", got)
	}
	last, avg := m.RTT()
	if last < 50*time.Millisecond {
		t.Errorf("lastRTT %v below the 50ms floor of the sample", last)
	}
	if last > 5*time.Second {
		t.Errorf("lastRTT %v implausibly large", last)
	}
	// First sample: SRTT == R and RTTVar == R/2, both derived from the
	// same internal sample, so these relations are exact.
	if avg != last {
		t.Errorf("first-sample SRTT should equal lastRTT: SRTT=%v last=%v", avg, last)
	}
	if got, want := m.RTTVar(), last/2; got != want {
		t.Errorf("first-sample RTTVar: got %v want lastRTT/2=%v", got, want)
	}
	if lpr := m.LastPongReceived(); lpr.Before(before) {
		t.Errorf("LastPongReceived %v not advanced past %v", lpr, before)
	}
	// RTO is now sample-driven and must sit inside the estimator's bounds.
	if r := m.RTO(); r < rtt.DefaultMinRTO || r > rtt.DefaultMaxRTO {
		t.Errorf("post-sample RTO %v outside [%v,%v]", r, rtt.DefaultMinRTO, rtt.DefaultMaxRTO)
	}
}

// TestRecordPongRecvSeqGating locks down every branch of the seq
// correlation guard: a stray/zero/duplicate pong must be a no-op that
// neither consumes a sample nor disturbs the pending-ping bookkeeping
// or lastPongRecv.
func TestRecordPongRecvSeqGating(t *testing.T) {
	t.Run("zero_seq_ignored_and_pending_preserved", func(t *testing.T) {
		m := NewMonitor(0)
		m.RecordPingSent(7)
		lpBefore := m.LastPongReceived()

		// seq==0 fails the `seq != 0` gate even if it were pending.
		m.RecordPongRecv(0, time.Now().Add(-30*time.Millisecond))
		if got := m.SampleCount(); got != 0 {
			t.Fatalf("zero-seq pong consumed a sample: SampleCount=%d", got)
		}
		if !m.LastPongReceived().Equal(lpBefore) {
			t.Error("zero-seq pong advanced LastPongReceived")
		}
		// The real pong for the still-pending seq must now correlate,
		// proving the zero-seq pong did not clear pendingPingSeq.
		m.RecordPongRecv(7, time.Now().Add(-30*time.Millisecond))
		if got := m.SampleCount(); got != 1 {
			t.Errorf("pending seq lost after zero-seq pong: SampleCount=%d want 1", got)
		}
	})

	t.Run("wrong_seq_ignored", func(t *testing.T) {
		m := NewMonitor(0)
		m.RecordPingSent(7)
		lpBefore := m.LastPongReceived()
		m.RecordPongRecv(99, time.Now().Add(-30*time.Millisecond))
		if got := m.SampleCount(); got != 0 {
			t.Errorf("mismatched-seq pong consumed a sample: SampleCount=%d", got)
		}
		if !m.LastPongReceived().Equal(lpBefore) {
			t.Error("mismatched-seq pong advanced LastPongReceived")
		}
	})

	t.Run("duplicate_after_consume_ignored", func(t *testing.T) {
		m := NewMonitor(0)
		doPingPong(m, 7, 30*time.Millisecond) // consumes; pending -> 0
		lpAfterFirst := m.LastPongReceived()
		// Replaying the same seq now hits pending==0 and is ignored.
		m.RecordPongRecv(7, time.Now().Add(-30*time.Millisecond))
		if got := m.SampleCount(); got != 1 {
			t.Errorf("duplicate pong consumed a second sample: SampleCount=%d want 1", got)
		}
		if !m.LastPongReceived().Equal(lpAfterFirst) {
			t.Error("duplicate pong advanced LastPongReceived")
		}
	})
}

// TestIncrementMissedPings verifies the counter increments monotonically,
// returns the new value each call, and is observable via MissedPings.
func TestIncrementMissedPings(t *testing.T) {
	m := NewMonitor(0)
	for want := 1; want <= 3; want++ {
		if got := m.IncrementMissedPings(); got != want {
			t.Errorf("IncrementMissedPings call %d: got %d want %d", want, got, want)
		}
	}
	if got := m.MissedPings(); got != 3 {
		t.Errorf("MissedPings: got %d want 3", got)
	}
}

// TestMarkClosedIsIdempotent checks the atomic closed flag transitions
// once and stays set.
func TestMarkClosedIsIdempotent(t *testing.T) {
	m := NewMonitor(0)
	if m.IsClosed() {
		t.Fatal("IsClosed true before MarkClosed")
	}
	m.MarkClosed()
	if !m.IsClosed() {
		t.Fatal("IsClosed false after MarkClosed")
	}
	m.MarkClosed() // second call must not flip it back
	if !m.IsClosed() {
		t.Error("IsClosed false after second MarkClosed")
	}
}

// TestAvgRTTEqualsSRTT guards the documented equivalence of the two
// backwards-compatible accessor names across the sample stream.
func TestAvgRTTEqualsSRTT(t *testing.T) {
	m := NewMonitor(0)
	if m.AvgRTT() != m.SRTT() {
		t.Errorf("AvgRTT/SRTT diverge pre-sample: %v vs %v", m.AvgRTT(), m.SRTT())
	}
	for seq := uint32(1); seq <= 5; seq++ {
		doPingPong(m, seq, time.Duration(seq)*20*time.Millisecond)
		if a, s := m.AvgRTT(), m.SRTT(); a != s {
			t.Errorf("AvgRTT %v != SRTT %v after sample %d", a, s, seq)
		}
	}
	if got := m.SampleCount(); got != 5 {
		t.Errorf("SampleCount: got %d want 5", got)
	}
}
