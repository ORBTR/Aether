/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package aether

import (
	"sort"
	"sync"
	"testing"
	"time"
)

// TestASessionLifetimeStreamIsNeverReclaimedAsIdle: a session's GC built from options
// naming session-lifetime IDs leaves those streams open however long they idle, and
// still resets every other idle stream at or above StreamGCExemptBelow, a per-call
// stream among them.
func TestASessionLifetimeStreamIsNeverReclaimedAsIdle(t *testing.T) {
	var mu sync.Mutex
	var reset []uint64
	opts := DefaultSessionOptions()
	opts.StreamIdleTimeout = 50 * time.Millisecond
	opts.SessionLifetimeStreams = []uint64{700, 701, 702}
	g := NewSessionStreamGC(opts, func(id uint64) {
		mu.Lock()
		reset = append(reset, id)
		mu.Unlock()
	})

	lifetime := []uint64{700, 701, 702}
	reclaimed := []uint64{15, 99, 703}
	for _, id := range append(append([]uint64{}, lifetime...), reclaimed...) {
		g.Register(id)
	}
	g.mu.Lock()
	for id := range g.lastActivity {
		g.lastActivity[id] = time.Now().Add(-time.Hour)
	}
	g.mu.Unlock()
	g.sweep()

	mu.Lock()
	got := append([]uint64(nil), reset...)
	mu.Unlock()
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	if len(got) != len(reclaimed) {
		t.Fatalf("reset %v after an hour idle, want exactly %v: a session-lifetime stream was reclaimed or a per-call one kept", got, reclaimed)
	}
	for i := range reclaimed {
		if got[i] != reclaimed[i] {
			t.Fatalf("reset %v after an hour idle, want exactly %v", got, reclaimed)
		}
	}
	if n := g.TrackedCount(); n != len(lifetime) {
		t.Errorf("%d stream(s) still tracked, want the %d session-lifetime ones", n, len(lifetime))
	}
}

// TestAStreamGCSweepsWithinItsIdleTimeout: Start sweeps at half the idle timeout, so a
// session given a short StreamIdleTimeout resets an idle stream within one and a half
// times it rather than at the next 30 s tick.
func TestAStreamGCSweepsWithinItsIdleTimeout(t *testing.T) {
	opts := DefaultSessionOptions()
	opts.StreamIdleTimeout = 200 * time.Millisecond
	done := make(chan time.Time, 1)
	g := NewSessionStreamGC(opts, func(uint64) {
		select {
		case done <- time.Now():
		default:
		}
	})
	start := time.Now()
	g.Register(42)
	go g.Start()
	defer g.Stop()
	select {
	case at := <-done:
		// The timers and the scheduler sit on top of the 300 ms bound.
		if took := at.Sub(start); took > 300*time.Millisecond+500*time.Millisecond {
			t.Errorf("an idle stream was reset %s after its last frame, want within 1.5 x %s", took, opts.StreamIdleTimeout)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("an idle stream was not reset within 10 s at StreamIdleTimeout %s", opts.StreamIdleTimeout)
	}
}

// TestAZeroStreamIdleTimeoutIsTheDefault: options naming no idle timeout keep the 5 min
// default and its 30 s sweep.
func TestAZeroStreamIdleTimeoutIsTheDefault(t *testing.T) {
	g := NewSessionStreamGC(DefaultSessionOptions(), nil)
	if g.idleTimeout != DefaultStreamIdleTimeout {
		t.Errorf("idle timeout %s, want DefaultStreamIdleTimeout %s", g.idleTimeout, DefaultStreamIdleTimeout)
	}
	if every := g.sweepInterval(); every != streamGCSweepCeiling {
		t.Errorf("sweep every %s, want %s", every, streamGCSweepCeiling)
	}
}
