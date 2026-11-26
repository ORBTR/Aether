/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package multipath

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// seededSession is a fake session whose estimator has measured rtt eight times, so its
// keepalive plan is past the warmup floor and follows the path.
func seededSession(remote string, rtt time.Duration) *fakeSession {
	f := newFakeSession(aether.ProtoNoise, 0, 0)
	f.remoteID = aether.NodeID(remote)
	for seq := uint32(1); seq <= 8; seq++ {
		f.hm.RecordPingSent(seq)
		f.hm.RecordPongRecv(seq, time.Now().Add(-rtt))
	}
	return f
}

// countingSession counts the probes it answers.
type countingSession struct {
	*fakeSession
	pings atomic.Int64
}

func (c *countingSession) Ping(context.Context) (time.Duration, error) {
	c.pings.Add(1)
	return time.Millisecond, nil
}

// TestADeadPathIsReconsideredAfterOneProbeCycleOfItsOwnPlan: a path marked dead becomes a
// standby candidate again once the Interval its own keepalive plan derives has passed,
// and not before.
func TestADeadPathIsReconsideredAfterOneProbeCycleOfItsOwnPlan(t *testing.T) {
	slow := seededSession("slow", 4*time.Second)
	cycle := aether.KeepalivePlanFor(slow).Interval
	if cycle <= 5*time.Second || cycle >= 30*time.Second {
		t.Fatalf("premise wrong: the slow path's plan Interval is %v", cycle)
	}

	m := NewManager()
	m.AddPath(newFakeSession(aether.ProtoNoise, 0, 0), aether.ProtoNoise, 100)
	m.AddPath(slow, aether.ProtoNoise, 50)
	dead := m.paths[1]

	for _, c := range []struct {
		since time.Duration
		want  PathState
	}{
		{cycle - time.Second, PathDead},
		{cycle + time.Second, PathStandby},
	} {
		m.mu.Lock()
		dead.State = PathDead
		dead.LastFailure = time.Now().Add(-c.since)
		m.resurrectExpiredDeadPathsLocked()
		got := dead.State
		m.mu.Unlock()
		if got != c.want {
			t.Fatalf("a path dead for %v with a plan Interval of %v is %s, want %s", c.since, cycle, got, c.want)
		}
	}
}

// TestRunProbeLoop_ProbesAtThePathsOwnInterval: with no interval set, the probe cycle is
// the shortest Interval among the paths' own keepalive plans, so a fast standby path is
// probed once per its plan's Interval beside a slow primary whose plan's is longer.
func TestRunProbeLoop_ProbesAtThePathsOwnInterval(t *testing.T) {
	primary := seededSession("primary", 4*time.Second)
	standby := &countingSession{fakeSession: seededSession("standby", 2*time.Millisecond)}
	cycle := aether.KeepalivePlanFor(standby).Interval
	if slow := aether.KeepalivePlanFor(primary).Interval; slow <= cycle+cycle/2 {
		t.Fatalf("premise wrong: the primary's plan Interval %v is not past %v", slow, cycle+cycle/2)
	}

	m := NewManager()
	m.AddPath(primary, aether.ProtoNoise, 100)
	m.AddPath(standby, aether.ProtoNoise, 50)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.RunProbeLoop(ctx)
	}()
	time.Sleep(cycle + cycle/2)
	cancel()
	<-done

	if got := standby.pings.Load(); got != 1 {
		t.Fatalf("%d probes of the standby path in %v, want 1 at its plan's Interval of %v", got, cycle+cycle/2, cycle)
	}
}

// TestSetProbeInterval_SetsTheCycleAndTheDeadPathsWait: an interval a caller sets is the
// probe cycle, and a dead path is reconsidered after one such cycle.
func TestSetProbeInterval_SetsTheCycleAndTheDeadPathsWait(t *testing.T) {
	standby := &countingSession{fakeSession: seededSession("standby", 4*time.Second)}
	m := NewManager()
	m.SetProbeInterval(50 * time.Millisecond)
	m.AddPath(newFakeSession(aether.ProtoNoise, 0, 0), aether.ProtoNoise, 100)
	m.AddPath(standby, aether.ProtoNoise, 50)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.RunProbeLoop(ctx)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for standby.pings.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if got := standby.pings.Load(); got < 3 {
		t.Fatalf("%d probes in 5 s at a 50ms interval", got)
	}

	m.mu.Lock()
	dead := m.paths[1]
	dead.State = PathDead
	dead.LastFailure = time.Now().Add(-100 * time.Millisecond)
	m.resurrectExpiredDeadPathsLocked()
	got := dead.State
	m.mu.Unlock()
	if got != PathStandby {
		t.Fatalf("a path dead for 100ms at a 50ms interval is %s, want %s", got, PathStandby)
	}
}

// TestSetProbeInterval_TakesEffectFromTheNextRound: the loop reads the cycle before every
// round, so an interval set while it runs holds from the round after the one waiting.
func TestSetProbeInterval_TakesEffectFromTheNextRound(t *testing.T) {
	standby := &countingSession{fakeSession: seededSession("standby", 2*time.Millisecond)}
	cycle := aether.KeepalivePlanFor(standby).Interval
	m := NewManager()
	m.AddPath(newFakeSession(aether.ProtoNoise, 0, 0), aether.ProtoNoise, 100)
	m.AddPath(standby, aether.ProtoNoise, 50)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.RunProbeLoop(ctx)
	}()
	// Let the loop start its first wait on the derived cycle before the interval is set.
	time.Sleep(500 * time.Millisecond)
	m.SetProbeInterval(50 * time.Millisecond)
	deadline := time.Now().Add(cycle + 5*time.Second)
	for standby.pings.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if got := standby.pings.Load(); got < 3 {
		t.Fatalf("%d probes in %v after setting a 50ms interval on a loop waiting out %v", got, cycle+5*time.Second, cycle)
	}
}
