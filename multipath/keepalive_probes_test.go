/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package multipath

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// TestAManagerTakingKeepaliveProbesPingsNoPath: once a caller's keepalive supplies the
// probes, no probe round pings a path, the primary's every fourth round included, and the
// rounds still return a dead path whose wait has passed to standby.
func TestAManagerTakingKeepaliveProbesPingsNoPath(t *testing.T) {
	primary := &countingSession{fakeSession: seededSession("primary", 2*time.Millisecond)}
	standby := &countingSession{fakeSession: seededSession("standby", 2*time.Millisecond)}
	dead := &countingSession{fakeSession: seededSession("dead", 2*time.Millisecond)}
	m := NewManager()
	m.TakeProbesFromKeepalive()
	m.AddPath(primary, aether.ProtoNoise, 100)
	m.AddPath(standby, aether.ProtoNoise, 50)
	m.AddPath(dead, aether.ProtoNoise, 50)
	m.mu.Lock()
	m.paths[2].State = PathDead
	m.paths[2].LastFailure = time.Now().Add(-time.Minute)
	m.mu.Unlock()

	for round := uint64(0); round < 2*primaryProbeEvery; round++ {
		m.probeNonPrimary(context.Background())
	}
	for name, s := range map[string]*countingSession{"primary": primary, "standby": standby, "dead": dead} {
		if got := s.pings.Load(); got != 0 {
			t.Errorf("%d probe rounds pinged the %s path %d times, want none", 2*primaryProbeEvery, name, got)
		}
	}
	m.mu.Lock()
	got := m.paths[2].State
	m.mu.Unlock()
	if got != PathStandby {
		t.Errorf("a path dead for a minute is %s after the probe rounds, want %s", got, PathStandby)
	}
}

// TestRecordKeepaliveProbeTakesTheResultAProbeRoundWould: a keepalive's answer records the
// round trip and the success and returns a probing path to standby; a failed probe stamps
// the failure and leaves the state; a dead path waiting out its wait and a flapping path
// are left alone, as the probe round skips them; a session the manager does not hold
// changes nothing.
func TestRecordKeepaliveProbeTakesTheResultAProbeRoundWould(t *testing.T) {
	primary := seededSession("primary", 2*time.Millisecond)
	probing := seededSession("probing", 2*time.Millisecond)
	dead := seededSession("dead", 2*time.Millisecond)
	flapping := seededSession("flapping", 2*time.Millisecond)
	m := NewManager()
	m.TakeProbesFromKeepalive()
	m.AddPath(primary, aether.ProtoNoise, 100)
	m.AddPath(probing, aether.ProtoNoise, 50)
	m.AddPath(dead, aether.ProtoNoise, 50)
	m.AddPath(flapping, aether.ProtoNoise, 50)
	before := time.Now().Add(-time.Hour)
	m.mu.Lock()
	for _, p := range m.paths[1:] {
		p.LastSuccess, p.ConsecutiveFailures = before, 2
	}
	m.paths[1].State = PathProbing
	m.paths[2].State, m.paths[2].LastFailure = PathDead, time.Now()
	m.paths[3].State, m.paths[3].flappingUntil = PathFlapping, time.Now().Add(time.Minute)
	m.mu.Unlock()

	start := time.Now()
	m.RecordKeepaliveProbe(probing, 7*time.Millisecond, nil)
	m.RecordKeepaliveProbe(dead, 7*time.Millisecond, nil)
	m.RecordKeepaliveProbe(flapping, 7*time.Millisecond, nil)
	m.RecordKeepaliveProbe(seededSession("stranger", time.Millisecond), 7*time.Millisecond, nil)

	m.mu.Lock()
	p := *m.paths[1]
	d, f := *m.paths[2], *m.paths[3]
	m.mu.Unlock()
	if p.State != PathStandby || p.RTT != 7*time.Millisecond || p.LastSuccess.Before(start) || p.ConsecutiveFailures != 0 {
		t.Fatalf("an answered probe left the probing path at %s, RTT %v, last success %v, %d failures",
			p.State, p.RTT, p.LastSuccess, p.ConsecutiveFailures)
	}
	if d.State != PathDead || d.RTT != 0 || !d.LastSuccess.Equal(before) {
		t.Errorf("an answer on a dead path waiting out its wait moved it to %s, RTT %v", d.State, d.RTT)
	}
	if f.State != PathFlapping || f.RTT != 0 || !f.LastSuccess.Equal(before) {
		t.Errorf("an answer on a flapping path moved it to %s, RTT %v", f.State, f.RTT)
	}
	if n := m.PathCount(); n != 4 {
		t.Errorf("a stranger's probe changed the path count to %d", n)
	}

	failedAt := time.Now()
	m.RecordKeepaliveProbe(probing, 0, errors.New("no answer"))
	m.mu.Lock()
	p = *m.paths[1]
	m.mu.Unlock()
	if p.State != PathStandby || p.LastFailure.Before(failedAt) || p.LastProbe.Before(failedAt) || p.RTT != 7*time.Millisecond {
		t.Errorf("a failed probe left the path at %s, last failure %v, last probe %v, RTT %v; want the state and RTT kept and the failure stamped",
			p.State, p.LastFailure, p.LastProbe, p.RTT)
	}
}

// TestTheManagersPlanReadsAMeasuredStandby: a converged session the manager holds beside a
// converged path whose latest probe was answered gets the with-standby Strikes; the same
// session alone, beside a path whose latest probe failed, is dead, is closed or is still
// warming up, or not held by the manager, gets aether.KeepalivePlanFor's plan.
func TestTheManagersPlanReadsAMeasuredStandby(t *testing.T) {
	session := seededSession("session", 2*time.Millisecond)
	alone := aether.KeepalivePlanFor(session)
	if alone.Strikes != 5 {
		t.Fatalf("premise wrong: a clean converged session's plan has %d strikes", alone.Strikes)
	}
	const withStandby = 2

	single := NewManager()
	single.AddPath(session, aether.ProtoNoise, 100)
	if got := single.KeepalivePlanFor(session); got != alone {
		t.Errorf("a session that is the peer's only path gets %+v, want %+v", got, alone)
	}

	standby := seededSession("standby", 2*time.Millisecond)
	m := NewManager()
	m.AddPath(session, aether.ProtoNoise, 100)
	m.AddPath(standby, aether.ProtoNoise, 50)
	plan := m.KeepalivePlanFor(session)
	if plan.Strikes != withStandby {
		t.Fatalf("beside a measured standby the plan has %d strikes, want %d", plan.Strikes, withStandby)
	}
	if plan.Interval != alone.Interval || plan.ProbeTimeout != alone.ProbeTimeout || plan.RetryGap != alone.RetryGap {
		t.Errorf("the standby moved more than the strikes: %+v against %+v", plan, alone)
	}
	if got := m.KeepalivePlanFor(standby).Strikes; got != withStandby {
		t.Errorf("the standby path beside a measured primary has %d strikes, want %d", got, withStandby)
	}

	m.RecordKeepaliveProbe(standby, 0, errors.New("no answer"))
	if got := m.KeepalivePlanFor(session).Strikes; got != alone.Strikes {
		t.Errorf("beside a standby whose latest probe failed: %d strikes, want %d", got, alone.Strikes)
	}
	m.RecordKeepaliveProbe(standby, 2*time.Millisecond, nil)
	if got := m.KeepalivePlanFor(session).Strikes; got != withStandby {
		t.Errorf("beside a standby that answered again: %d strikes, want %d", got, withStandby)
	}

	m.mu.Lock()
	m.paths[1].State = PathDead
	m.mu.Unlock()
	if got := m.KeepalivePlanFor(session).Strikes; got != alone.Strikes {
		t.Errorf("beside a dead path: %d strikes, want %d", got, alone.Strikes)
	}
	m.mu.Lock()
	m.paths[1].State = PathStandby
	m.mu.Unlock()
	_ = standby.Close()
	if got := m.KeepalivePlanFor(session).Strikes; got != alone.Strikes {
		t.Errorf("beside a closed path: %d strikes, want %d", got, alone.Strikes)
	}

	warming := NewManager()
	warming.AddPath(session, aether.ProtoNoise, 100)
	warming.AddPath(newFakeSession(aether.ProtoNoise, 0, 0), aether.ProtoNoise, 50)
	if got := warming.KeepalivePlanFor(session).Strikes; got != alone.Strikes {
		t.Errorf("beside a path with nothing measured: %d strikes, want %d", got, alone.Strikes)
	}

	pair := NewManager()
	pair.AddPath(seededSession("pair-primary", 2*time.Millisecond), aether.ProtoNoise, 100)
	pair.AddPath(seededSession("pair-standby", 2*time.Millisecond), aether.ProtoNoise, 50)
	stranger := seededSession("stranger", 2*time.Millisecond)
	if got := pair.KeepalivePlanFor(stranger); got != aether.KeepalivePlanFor(stranger) {
		t.Errorf("a session the manager does not hold gets %+v, want %+v", got, aether.KeepalivePlanFor(stranger))
	}
}

// TestAFailedStandbyLeavesThePrimary: the failure of a standby path marks that path dead
// and leaves the primary carrying the traffic; the failure of the primary fails over to
// the standby, as OnPrimaryFailure does.
func TestAFailedStandbyLeavesThePrimary(t *testing.T) {
	primary := seededSession("primary", 2*time.Millisecond)
	standby := seededSession("standby", 2*time.Millisecond)
	m := NewManager()
	m.AddPath(primary, aether.ProtoNoise, 100)
	m.AddPath(standby, aether.ProtoNoise, 50)

	if m.OnPathFailure(standby) {
		t.Error("the failure of a standby path reported a failover")
	}
	if cur, ok := m.PrimarySession(); !ok || cur != aether.Session(primary) {
		t.Fatalf("after the standby failed the primary is %v, want the primary path", remoteOf(cur))
	}
	m.mu.Lock()
	ps, ss, lastFailure := m.paths[0].State, m.paths[1].State, m.paths[1].LastFailure
	m.mu.Unlock()
	if ps != PathActive || ss != PathDead || lastFailure.IsZero() {
		t.Fatalf("after the standby failed: primary %s, standby %s (failure stamped %v); want %s and %s",
			ps, ss, !lastFailure.IsZero(), PathActive, PathDead)
	}
	if m.OnPathFailure(seededSession("stranger", time.Millisecond)) {
		t.Error("the failure of a session the manager does not hold reported a failover")
	}

	failover := NewManager()
	failover.AddPath(primary, aether.ProtoNoise, 100)
	failover.AddPath(standby, aether.ProtoNoise, 50)
	if !failover.OnPathFailure(primary) {
		t.Error("the failure of the primary reported no failover")
	}
	if cur, ok := failover.PrimarySession(); !ok || cur != aether.Session(standby) {
		t.Fatalf("after the primary failed the primary is %v, want the standby", remoteOf(cur))
	}
}

// remoteOf names a session in a failure message by its remote node ID.
func remoteOf(s aether.Session) aether.NodeID {
	if s == nil {
		return ""
	}
	return s.RemoteNodeID()
}
