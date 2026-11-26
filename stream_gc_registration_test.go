/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package aether

import (
	"testing"
	"time"
)

// An ID registered again replaces the earlier registration's entry, and the earlier
// registration's release leaves the later one tracked; only the later one's own release,
// or a release by ID, takes the ID out.
func TestAStreamGCReleasesOnlyTheRegistrationItIsGiven(t *testing.T) {
	g := NewSessionStreamGCByRegistration(DefaultSessionOptions(), nil)
	g.RegisterAs(100, 1)
	g.RegisterAs(100, 2)
	g.UnregisterRegistration(100, 1)
	if got := g.TrackedCount(); got != 1 {
		t.Fatalf("after the earlier registration's release the GC tracks %d, want 1 (the later one)", got)
	}
	g.RecordActivity(100)
	g.UnregisterRegistration(100, 2)
	if got := g.TrackedCount(); got != 0 {
		t.Fatalf("after the later registration's release the GC tracks %d, want 0", got)
	}

	g.RegisterAs(101, 3)
	g.Unregister(101)
	g.RecordActivity(101) // an ID's activity with no stream: tracked under no registration
	g.UnregisterRegistration(101, 3)
	if got := g.TrackedCount(); got != 1 {
		t.Fatalf("a released registration's later release took out the ID's untracked activity: %d tracked, want 1", got)
	}
	g.UnregisterRegistration(101, 0)
	if got := g.TrackedCount(); got != 0 {
		t.Fatalf("the activity entry's release left %d tracked, want 0", got)
	}
}

// The sweep hands each idle ID's registration to the session's reset, zero for an ID
// tracked without one, and has let the entry go by then.
func TestAStreamGCSweepHandsTheIdleRegistrationToTheReset(t *testing.T) {
	got := map[uint64]uint64{}
	var g *StreamGC
	g = NewSessionStreamGCByRegistration(DefaultSessionOptions(), func(id, reg uint64) {
		got[id] = reg
		g.mu.Lock()
		_, still := g.lastActivity[id]
		g.mu.Unlock()
		if still {
			t.Errorf("stream %d still tracked when its reset ran", id)
		}
	})
	g.RegisterAs(100, 7)
	g.Register(101)
	g.RecordActivity(102)
	g.mu.Lock()
	for id := range g.lastActivity {
		g.lastActivity[id] = time.Now().Add(-time.Hour)
	}
	g.mu.Unlock()
	g.sweep()
	want := map[uint64]uint64{100: 7, 101: 0, 102: 0}
	if len(got) != len(want) {
		t.Fatalf("the sweep reset %v, want %v", got, want)
	}
	for id, reg := range want {
		if r, ok := got[id]; !ok || r != reg {
			t.Fatalf("the sweep reset %v, want %v", got, want)
		}
	}
	if n := g.TrackedCount(); n != 0 {
		t.Fatalf("the sweep left %d tracked", n)
	}
}
