//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

package adapter

import (
	"testing"
	"time"
)

// TestAEL02_PruneClearsActiveGroupState guards AE-L-02: when the age-prune
// loop in FragmentBuffer.Add deletes the group that is currently being
// assembled (ss.current) on the SAME stream, it must also clear
// hasCurr/current. Otherwise a delayed index>0 fragment passes the
// !hasCurr drop guard, takes the ss.current branch, finds no group, and
// instantiates a corrupt never-completing group under the stale key.
//
// The empty-stream drop only fires for OTHER streams (sid != streamID), so
// a same-stream reproduction is required to surface the stale-flag bug.
func TestAEL02_PruneClearsActiveGroupState(t *testing.T) {
	ael02Frag := func(index, total uint8, p []byte) []byte {
		b := make([]byte, fragHeaderSize+len(p))
		b[0], b[1], b[2], b[3] = fragMagic0, fragMagic1, index, total
		copy(b[fragHeaderSize:], p)
		return b
	}

	fb := NewFragmentBuffer()
	fb.SetGroupMaxAge(1 * time.Millisecond) // ageCap = min(timeout 10s, 1ms) = 1ms

	// Seed a 3-fragment group (index=0) on stream 1 -> sets current/hasCurr.
	if _, err := fb.Add(1, 100, ael02Frag(0, 3, []byte("aaa"))); err != nil {
		t.Fatalf("seed index=0: %v", err)
	}
	time.Sleep(5 * time.Millisecond) // age past groupMaxAge

	// Delayed index=2 on the SAME stream. Add() first prunes the aged active
	// group; with AE-L-02 fixed, hasCurr/current are cleared so this orphaned
	// non-zero fragment is dropped instead of seeding a corrupt group.
	_, err := fb.Add(1, 0, ael02Frag(2, 3, []byte("ccc")))
	if err == nil {
		t.Fatalf("expected orphaned index=2 to be dropped after active-group prune; got nil (stale hasCurr misdirected it into a corrupt group)")
	}
	if p := fb.Pending(); p != 0 {
		t.Fatalf("expected 0 pending groups, got %d (corrupt never-completing group leaked)", p)
	}
}
