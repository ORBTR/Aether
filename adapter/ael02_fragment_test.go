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

// TestAEL02_PruneClearsActiveGroupState: when the age-prune
// loop in FragmentBuffer.Add deletes the group being assembled on the SAME
// stream, a delayed later fragment of that message must be refused instead of
// instantiating a corrupt never-completing group under the pruned message ID.
func TestAEL02_PruneClearsActiveGroupState(t *testing.T) {
	fb := NewFragmentBuffer()
	fb.SetGroupMaxAge(1 * time.Millisecond) // ageCap = min(timeout 10s, 1ms) = 1ms
	r := fxReceiver()

	// Seed a 3-fragment group on stream 7.
	_, frags := fxMessage(t, fxBinding(), 100, 700)
	if len(frags) != 3 {
		t.Fatalf("expected 3 fragments, got %d", len(frags))
	}
	if _, _, err := fb.Add(r, 7, frags[0]); err != nil {
		t.Fatalf("seed: %v", err)
	}
	time.Sleep(5 * time.Millisecond) // age past groupMaxAge

	// Delayed fragment 2 on the SAME stream. Add() first prunes the aged
	// group; the message ID stays opened, so this fragment is dropped
	// instead of seeding a corrupt group.
	_, _, err := fb.Add(r, 7, frags[2])
	if err == nil {
		t.Fatalf("expected the delayed fragment of a pruned group to be dropped; got nil (it seeded a corrupt group)")
	}
	if p := fb.Pending(); p != 0 {
		t.Fatalf("expected 0 pending groups, got %d (corrupt never-completing group leaked)", p)
	}
}
