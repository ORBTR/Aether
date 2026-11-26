/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package aether

import (
	"errors"
	"reflect"
	"testing"

	"github.com/ORBTR/aether/flow"
)

// TestAetherWireVersionsRegistersBounds: every session states the credit and
// queue profile it runs, required. A peer that omits it, or runs another version
// of it, is refused naming the entry whichever side chooses, because its sender's
// connection credit would not be this side's memory ceiling.
func TestAetherWireVersionsRegistersBounds(t *testing.T) {
	own := AetherWireVersions()
	var found *WireVersion
	for i := range own {
		if own[i].Name == WireVersionBounds {
			found = &own[i]
		}
	}
	if found == nil {
		t.Fatalf("AetherWireVersions() = %+v has no bounds entry", own)
	}
	if !found.Required || !reflect.DeepEqual(found.Versions, []uint16{flow.BoundsProfileVersion}) {
		t.Fatalf("bounds entry = %+v, want only version %d, required", *found, flow.BoundsProfileVersion)
	}
	both, err := ChooseWireVersions(own, own)
	if err != nil {
		t.Fatalf("ChooseWireVersions(own, own): %v", err)
	}
	if v, ok := both.Version(WireVersionBounds); !ok || v != flow.BoundsProfileVersion {
		t.Fatalf("chosen bounds = %d, %v", v, ok)
	}
	var without, other WireVersions
	for _, e := range own {
		if e.Name == WireVersionBounds {
			other = append(other, WireVersion{Name: e.Name, Versions: []uint16{flow.BoundsProfileVersion + 1}, Required: true})
			continue
		}
		without = append(without, e)
		other = append(other, e)
	}
	for _, peer := range []WireVersions{without, other} {
		for _, swap := range []bool{false, true} {
			a, b := own, peer
			if swap {
				a, b = peer, own
			}
			_, err := ChooseWireVersions(a, b)
			var mm *WireVersionMismatchError
			if !errors.As(err, &mm) || mm.Name != WireVersionBounds {
				t.Errorf("peer %+v (swapped %v): err = %v, want a mismatch naming bounds", peer, swap, err)
			}
		}
	}
}
