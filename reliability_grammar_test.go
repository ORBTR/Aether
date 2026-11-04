/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import (
	"errors"
	"reflect"
	"testing"
)

// TestAetherWireVersionsRegistersReliability: every offer carries the
// reliability profile as a required entry at version 1, so a peer that omits
// it, or offers only another version, is refused before a session exists, and
// an application cannot register the name for itself.
func TestAetherWireVersionsRegistersReliability(t *testing.T) {
	own := AetherWireVersions()
	var found *WireVersion
	for i := range own {
		if own[i].Name == "reliability" {
			found = &own[i]
		}
	}
	if found == nil {
		t.Fatalf("AetherWireVersions() = %+v has no reliability entry", own)
	}
	if !found.Required || !reflect.DeepEqual(found.Versions, []uint16{1}) {
		t.Fatalf("reliability entry = %+v, want versions [1], required", *found)
	}
	if err := own.Validate(); err != nil {
		t.Fatalf("AetherWireVersions() is not canonical: %v", err)
	}

	both, err := ChooseWireVersions(own, own)
	if err != nil {
		t.Fatalf("ChooseWireVersions(own, own): %v", err)
	}
	if v, ok := both.Version(WireVersionReliability); !ok || v != 1 {
		t.Fatalf("chosen reliability = %d, %v; want 1, true", v, ok)
	}

	// Peers that agree on every other entry and omit reliability, or offer
	// only another version of it.
	agreeing := WireVersions{
		wv(WireVersionBounds, true, 1),
		wv(WireVersionFragment, true, WireVersionFragmentCurrent),
		wv(WireVersionFrame, true, WireVersionFrameCurrent),
		wv(WireVersionFrameShort, false, wireVersionFrameShortCurrent),
	}
	for _, peer := range []WireVersions{
		agreeing,
		append(append(WireVersions(nil), agreeing...), wv(WireVersionReliability, true, 2)),
		append(append(WireVersions(nil), agreeing...), wv(WireVersionReliability, false, 2, 3)),
	} {
		for _, swap := range []bool{false, true} {
			a, b := own, peer
			if swap {
				a, b = peer, own
			}
			_, err := ChooseWireVersions(a, b)
			var mm *WireVersionMismatchError
			if !errors.As(err, &mm) || mm.Name != WireVersionReliability {
				t.Errorf("peer %+v (swapped %v): err = %v, want a mismatch naming reliability", peer, swap, err)
			}
		}
	}

	if _, err := LocalWireVersions(WireVersions{wv(WireVersionReliability, true, 1)}); !errors.Is(err, ErrWireVersionsMalformed) {
		t.Fatalf("an application reliability entry: err = %v, want ErrWireVersionsMalformed", err)
	}
}
