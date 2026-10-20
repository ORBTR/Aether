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

// TestAetherWireVersionsRegistersFragment: every offer carries the fragment
// envelope as a required entry at version 2, so a peer that omits it, or offers
// only another version, is refused before a session exists, and an application
// cannot register the name for itself.
func TestAetherWireVersionsRegistersFragment(t *testing.T) {
	own := AetherWireVersions()
	var found *WireVersion
	for i := range own {
		if own[i].Name == "fragment" {
			found = &own[i]
		}
	}
	if found == nil {
		t.Fatalf("AetherWireVersions() = %+v has no fragment entry", own)
	}
	if !found.Required || !reflect.DeepEqual(found.Versions, []uint16{2}) {
		t.Fatalf("fragment entry = %+v, want versions [2], required", *found)
	}
	if err := own.Validate(); err != nil {
		t.Fatalf("AetherWireVersions() is not canonical: %v", err)
	}

	both, err := ChooseWireVersions(own, own)
	if err != nil {
		t.Fatalf("ChooseWireVersions(own, own): %v", err)
	}
	if v, ok := both.Version("fragment"); !ok || v != 2 {
		t.Fatalf("chosen fragment = %d, %v; want 2, true", v, ok)
	}

	for _, peer := range []WireVersions{
		{wv(WireVersionFrame, true, 2), wv(WireVersionFrameShort, false, 1)},
		{wv("fragment", true, 1), wv(WireVersionFrame, true, 2)},
		{wv("fragment", false, 3), wv(WireVersionFrame, true, 2)},
	} {
		for _, swap := range []bool{false, true} {
			a, b := own, peer
			if swap {
				a, b = peer, own
			}
			_, err := ChooseWireVersions(a, b)
			var mm *WireVersionMismatchError
			if !errors.As(err, &mm) || mm.Name != "fragment" {
				t.Errorf("peer %+v (swapped %v): err = %v, want a mismatch naming fragment", peer, swap, err)
			}
		}
	}

	if _, err := LocalWireVersions(WireVersions{wv("fragment", true, 2)}); !errors.Is(err, ErrWireVersionsMalformed) {
		t.Fatalf("an application fragment entry: err = %v, want ErrWireVersionsMalformed", err)
	}
}

// TestFragmentFrameNeverTakesAShortForm: the short DATA forms carry no flags, so
// a DATA frame the sender marked as one fragment of a message keeps its full
// header on a session whose grammar has short forms. An unmarked DATA frame on
// the same pinned stream stays short-eligible.
func TestFragmentFrameNeverTakesAShortForm(t *testing.T) {
	c := shortFormCompressor(t)
	primer := &Frame{Type: TypeDATA, StreamID: 5, SeqNo: 1}
	c.RecordFullHeader(primer)

	plain := &Frame{Type: TypeDATA, StreamID: 5, SeqNo: 2, Length: 4, Payload: []byte("data")}
	if !c.ShouldCompressData(plain) {
		t.Fatalf("an unmarked DATA frame on a pinned stream is not short-eligible")
	}
	marked := *plain
	marked.Flags = FrameFlags(0x80)
	if c.ShouldCompressData(&marked) {
		t.Fatalf("a DATA frame flagged 0x80 (one fragment) was admitted to a short form, which drops the flag")
	}
	f := &Frame{Type: TypeDATA, Flags: FrameFlags(0x80)}
	if !f.IsFragment() {
		t.Fatalf("Frame.IsFragment() is false for a DATA frame flagged 0x80")
	}
	if (&Frame{Type: TypeACK, Flags: FrameFlags(0x80)}).IsFragment() {
		t.Fatalf("Frame.IsFragment() is true for a composite ACK, whose 0x80 is the composite marker")
	}
}
