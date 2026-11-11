/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

// TestOpenPayloadGolden: the OPEN payload of the current frame grammar is
// thirty-nine bytes, the opener's initial credit big-endian in bytes 10-13, the
// stream's FEC level in byte 14, the opener's generation big-endian in bytes 15-22,
// and its statement of its earlier stream under the ID, that stream's generation and
// what its consumer returned there, big-endian in bytes 23-30 and 31-38; it decodes
// back to what was encoded. A payload of an earlier layout, the twenty-three bytes
// without the statement among them, decodes to the zero value, and Validate refuses
// an OPEN frame carrying one before any handler reads it.
func TestOpenPayloadGolden(t *testing.T) {
	o := OpenPayload{Reliability: ReliableUnordered, Priority: 128, Dependency: 0x0102030405060708, InitialCredit: 0x00100400, FECLevel: 2, Generation: 0x3132333435363738,
		PriorGeneration: 0x4142434445464748, PriorConsumed: 0x5152535455565758}
	want := []byte{byte(ReliableUnordered), 0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x10, 0x04, 0x00, 0x02,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
		0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58}
	got := EncodeOpenPayload(o)
	if !bytes.Equal(got, want) {
		t.Fatalf("EncodeOpenPayload = % x, want % x", got, want)
	}
	if OpenPayloadSize != len(want) {
		t.Fatalf("OpenPayloadSize = %d, want %d", OpenPayloadSize, len(want))
	}
	if back := DecodeOpenPayload(got); back != o {
		t.Fatalf("DecodeOpenPayload = %+v, want %+v", back, o)
	}
	if MaxOpenCredit != 1<<32-1 {
		t.Fatalf("MaxOpenCredit = %d, the four-byte field holds %d", MaxOpenCredit, int64(1<<32-1))
	}

	for _, n := range []int{10, 14, 15, 23, 31} {
		earlier := got[:n]
		if back := DecodeOpenPayload(earlier); back != (OpenPayload{}) {
			t.Fatalf("a %d-byte OPEN payload decoded to %+v, want the zero value", n, back)
		}
		f := &Frame{StreamID: 140, Type: TypeOPEN, Length: uint32(len(earlier)), Payload: earlier}
		if err := f.Validate(); err == nil {
			t.Fatalf("Validate admitted a %d-byte OPEN frame", n)
		}
	}
	f := &Frame{StreamID: 140, Type: TypeOPEN, Length: uint32(len(got)), Payload: got}
	if err := f.Validate(); err != nil {
		t.Fatalf("Validate refused a current OPEN frame: %v", err)
	}
}

// earlierFrameOffer is this build's own offer with the frame grammar entry
// listing only the version before the current one: a peer whose RESET
// acknowledgment states no Consumed and which settles a reset stream's connection
// credit by taking it back at its own RESET and withholding its later grants.
func earlierFrameOffer(t *testing.T) WireVersions {
	t.Helper()
	own, err := LocalWireVersions(nil)
	if err != nil {
		t.Fatalf("LocalWireVersions: %v", err)
	}
	out := make(WireVersions, len(own))
	for i, e := range own {
		out[i] = WireVersion{Name: e.Name, Versions: append([]uint16(nil), e.Versions...), Required: e.Required}
		if e.Name == WireVersionFrame {
			out[i].Versions = []uint16{WireVersionFrameCurrent - 1}
		}
	}
	return out
}

// TestFrameGrammarNegotiation: two peers of this build choose the current
// frame grammar on both sides; a peer that also lists the earlier grammar
// still meets this build at the current one, the highest both list; a peer
// that lists only the earlier grammar is refused with a
// *WireVersionMismatchError naming the frame entry and both lists, whichever
// side is local, so neither side reaches session state.
func TestFrameGrammarNegotiation(t *testing.T) {
	if WireVersionFrameCurrent != 6 || WireVersionFrameCurrent-1 != 5 {
		t.Fatalf("WireVersionFrameCurrent = %d; the RESET acknowledgment stating Consumed is grammar 6, and the earlier grammar every peer of this build refuses is 5", WireVersionFrameCurrent)
	}
	own, err := LocalWireVersions(nil)
	if err != nil {
		t.Fatalf("LocalWireVersions: %v", err)
	}
	for _, e := range own {
		if e.Name == WireVersionFrame {
			if !e.Required || !reflect.DeepEqual(e.Versions, []uint16{WireVersionFrameCurrent}) {
				t.Fatalf("own frame entry %+v, want only version %d, required", e, WireVersionFrameCurrent)
			}
		}
	}
	ab, err := ChooseWireVersions(own, own)
	if err != nil {
		t.Fatalf("two peers of this build: %v", err)
	}
	if v, ok := ab.Version(WireVersionFrame); !ok || v != WireVersionFrameCurrent {
		t.Fatalf("two peers of this build chose frame %d, %v", v, ok)
	}

	both := earlierFrameOffer(t)
	for i := range both {
		if both[i].Name == WireVersionFrame {
			both[i].Versions = []uint16{WireVersionFrameCurrent - 1, WireVersionFrameCurrent}
		}
	}
	for _, swap := range []bool{false, true} {
		a, b := own, both
		if swap {
			a, b = both, own
		}
		got, err := ChooseWireVersions(a, b)
		if err != nil {
			t.Fatalf("a peer listing both grammars (swapped %v): %v", swap, err)
		}
		if !got.Equal(ab) {
			t.Fatalf("a peer listing both grammars (swapped %v) chose %v, want %v", swap, got, ab)
		}
	}

	earlier := earlierFrameOffer(t)
	for _, swap := range []bool{false, true} {
		a, b := own, earlier
		if swap {
			a, b = earlier, own
		}
		got, err := ChooseWireVersions(a, b)
		if len(got.Entries()) != 0 {
			t.Fatalf("refusal (swapped %v) returned a chosen set %v", swap, got)
		}
		var mm *WireVersionMismatchError
		if !errors.As(err, &mm) || !errors.Is(err, ErrWireVersionMismatch) {
			t.Fatalf("a peer of the earlier grammar (swapped %v): err = %v, want a *WireVersionMismatchError", swap, err)
		}
		if mm.Name != WireVersionFrame {
			t.Fatalf("the refusal names %q, want %q", mm.Name, WireVersionFrame)
		}
		wantLocal, wantPeer := []uint16{WireVersionFrameCurrent}, []uint16{WireVersionFrameCurrent - 1}
		if swap {
			wantLocal, wantPeer = wantPeer, wantLocal
		}
		if !reflect.DeepEqual(mm.Local, wantLocal) || !reflect.DeepEqual(mm.Peer, wantPeer) {
			t.Fatalf("the refusal lists local %v peer %v, want %v and %v", mm.Local, mm.Peer, wantLocal, wantPeer)
		}
	}
}
