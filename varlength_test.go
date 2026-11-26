/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package aether

import (
	"bytes"
	"errors"
	"math"
	"testing"
)

// TestVarLength_CanonicalFormsRoundTrip: every value encodes in the one form
// VarLengthSize gives for it, and that form decodes back to the value in as
// many bytes.
func TestVarLength_CanonicalFormsRoundTrip(t *testing.T) {
	for _, v := range []uint32{0, 1, 127, 128, 255, 256, 16383, 16384, 65535, 1 << 20, math.MaxUint32} {
		var buf bytes.Buffer
		n, err := EncodeVarLength(&buf, v)
		if err != nil || n != VarLengthSize(v) || buf.Len() != n {
			t.Fatalf("value %d: encoded %d bytes (%v), VarLengthSize %d", v, n, err, VarLengthSize(v))
		}
		got, read, err := DecodeVarLength(bytes.NewReader(buf.Bytes()))
		if err != nil || got != v || read != n {
			t.Fatalf("value %d: decoded %d in %d bytes, %v; want %d in %d", v, got, read, err, v, n)
		}
	}
}

// TestVarLength_RefusesNoncanonicalEncodings: an encoding of a value in more
// bytes than its canonical form, or a two-byte form carrying a value that form
// does not reach, is refused with ErrVarLengthNoncanonical after exactly its
// own bytes are read, so a 0x86 frame's payload is never sized from it.
func TestVarLength_RefusesNoncanonicalEncodings(t *testing.T) {
	cases := []struct {
		name string
		enc  []byte
		n    int
	}{
		{"5 in 2 bytes", []byte{0x80, 0x05}, 2},
		{"127 in 2 bytes", []byte{0x80, 0x7F}, 2},
		{"5 in 5 bytes", []byte{0xFF, 0, 0, 0, 5}, 5},
		{"256 in 5 bytes", []byte{0xFF, 0, 0, 0x01, 0x00}, 5},
		{"16383 in 5 bytes", []byte{0xFF, 0, 0, 0x3F, 0xFF}, 5},
		{"16384 in 2 bytes", []byte{0xC0, 0x00}, 2},
		{"32511 in 2 bytes", []byte{0xFE, 0xFF}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cr := &countingReader{r: bytes.NewReader(append(append([]byte(nil), tc.enc...), 0xAA, 0xBB))}
			v, n, err := DecodeVarLength(cr)
			if !errors.Is(err, ErrVarLengthNoncanonical) {
				t.Fatalf("% x decoded to %d in %d bytes, err %v; want ErrVarLengthNoncanonical", tc.enc, v, n, err)
			}
			if n != tc.n || cr.n != tc.n {
				t.Fatalf("% x: reported %d bytes, read %d; want %d and nothing past the encoding", tc.enc, n, cr.n, tc.n)
			}
		})
	}
}

// TestNoncanonicalShortFrameRefusedBeforePayload: on a session that chose
// frame.short, a 0x86 DATA frame whose length is a noncanonical varint is
// refused by ReadNextFrame with ErrVarLengthNoncanonical after the indicator,
// the four header bytes and the two length bytes, with the payload unread; the
// same frame with its canonical length decodes.
func TestNoncanonicalShortFrameRefusedBeforePayload(t *testing.T) {
	first := &Frame{SenderID: PeerID{1}, ReceiverID: PeerID{2}, StreamID: 5, Type: TypeDATA, SeqNo: 1, Length: 1, Payload: []byte{9}}
	for _, tc := range []struct {
		name   string
		length []byte
		refuse bool
	}{
		{"noncanonical 0x80 0x01", []byte{0x80, 0x01}, true},
		{"noncanonical 0xFF 0 0 0 1", []byte{0xFF, 0, 0, 0, 1}, true},
		{"canonical 0x01", []byte{0x01}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rx := shortFormCompressor(t)
			var wire bytes.Buffer
			if _, err := EncodeFrame(&wire, first); err != nil {
				t.Fatalf("encode: %v", err)
			}
			short := append([]byte{ShortDataVarIndicator, 0, 5, 0, 2}, tc.length...)
			short = append(short, 0xAA)
			wire.Write(short)
			if _, _, _, err := ReadNextFrame(&wire, rx); err != nil {
				t.Fatalf("full frame: %v", err)
			}
			cr := &countingReader{r: &wire}
			f, ind, _, err := ReadNextFrame(cr, rx)
			if !tc.refuse {
				if err != nil || f == nil || f.Length != 1 || !bytes.Equal(f.Payload, []byte{0xAA}) {
					t.Fatalf("canonical 0x86 frame: %+v, %v", f, err)
				}
				return
			}
			if !errors.Is(err, ErrVarLengthNoncanonical) {
				t.Fatalf("noncanonical 0x86 length % x: frame %+v, err %v; want ErrVarLengthNoncanonical", tc.length, f, err)
			}
			if ind != ShortDataVarIndicator || f != nil {
				t.Fatalf("refusal returned indicator 0x%02x, frame %v", ind, f)
			}
			if want := 1 + 4 + len(tc.length); cr.n != want {
				t.Fatalf("read %d bytes before refusing, want %d (the payload byte stays unread)", cr.n, want)
			}
			if wire.Len() != 1 {
				t.Fatalf("%d bytes left, want the one payload byte", wire.Len())
			}
		})
	}
}
