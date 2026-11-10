/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// TestShortForms_GoldenLayoutsAsTheSpecStatesThem: every short form section 23.2 of
// docs/protocol-spec.md lays out, written by the codec and read back byte by byte, so
// the spec and the codec cannot drift apart unseen. Stream 5 is primed with a full
// header at SeqNo 70000, above 65,535, where a delta and the low 16 bits differ.
func TestShortForms_GoldenLayoutsAsTheSpecStatesThem(t *testing.T) {
	c := shortFormCompressor(t)
	c.RecordFullHeader(&Frame{StreamID: 5, Type: TypeDATA, SeqNo: 70000, Length: 1, Payload: []byte{1}})

	// 23.2.1 0x82: [0x82:1][StreamID:2][SeqLow:2][Length:4], SeqLow the low 16 bits of
	// the absolute SeqNo, which the decoder rebuilds against the stream's last SeqNo.
	payload := bytes.Repeat([]byte{0xAB}, 300)
	var b bytes.Buffer
	if _, err := c.EncodeDataShort(&b, &Frame{StreamID: 5, Type: TypeDATA, SeqNo: 70005, Length: uint32(len(payload)), Payload: payload}); err != nil {
		t.Fatalf("0x82: %v", err)
	}
	want := []byte{0x82, 0, 5, 0, 0, 0, 0, 0x01, 0x2C}
	binary.BigEndian.PutUint16(want[3:5], uint16(70005&0xFFFF))
	if got := b.Bytes(); !bytes.Equal(got[:ShortDataSize], want) || b.Len() != ShortDataSize+len(payload) {
		t.Fatalf("0x82 header % x (%d bytes), want % x then the 300-byte payload", got[:ShortDataSize], b.Len(), want)
	}
	rx := shortFormCompressor(t)
	rx.RecordFullHeader(&Frame{StreamID: 5, Type: TypeDATA, SeqNo: 70000, Length: 1, Payload: []byte{1}})
	f, err := rx.DecodeDataShort(bytes.NewReader(b.Bytes()[1:]))
	if err != nil || f.SeqNo != 70005 || f.StreamID != 5 || !bytes.Equal(f.Payload, payload) {
		t.Fatalf("0x82 decoded to %+v, %v; want stream 5, SeqNo 70005 and the payload", f, err)
	}

	// 23.2.2 0x83: [0x83:1][Type:1][StreamID:2][SeqNo:4], 8 bytes.
	b.Reset()
	if _, err := c.EncodeControlShort(&b, &Frame{StreamID: 2, Type: TypePING, SeqNo: 0x01020304}); err != nil {
		t.Fatalf("0x83: %v", err)
	}
	if want := []byte{0x83, byte(TypePING), 0, 2, 1, 2, 3, 4}; !bytes.Equal(b.Bytes(), want) {
		t.Fatalf("0x83: % x, want % x", b.Bytes(), want)
	}

	// 23.2.3 0x84: [0x84:1][StreamID:2][BaseACK:4][AckDelay:2][BitmapLen:1=0][Flags:1],
	// 11 bytes; 0x88: [0x88:1][StreamID:2][Length:2][CompositeACK payload].
	b.Reset()
	lite := EncodeCompositeACK(&CompositeACK{BaseACK: 0x0A0B0C0D, AckDelay: 0x0102})
	if _, err := c.EncodeACKShort(&b, &Frame{StreamID: 7, Type: TypeACK, Flags: FlagCOMPOSITE_ACK, Length: uint32(len(lite)), Payload: lite}); err != nil {
		t.Fatalf("0x84: %v", err)
	}
	if want := []byte{0x84, 0, 7, 0x0A, 0x0B, 0x0C, 0x0D, 0x01, 0x02, 0, 0}; !bytes.Equal(b.Bytes(), want) {
		t.Fatalf("0x84: % x, want % x", b.Bytes(), want)
	}
	b.Reset()
	full := EncodeCompositeACK(&CompositeACK{BaseACK: 9, Bitmap: []byte{0xF0, 0, 0, 0}})
	ackGaps := &Frame{StreamID: 7, Type: TypeACK, Flags: FlagCOMPOSITE_ACK, Length: uint32(len(full)), Payload: full}
	if _, err := c.EncodeACKShort(&b, ackGaps); err != nil {
		t.Fatalf("0x88: %v", err)
	}
	if got := b.Bytes(); got[0] != 0x88 || binary.BigEndian.Uint16(got[1:3]) != 7 || int(binary.BigEndian.Uint16(got[3:5])) != len(full) || !bytes.Equal(got[5:], full) || b.Len() != 5+len(full) {
		t.Fatalf("0x88: % x, want 88 00 07, the length %d and the payload", got, len(full))
	}

	// 23.2.5 0x86: [0x86:1][StreamID:2][SeqLow:2][Length:varint]; the varint has one
	// canonical form, 1 byte to 127, 2 bytes (0x80|high, low) to 16,383, then 5 bytes
	// (0xFF, uint32 big-endian), so the header is 6, 7 or 10 bytes.
	for _, tc := range []struct {
		n      int
		varint []byte
	}{
		{5, []byte{5}},
		{200, []byte{0x80, 200}},
		{20000, []byte{0xFF, 0, 0, 0x4E, 0x20}},
	} {
		b.Reset()
		p := bytes.Repeat([]byte{1}, tc.n)
		if _, err := c.EncodeDataShortVar(&b, &Frame{StreamID: 5, Type: TypeDATA, SeqNo: 70006, Length: uint32(tc.n), Payload: p}); err != nil {
			t.Fatalf("0x86 length %d: %v", tc.n, err)
		}
		want := append([]byte{0x86, 0, 5, 0, 0}, tc.varint...)
		binary.BigEndian.PutUint16(want[3:5], uint16(70006&0xFFFF))
		if got := b.Bytes()[:b.Len()-tc.n]; !bytes.Equal(got, want) {
			t.Fatalf("0x86 length %d: header % x, want % x", tc.n, got, want)
		}
	}
	if _, _, err := DecodeVarLength(bytes.NewReader([]byte{0x80, 5})); !errors.Is(err, ErrVarLengthNoncanonical) {
		t.Fatalf("a 2-byte varint carrying 5 decoded with %v, want ErrVarLengthNoncanonical", err)
	}

	// 23.2.4 0x85: [0x85:1][Count:1] and each child in the first short form it
	// qualifies for, or as a full frame behind 0x01: a gapped ACK goes as 0x88, and a
	// PING on a stream past the 16-bit ID as a full frame.
	b.Reset()
	ping := &Frame{StreamID: 70000, Type: TypePING, SeqNo: 1}
	if _, err := c.EncodeBatch(&b, []*Frame{ackGaps, ping}); err != nil {
		t.Fatalf("0x85: %v", err)
	}
	bb := b.Bytes()
	if bb[0] != 0x85 || bb[1] != 2 || bb[2] != 0x88 || bb[2+5+len(full)] != FullFrameDiscriminator {
		t.Fatalf("0x85 batch % x: want 85 02, a 0x88 child, then a child behind 0x01", bb[:3])
	}
	frames, err := shortFormCompressor(t).DecodeBatch(bytes.NewReader(bb[1:]))
	if err != nil || len(frames) != 2 || frames[1].StreamID != 70000 || frames[1].Type != TypePING {
		t.Fatalf("0x85 decoded to %d frames, %v", len(frames), err)
	}

	// 23.2.6 0x87: the header of 0x82 under its own indicator. No sender writes it,
	// since ShouldCompressData keeps every FlagENCRYPTED frame on the full header, and
	// a batch refuses it as a child.
	b.Reset()
	enc := &Frame{StreamID: 5, Type: TypeDATA, Flags: FlagENCRYPTED, SeqNo: 70007, Length: 29, Payload: make([]byte, 29)}
	if c.ShouldCompressData(enc) {
		t.Fatal("ShouldCompressData admits a FlagENCRYPTED frame to a short form")
	}
	if _, err := c.EncodeEncryptedDataShort(&b, enc); err != nil {
		t.Fatalf("0x87: %v", err)
	}
	want = []byte{0x87, 0, 5, 0, 0, 0, 0, 0, 29}
	binary.BigEndian.PutUint16(want[3:5], uint16(70007&0xFFFF))
	if got := b.Bytes()[:ShortDataSize]; !bytes.Equal(got, want) {
		t.Fatalf("0x87 header % x, want % x", got, want)
	}
	if _, err := shortFormCompressor(t).DecodeBatch(bytes.NewReader(append([]byte{1}, b.Bytes()...))); err == nil {
		t.Fatal("a batch carrying a 0x87 child decoded")
	}
}
