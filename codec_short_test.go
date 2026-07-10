/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import (
	"bytes"
	"testing"
)

// TestEncodeDecodeACKShort_FullFormZeroAckDelay_NoDesync is the AE-H-13
// regression. A full-form composite ACK (bitmap present) whose AckDelay==0
// used to encode under the shared 0x84 indicator and then decode as the
// 11-byte lite form, under-consuming the frame's wire bytes and desyncing
// every subsequent frame on the ordered stream. With the dedicated
// ShortACKFullIndicator (0x88), the full form is decoded byte-exactly.
func TestEncodeDecodeACKShort_FullFormZeroAckDelay_NoDesync(t *testing.T) {
	// [BaseACK:4][AckDelay:2 = 0x0000][BitmapLen:1 = 4][Bitmap:4][Flags:1].
	// BitmapLen != 0 forces the full form; AckDelay == 0 is the desync trigger.
	payload := []byte{
		0x00, 0x00, 0x00, 0x64, // BaseACK = 100
		0x00, 0x00, // AckDelay = 0 (trigger)
		0x04,                   // BitmapLen = 4
		0xFF, 0x00, 0xFF, 0x00, // Bitmap (4 bytes)
		byte(CACKHasGaps), // Flags
	}
	full := &Frame{
		StreamID: 1, Type: TypeACK, Flags: FlagCOMPOSITE_ACK,
		Length: uint32(len(payload)), Payload: payload,
	}

	c := NewCompressor()
	var buf bytes.Buffer
	if _, err := c.EncodeACKShort(&buf, full); err != nil {
		t.Fatalf("EncodeACKShort(full): %v", err)
	}

	// A sentinel that must remain byte-for-byte after the ACK is decoded —
	// this is what proves there is no under-consumption / stream desync.
	sentinel := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	buf.Write(sentinel)

	if got := buf.Bytes()[0]; got != ShortACKFullIndicator {
		t.Fatalf("full ACK indicator: got 0x%02x want 0x%02x (ShortACKFullIndicator)", got, ShortACKFullIndicator)
	}

	dc := NewCompressor()
	frame, indicator, batch, err := ReadNextFrame(&buf, dc)
	if err != nil {
		t.Fatalf("ReadNextFrame(full ACK): %v", err)
	}
	if batch != nil {
		t.Fatalf("expected single frame, got batch of %d", len(batch))
	}
	if indicator != ShortACKFullIndicator {
		t.Fatalf("decoded indicator: got 0x%02x want 0x%02x", indicator, ShortACKFullIndicator)
	}
	if frame.Type != TypeACK {
		t.Errorf("Type: got %v want TypeACK", frame.Type)
	}
	if frame.StreamID != 1 {
		t.Errorf("StreamID: got %d want 1", frame.StreamID)
	}
	if frame.Length != uint32(len(payload)) {
		t.Errorf("Length: got %d want %d", frame.Length, len(payload))
	}
	if !bytes.Equal(frame.Payload, payload) {
		t.Errorf("Payload: got %v want %v", frame.Payload, payload)
	}
	// The cursor must sit exactly at the sentinel — no desync.
	if remaining := buf.Bytes(); !bytes.Equal(remaining, sentinel) {
		t.Fatalf("stream desync: after decoding the full ACK the reader cursor is not at the sentinel; got %v want %v", remaining, sentinel)
	}
}

// TestEncodeDecodeACKShort_LiteForm_RoundTrip proves the lite form still uses
// the 0x84 indicator at 11 bytes and round-trips after the AE-H-13 split, and
// that it is NOT taken down the full-decode branch.
func TestEncodeDecodeACKShort_LiteForm_RoundTrip(t *testing.T) {
	// Length == CompositeACKMinSize (8), BitmapLen (byte 6) == 0, Flags (byte 7) == 0.
	payload := []byte{0x00, 0x00, 0x00, 0x2A, 0x00, 0x00, 0x00, 0x00} // BaseACK = 42
	lite := &Frame{
		StreamID: 3, Type: TypeACK, Flags: FlagCOMPOSITE_ACK,
		Length: CompositeACKMinSize, Payload: payload,
	}

	c := NewCompressor()
	var buf bytes.Buffer
	n, err := c.EncodeACKShort(&buf, lite)
	if err != nil {
		t.Fatalf("EncodeACKShort(lite): %v", err)
	}
	if n != ShortACKLiteSize {
		t.Fatalf("lite ACK wire size: got %d want %d", n, ShortACKLiteSize)
	}
	if got := buf.Bytes()[0]; got != ShortACKIndicator {
		t.Fatalf("lite ACK indicator: got 0x%02x want 0x%02x (ShortACKIndicator)", got, ShortACKIndicator)
	}

	dc := NewCompressor()
	frame, indicator, batch, err := ReadNextFrame(&buf, dc)
	if err != nil {
		t.Fatalf("ReadNextFrame(lite ACK): %v", err)
	}
	if batch != nil {
		t.Fatalf("expected single frame, got batch of %d", len(batch))
	}
	if indicator != ShortACKIndicator {
		t.Fatalf("decoded indicator: got 0x%02x want 0x%02x", indicator, ShortACKIndicator)
	}
	if frame.Type != TypeACK {
		t.Errorf("Type: got %v want TypeACK", frame.Type)
	}
	if frame.StreamID != 3 {
		t.Errorf("StreamID: got %d want 3", frame.StreamID)
	}
	if frame.Length != CompositeACKMinSize {
		t.Errorf("Length: got %d want %d", frame.Length, CompositeACKMinSize)
	}
	if !bytes.Equal(frame.Payload, payload) {
		t.Errorf("Payload: got %v want %v", frame.Payload, payload)
	}
	if buf.Len() != 0 {
		t.Fatalf("lite ACK left %d unconsumed bytes", buf.Len())
	}
}

// TestShouldCompress_OversizedStreamIDFallsBackToFullHeader is the AE-H-14
// regression. The short-header StreamID field is uint16; a stream whose ID
// exceeds MaxShortHeaderStreamID (0xFFFF) must not be admitted to any
// short-header form, or the ID truncates on the wire and the decoder
// misroutes the frame. Streams keep working via the full 50-byte header
// (no capability loss).
func TestShouldCompress_OversizedStreamIDFallsBackToFullHeader(t *testing.T) {
	const oversized = uint64(0x1_0001) // 65537 — low 16 bits collide with 0x0001
	sender := PeerID{1, 2, 3, 4, 5, 6, 7, 8}
	receiver := PeerID{9, 10, 11, 12, 13, 14, 15, 16}

	c := NewCompressor()

	// Establish identity + stream state for the oversized stream.
	f0 := &Frame{
		SenderID: sender, ReceiverID: receiver,
		StreamID: oversized, Type: TypeDATA, SeqNo: 1,
	}
	c.RecordFullHeader(f0)

	// A DATA frame on the oversized stream must fall back to the full header.
	f1 := &Frame{
		SenderID: sender, ReceiverID: receiver,
		StreamID: oversized, Type: TypeDATA, SeqNo: 2,
		Length: 3, Payload: []byte{1, 2, 3},
	}
	if c.ShouldCompressData(f1) {
		t.Error("ShouldCompressData: oversized StreamID must not compress (uint16 truncation)")
	}

	ctrl := &Frame{
		SenderID: sender, ReceiverID: receiver,
		StreamID: oversized, Type: TypePING, SeqNo: 3,
	}
	if c.ShouldCompressControl(ctrl) {
		t.Error("ShouldCompressControl: oversized StreamID must not compress")
	}

	ack := &Frame{
		SenderID: sender, ReceiverID: receiver,
		StreamID: oversized, Type: TypeACK,
	}
	if c.ShouldCompressACK(ack) {
		t.Error("ShouldCompressACK: oversized StreamID must not compress")
	}

	// Positive control: an in-range stream (0x0001) still compresses, proving
	// the guard did not over-reject.
	const inRange = uint64(0x0001)
	g0 := &Frame{
		SenderID: sender, ReceiverID: receiver,
		StreamID: inRange, Type: TypeDATA, SeqNo: 1,
	}
	c.RecordFullHeader(g0)
	g1 := &Frame{
		SenderID: sender, ReceiverID: receiver,
		StreamID: inRange, Type: TypeDATA, SeqNo: 2,
		Length: 3, Payload: []byte{1, 2, 3},
	}
	if !c.ShouldCompressData(g1) {
		t.Error("ShouldCompressData: in-range StreamID should still compress (guard over-rejected)")
	}

	// Behaviour-level regression: routing the oversized frame through the
	// batch encoder must preserve the full 64-bit StreamID on decode.
	var buf bytes.Buffer
	if _, err := c.EncodeBatch(&buf, []*Frame{f1}); err != nil {
		t.Fatalf("EncodeBatch: %v", err)
	}
	var peek [1]byte
	copy(peek[:], buf.Bytes()) // indicator byte
	if peek[0] != ShortBatchIndicator {
		t.Fatalf("batch indicator: got 0x%02x want 0x%02x", peek[0], ShortBatchIndicator)
	}
	// Consume the batch indicator, then decode the batch body.
	buf.Next(1)
	dc := NewCompressor()
	frames, err := dc.DecodeBatch(&buf)
	if err != nil {
		t.Fatalf("DecodeBatch: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("DecodeBatch: got %d frames want 1", len(frames))
	}
	if frames[0].StreamID != oversized {
		t.Fatalf("StreamID truncated: got 0x%X want 0x%X", frames[0].StreamID, oversized)
	}
}
