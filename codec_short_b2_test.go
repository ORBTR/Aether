/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

package aether

import (
	"bytes"
	"testing"
)

// TestB2_ShouldCompressACK_RefusesFlagCOMPRESSED is the B2 FIX.
//
// The ACK short forms carry no Flags field, and DecodeACKShortFull hardcodes
// Flags to FlagCOMPOSITE_ACK — so FlagCOMPRESSED is overwritten, not merely
// dropped. The receiver then parses a raw DEFLATE stream as a CompositeACK,
// DecodeCompositeACK returns nil, and the peer is charged ReasonACKValidation
// (weight 25) for an ACK that was perfectly well formed.
//
// Same gate as B3's on the DATA path: refuse the flag, take the full header.
func TestB2_ShouldCompressACK_RefusesFlagCOMPRESSED(t *testing.T) {
	c := NewCompressor()
	// Pin identity so the frame is short-eligible on every axis but the flag.
	c.RecordFullHeader(&Frame{Type: TypeACK, StreamID: 1})

	compressed := &Frame{Type: TypeACK, StreamID: 1, Flags: FlagCOMPRESSED,
		Length: 40, Payload: make([]byte, 40)}
	if c.ShouldCompressACK(compressed) {
		t.Error("B2 REGRESSION: ShouldCompressACK accepted a FlagCOMPRESSED frame " +
			"onto a short form that cannot carry the flag — DecodeACKShortFull would " +
			"overwrite it with FlagCOMPOSITE_ACK and the receiver would parse DEFLATE " +
			"bytes as a CompositeACK, charging ReasonACKValidation for a good ACK")
	}

	// Control: the same ACK without the flag stays short-eligible, so ACK header
	// compression is not lost for ordinary traffic.
	plain := *compressed
	plain.Flags = 0
	if !c.ShouldCompressACK(&plain) {
		t.Error("gate over-broad: an unflagged ACK on a pinned session must remain " +
			"short-header eligible")
	}
}

// TestB2_DecodeACKShortFull_OverwritesFlags documents WHY the gate is required and
// is the tripwire if the ACK short form ever gains a Flags field.
//
// Unlike the DATA decoder (which now sets Flags explicitly to zero), the ACK-full
// decoder asserts a flag value of its own. That is legitimate for the composite
// marker but means ANY other flag on the frame is destroyed in transit.
func TestB2_DecodeACKShortFull_OverwritesFlags(t *testing.T) {
	tx := NewCompressor()
	rx := NewCompressor()
	primer := &Frame{Type: TypeACK, StreamID: 1}
	tx.RecordFullHeader(primer)
	rx.RecordFullHeader(primer)

	// Encode an ACK carrying BOTH the composite marker and FlagCOMPRESSED.
	payload := make([]byte, 40)
	for i := range payload {
		payload[i] = byte(i)
	}
	sent := &Frame{Type: TypeACK, StreamID: 1,
		Flags:  FlagCOMPOSITE_ACK | FlagCOMPRESSED,
		Length: uint32(len(payload)), Payload: payload}

	var buf bytes.Buffer
	if _, err := tx.EncodeACKShort(&buf, sent); err != nil {
		t.Fatalf("EncodeACKShort: %v", err)
	}

	// Decode through the production read path, which reads the indicator itself
	// and dispatches to the matching short decoder.
	got, indicator, _, err := ReadNextFrame(&buf, rx)
	if err != nil {
		t.Fatalf("ReadNextFrame: %v", err)
	}
	if indicator != ShortACKFullIndicator && indicator != ShortACKIndicator {
		t.Fatalf("expected an ACK short indicator, got 0x%02x", indicator)
	}

	if got.Flags.Has(FlagCOMPRESSED) {
		t.Fatal("the ACK short form now appears to preserve FlagCOMPRESSED — REVISIT " +
			"the ShouldCompressACK gate, which exists only because it did not")
	}
	if !got.Flags.Has(FlagCOMPOSITE_ACK) {
		t.Error("the composite marker should still be asserted by the decoder")
	}
	// The payload itself survives byte-for-byte; it is only the INTERPRETATION
	// that is lost — which is exactly why nothing downstream detects it.
	if !bytes.Equal(got.Payload, payload) {
		t.Errorf("payload should round-trip verbatim; the defect is flag loss, not "+
			"byte loss (got %d bytes, want %d)", len(got.Payload), len(payload))
	}
}
