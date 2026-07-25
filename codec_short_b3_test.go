/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

package aether

import (
	"bytes"
	"compress/flate"
	"io"
	"strings"
	"testing"
)

// b3deflate compresses like the production writer does
// (adapter/noise_reliability.go compressPayload → flate.BestSpeed).
func b3deflate(t *testing.T, in []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestSpeed)
	if err != nil {
		t.Fatalf("flate.NewWriter: %v", err)
	}
	if _, err := w.Write(in); err != nil {
		t.Fatalf("deflate write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("deflate close: %v", err)
	}
	return buf.Bytes()
}

// b3compressedDataFrame builds a DATA frame carrying a deflated payload, with a
// primed compressor whose stream state makes the frame short-header ELIGIBLE on
// every axis except the flag — so a gate failure is attributable to the flag alone.
func b3compressedDataFrame(t *testing.T) (*Compressor, *Frame, []byte) {
	t.Helper()
	tx := NewCompressor()
	const streamID = uint64(7)

	// A stream's first frame always takes the full header; prime past that.
	tx.RecordFullHeader(&Frame{StreamID: streamID, Type: TypeDATA, SeqNo: 1})

	original := []byte(strings.Repeat("orbtr-mesh-payload-", 8))
	if len(original) <= 64 {
		t.Fatalf("fixture must exceed the 64-byte compression gate, got %d", len(original))
	}
	compressed := b3deflate(t, original)
	if len(compressed) >= len(original) {
		t.Fatalf("fixture must shrink under flate (%d -> %d)", len(original), len(compressed))
	}

	return tx, &Frame{
		StreamID: streamID,
		Type:     TypeDATA,
		SeqNo:    2,
		Flags:    FlagCOMPRESSED,
		Length:   uint32(len(compressed)),
		Payload:  compressed,
	}, original
}

// TestB3_ShouldCompressData_RefusesFlagCOMPRESSED is the B3 FIX.
//
// writeFrame deflates any payload over 64 bytes and sets FlagCOMPRESSED before
// the header form is chosen. The short DATA forms (0x82/0x86) have no Flags
// field, so such a frame must fall back to the full header — otherwise the flag
// is dropped in transit and the receiver, which decompresses only when it sees
// FlagCOMPRESSED, hands the application raw DEFLATE bytes.
//
// TestB3_ShortDataWireForm_CannotCarryFlags below demonstrates the damage this
// gate prevents; this test pins the gate itself.
func TestB3_ShouldCompressData_RefusesFlagCOMPRESSED(t *testing.T) {
	tx, frame, _ := b3compressedDataFrame(t)

	if tx.ShouldCompressData(frame) {
		t.Fatal("B3 REGRESSION: ShouldCompressData accepted a FlagCOMPRESSED frame " +
			"onto the short-header DATA path, which cannot carry the flag — it must " +
			"fall back to the full header")
	}

	// Control: the SAME frame without the flag is still eligible, proving the
	// refusal is attributable to FlagCOMPRESSED and not to unrelated state.
	plain := *frame
	plain.Flags = 0
	if !tx.ShouldCompressData(&plain) {
		t.Error("gate over-broad: an unflagged DATA frame on a primed stream should " +
			"still be short-header eligible (header compression must not be lost " +
			"for ordinary traffic)")
	}
}

// TestB3_ShortDataWireForm_CannotCarryFlags documents WHY the gate above exists,
// and is the tripwire if the wire format ever changes.
//
// It asserts a PROPERTY OF THE FORMAT, not a bug: encoding a flagged frame short
// loses the flag, and a receiver applying the production rule then delivers the
// still-compressed bytes to the application — with Length matching the header, so
// Validate() passes, no guard trips and no abuse counter increments. That silence
// is what made B3 invisible in production while it corrupted data.
//
// If a Flags field is ever added to the short DATA forms, this test will fail —
// at which point revisit the ShouldCompressData gate, because the fallback may no
// longer be necessary.
func TestB3_ShortDataWireForm_CannotCarryFlags(t *testing.T) {
	tx, frame, original := b3compressedDataFrame(t)
	rx := NewCompressor()
	rx.RecordFullHeader(&Frame{StreamID: frame.StreamID, Type: TypeDATA, SeqNo: 1})

	var buf bytes.Buffer
	if _, err := tx.EncodeDataShort(&buf, frame); err != nil {
		t.Fatalf("EncodeDataShort: %v", err)
	}
	wire := buf.Bytes()
	if len(wire) == 0 || wire[0] != ShortDataIndicator {
		t.Fatalf("unexpected short-DATA indicator: %#v", wire[:1])
	}

	decoded, err := rx.DecodeDataShort(bytes.NewReader(wire[1:])) // skip indicator
	if err != nil {
		t.Fatalf("DecodeDataShort: %v", err)
	}

	if decoded.Flags.Has(FlagCOMPRESSED) {
		t.Fatal("the short DATA form now appears to carry Flags — REVISIT the " +
			"ShouldCompressData FlagCOMPRESSED gate, which exists only because it could not")
	}

	// Replay the receiver's actual rule: decompress iff the flag is set. With the
	// flag gone, the application is handed the compressed bytes verbatim.
	delivered := decoded.Payload
	if decoded.Flags.Has(FlagCOMPRESSED) {
		out, err := io.ReadAll(flate.NewReader(bytes.NewReader(delivered)))
		if err != nil {
			t.Fatalf("inflate: %v", err)
		}
		delivered = out
	}
	if bytes.Equal(delivered, original) {
		t.Fatal("expected the flag loss to corrupt delivery; it did not — the " +
			"compression/flag contract has changed, re-derive the B3 analysis")
	}

	// And the corruption is undetectable by the frame's own invariants: the header
	// length matches the payload, which is what Validate() checks.
	if int(decoded.Length) != len(decoded.Payload) {
		t.Errorf("length/payload mismatch (%d vs %d) — if this ever diverges, B3 "+
			"would at least be detectable by Validate(); it is not today",
			decoded.Length, len(decoded.Payload))
	}
}
