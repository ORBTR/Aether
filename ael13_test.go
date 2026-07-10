/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import (
	"bytes"
	"testing"
)

// TestAEL13_ControlShortIs8BytesAndRoundTripsSeqNo is the AE-L-13 capability
// lock. Control-short (0x83) is 8 bytes on the wire — [indicator:1][type:1]
// [streamID:2][seqNo:4] — and the SeqNo round-trips so PING<->PONG RTT
// correlation can feed the RFC 6298 estimator. An earlier spec revision
// (and stale banner) claimed 4 bytes with "no SeqNo"; anyone "fixing" the
// code down to 4 bytes to match would drop SeqNo, freeze the RTO estimator
// at its InitialRTO seed, and misframe every subsequent frame. This guard
// fails loudly if the wire size or SeqNo carriage is reduced.
func TestAEL13_ControlShortIs8BytesAndRoundTripsSeqNo(t *testing.T) {
	// (1) The constant must remain 8 bytes.
	if ShortControlSize != 8 {
		t.Fatalf("AE-L-13: ShortControlSize = %d, want 8 (control-short must carry SeqNo)", ShortControlSize)
	}

	// (2) Encode writes exactly 8 bytes.
	const wantSeqNo uint32 = 0x01020304
	f := &Frame{StreamID: 7, Type: TypePING, SeqNo: wantSeqNo}
	c := NewCompressor()
	var buf bytes.Buffer
	n, err := c.EncodeControlShort(&buf, f)
	if err != nil {
		t.Fatalf("AE-L-13: EncodeControlShort error: %v", err)
	}
	if n != 8 {
		t.Fatalf("AE-L-13: EncodeControlShort wrote %d bytes, want 8", n)
	}
	if buf.Len() != 8 {
		t.Fatalf("AE-L-13: buffer holds %d bytes after encode, want 8", buf.Len())
	}

	// (3) Append a sentinel so under/over-consumption is detectable.
	ael13Sentinel := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	buf.Write(ael13Sentinel)

	// (4) Consume the indicator byte (as the frame reader does), then decode.
	if _, err := buf.ReadByte(); err != nil {
		t.Fatalf("AE-L-13: reading indicator byte: %v", err)
	}
	dc := NewCompressor()
	got, err := dc.DecodeControlShort(&buf)
	if err != nil {
		t.Fatalf("AE-L-13: DecodeControlShort error: %v", err)
	}
	if got.Type != TypePING {
		t.Errorf("AE-L-13: decoded Type = %#x, want TypePING (%#x)", got.Type, TypePING)
	}
	if got.StreamID != 7 {
		t.Errorf("AE-L-13: decoded StreamID = %d, want 7", got.StreamID)
	}
	// The whole point of 8 bytes: SeqNo survives the round trip.
	if got.SeqNo != wantSeqNo {
		t.Errorf("AE-L-13: decoded SeqNo = %#x, want %#x (RTT-correlation capability lost)", got.SeqNo, wantSeqNo)
	}

	// (5) Decode consumed exactly the 7 post-indicator bytes; the sentinel
	// (and only the sentinel) remains — no over/under-consumption / desync.
	if buf.Len() != 4 {
		t.Fatalf("AE-L-13: %d bytes remain after decode, want 4 (control-short misframed)", buf.Len())
	}
	if !bytes.Equal(buf.Bytes(), ael13Sentinel) {
		t.Errorf("AE-L-13: trailing bytes = % x, want sentinel % x", buf.Bytes(), ael13Sentinel)
	}
}
