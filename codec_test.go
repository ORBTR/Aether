/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package aether

import (
	"bytes"
	"testing"
)

// TestEncodeDecodeFrame_RoundTrip ensures every well-formed frame
// round-trips through EncodeFrame / DecodeFrame without data loss.
func TestEncodeDecodeFrame_RoundTrip(t *testing.T) {
	cases := []struct {
		name  string
		frame Frame
	}{
		{"data-small", Frame{
			StreamID: 42, Type: TypeDATA, SeqNo: 10,
			Length: 5, Payload: []byte("hello"),
		}},
		{"data-empty", Frame{
			StreamID: 1, Type: TypeDATA, SeqNo: 0,
		}},
		{"ack-composite", Frame{
			StreamID: 1, Type: TypeACK, Flags: FlagCOMPOSITE_ACK,
			AckNo: 100,
			Length: 4, Payload: []byte{0, 0, 0, 100},
		}},
		{"open", Frame{
			StreamID: 99, Type: TypeOPEN,
			Length: 10, Payload: make([]byte, 10),
		}},
		{"close", Frame{StreamID: 7, Type: TypeCLOSE}},
		{"reset", Frame{
			StreamID: 7, Type: TypeRESET,
			Length: 4, Payload: []byte{0, 0, 0, 1},
		}},
		{"ping", Frame{StreamID: 2, Type: TypePING, SeqNo: 123}},
		{"pong", Frame{StreamID: 2, Type: TypePONG, SeqNo: 123}},
		{"goaway", Frame{
			StreamID: 0, Type: TypeGOAWAY,
			Length: 8, Payload: []byte{0, 0, 0, 0, 'b', 'y', 'e', 0},
		}},
		{"encrypted-flag", Frame{
			StreamID: 1, Type: TypeDATA, SeqNo: 5,
			Flags: FlagENCRYPTED,
			Nonce: Nonce{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
			Length: 3, Payload: []byte{0x01, 0x02, 0x03},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			n, err := EncodeFrame(&buf, &c.frame)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if n != int(HeaderSize)+int(c.frame.Length) {
				t.Fatalf("bytes written: got %d want %d", n, HeaderSize+int(c.frame.Length))
			}
			decoded, err := DecodeFrame(&buf)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if decoded.Type != c.frame.Type {
				t.Errorf("Type: got %v want %v", decoded.Type, c.frame.Type)
			}
			if decoded.StreamID != c.frame.StreamID {
				t.Errorf("StreamID: got %d want %d", decoded.StreamID, c.frame.StreamID)
			}
			if decoded.SeqNo != c.frame.SeqNo {
				t.Errorf("SeqNo: got %d want %d", decoded.SeqNo, c.frame.SeqNo)
			}
			if decoded.AckNo != c.frame.AckNo {
				t.Errorf("AckNo: got %d want %d", decoded.AckNo, c.frame.AckNo)
			}
			if decoded.Flags != c.frame.Flags {
				t.Errorf("Flags: got %v want %v", decoded.Flags, c.frame.Flags)
			}
			if decoded.Length != c.frame.Length {
				t.Errorf("Length: got %d want %d", decoded.Length, c.frame.Length)
			}
			if !bytes.Equal(decoded.Payload[:decoded.Length], c.frame.Payload[:c.frame.Length]) {
				t.Errorf("Payload: got %x want %x", decoded.Payload[:decoded.Length], c.frame.Payload[:c.frame.Length])
			}
		})
	}
}

// TestDecodeFrame_RejectsOversizedPayload ensures the decoder rejects
// a length field exceeding MaxPayloadSize before allocating.
func TestDecodeFrame_RejectsOversizedPayload(t *testing.T) {
	var buf bytes.Buffer
	// Build a header with Length = MaxPayloadSize + 1.
	var hdr [HeaderSize]byte
	hdr[24] = byte(TypeDATA)
	// Length at offset 34 (big-endian uint32) — cast through uint32 so
	// the shift works even though MaxPayloadSize > 255.
	bogus := uint32(MaxPayloadSize + 1)
	hdr[34] = byte(bogus >> 24)
	hdr[35] = byte(bogus >> 16)
	hdr[36] = byte(bogus >> 8)
	hdr[37] = byte(bogus)
	buf.Write(hdr[:])

	_, err := DecodeFrame(&buf)
	if err == nil {
		t.Fatal("expected oversize rejection")
	}
}

// TestEncodeDecodeCompositeACK_RoundTrip covers the ACK v2 format with
// all extension bits: the caps defense (see _SECURITY.md §3.2), ECN,
// and the window-credit piggyback extension.
func TestEncodeDecodeCompositeACK_RoundTrip(t *testing.T) {
	ack := &CompositeACK{
		BaseACK:  1000,
		AckDelay: 42,
		Bitmap:   make([]byte, 8),
		Flags:    CACKHasExtRanges | CACKHasDropped | CACKHasLossDensity | CACKHasECN | CACKHasGaps | CACKHasWindowCredit,
		ExtRanges: []SACKBlock{
			{Start: 2000, End: 2005},
			{Start: 3000, End: 3100},
		},
		DroppedRanges: []SACKBlock{
			{Start: 500, End: 510},
		},
		LossRate:     1234,
		CEBytes:      4096,
		WindowCredit: 8_388_608, // 8 MB cumulative grant
	}
	ack.Bitmap[0] = 0b10101010
	ack.Bitmap[4] = 0b01010101

	encoded := EncodeCompositeACK(ack)
	decoded := DecodeCompositeACK(encoded)
	if decoded == nil {
		t.Fatal("decode returned nil")
	}

	if decoded.BaseACK != ack.BaseACK {
		t.Errorf("BaseACK: got %d want %d", decoded.BaseACK, ack.BaseACK)
	}
	if decoded.AckDelay != ack.AckDelay {
		t.Errorf("AckDelay: got %d want %d", decoded.AckDelay, ack.AckDelay)
	}
	if !bytes.Equal(decoded.Bitmap, ack.Bitmap) {
		t.Errorf("Bitmap mismatch: got %x want %x", decoded.Bitmap, ack.Bitmap)
	}
	if decoded.Flags != ack.Flags {
		t.Errorf("Flags: got %v want %v", decoded.Flags, ack.Flags)
	}
	if len(decoded.ExtRanges) != len(ack.ExtRanges) {
		t.Errorf("ExtRanges: got %d want %d", len(decoded.ExtRanges), len(ack.ExtRanges))
	}
	if len(decoded.DroppedRanges) != len(ack.DroppedRanges) {
		t.Errorf("DroppedRanges: got %d want %d", len(decoded.DroppedRanges), len(ack.DroppedRanges))
	}
	if decoded.LossRate != ack.LossRate {
		t.Errorf("LossRate: got %d want %d", decoded.LossRate, ack.LossRate)
	}
	if decoded.CEBytes != ack.CEBytes {
		t.Errorf("CEBytes: got %d want %d (ECN round-trip)", decoded.CEBytes, ack.CEBytes)
	}
	if decoded.WindowCredit != ack.WindowCredit {
		t.Errorf("WindowCredit round-trip: got %d want %d", decoded.WindowCredit, ack.WindowCredit)
	}
}

// Round-trip with only the window-credit flag set — isolates the
// extension from other extension bits so a decode-order bug specific to
// the window-credit path can be pinned precisely.
func TestCompositeACK_WithWindowCredit_RoundTripIsolated(t *testing.T) {
	ack := &CompositeACK{
		BaseACK:      500,
		AckDelay:     10,
		Flags:        CACKHasWindowCredit,
		WindowCredit: 1_234_567_890,
	}
	decoded := DecodeCompositeACK(EncodeCompositeACK(ack))
	if decoded == nil {
		t.Fatal("decode returned nil")
	}
	if decoded.WindowCredit != ack.WindowCredit {
		t.Errorf("isolated WindowCredit round-trip: got %d want %d",
			decoded.WindowCredit, ack.WindowCredit)
	}
	if decoded.Flags&CACKHasWindowCredit == 0 {
		t.Error("CACKHasWindowCredit flag missing after round-trip")
	}
}

// When the window-credit flag is NOT set, WindowCredit must stay zero
// on decode. This is the boundary test that catches an unguarded 8-byte
// read path where the decoder could consume stream bytes belonging to a
// later frame because it ignores the flag.
func TestCompositeACK_WithoutWindowCredit_StaysZero(t *testing.T) {
	ack := &CompositeACK{
		BaseACK:  500,
		AckDelay: 10,
		Flags:    0, // no extensions
	}
	decoded := DecodeCompositeACK(EncodeCompositeACK(ack))
	if decoded == nil {
		t.Fatal("decode returned nil")
	}
	if decoded.WindowCredit != 0 {
		t.Errorf("WindowCredit should be 0 when flag not set, got %d", decoded.WindowCredit)
	}
}

// TestDecodeCompositeACK_Truncated should return nil on too-short input.
func TestDecodeCompositeACK_Truncated(t *testing.T) {
	// Shorter than CompositeACKMinSize (8)
	if got := DecodeCompositeACK(make([]byte, 4)); got != nil {
		t.Errorf("expected nil for truncated input, got %+v", got)
	}
}

// TestEncodeDecodePriority_RoundTrip covers the PRIORITY payload codec.
func TestEncodeDecodePriority_RoundTrip(t *testing.T) {
	p := PriorityPayload{Weight: 200, Dependency: 0xDEADBEEF}
	encoded := EncodePriority(p)
	if len(encoded) != PriorityPayloadSize {
		t.Fatalf("encoded size: got %d want %d", len(encoded), PriorityPayloadSize)
	}
	decoded := DecodePriority(encoded)
	if decoded.Weight != p.Weight {
		t.Errorf("Weight: got %d want %d", decoded.Weight, p.Weight)
	}
	if decoded.Dependency != p.Dependency {
		t.Errorf("Dependency: got %x want %x", decoded.Dependency, p.Dependency)
	}
}

func TestEncodeDecodeOpenPayload_RoundTrip(t *testing.T) {
	o := OpenPayload{Reliability: ReliableUnordered, Priority: 128, Dependency: 42}
	encoded := EncodeOpenPayload(o)
	if len(encoded) != OpenPayloadSize {
		t.Fatalf("encoded size: got %d want %d", len(encoded), OpenPayloadSize)
	}
	decoded := DecodeOpenPayload(encoded)
	if decoded != o {
		t.Errorf("round-trip: got %+v want %+v", decoded, o)
	}
}

func TestEncodeDecodeGoAway_RoundTrip(t *testing.T) {
	encoded := EncodeGoAway(GoAwayMigration, "moving to better path")
	reason, msg := DecodeGoAway(encoded)
	if reason != GoAwayMigration {
		t.Errorf("reason: got %v want %v", reason, GoAwayMigration)
	}
	if msg != "moving to better path" {
		t.Errorf("message: got %q want %q", msg, "moving to better path")
	}
}

func TestEncodeDecodeReset_RoundTrip(t *testing.T) {
	for _, r := range []ResetReason{ResetCancel, ResetRefused, ResetInternal, ResetFlowCtrl, ResetTimeout} {
		encoded := EncodeReset(r)
		if len(encoded) != ResetPayloadSize {
			t.Fatalf("encoded size: %d", len(encoded))
		}
		if got := DecodeReset(encoded); got != r {
			t.Errorf("round-trip: got %v want %v", got, r)
		}
	}
}

func TestEncodeDecodeWindowUpdate_RoundTrip(t *testing.T) {
	encoded := EncodeWindowUpdate(65536)
	if got := DecodeWindowUpdate(encoded); got != 65536 {
		t.Errorf("round-trip: got %d want 65536", got)
	}
}

func TestEncodeDecodeFECHeader_RoundTrip(t *testing.T) {
	h := FECHeader{GroupID: 0xCAFEBABE, Index: 5, Total: 10}
	encoded := EncodeFECHeader(h)
	if len(encoded) != FECHeaderSize {
		t.Fatalf("encoded size: %d", len(encoded))
	}
	if got := DecodeFECHeader(encoded); got != h {
		t.Errorf("round-trip: got %+v want %+v", got, h)
	}
}

// TestPayloadPool_ReturnsBufferOfCorrectSize sanity-checks the pooled
// buffer allocator used by DecodeFrame.
func TestPayloadPool_ReturnsBufferOfCorrectSize(t *testing.T) {
	buf := GetPayloadBuf(1024)
	if len(buf) != 1024 {
		t.Errorf("length: got %d want 1024", len(buf))
	}
	PutPayloadBuf(buf)
	// Oversized buffers should not be pooled.
	oversized := make([]byte, 512*1024)
	PutPayloadBuf(oversized) // must not panic
}

// TestFrameValidate catches structural errors.
func TestFrameValidate(t *testing.T) {
	// Valid frame — small payload, no encryption flag.
	f := &Frame{Type: TypeDATA, Length: 3, Payload: []byte{1, 2, 3}}
	if err := f.Validate(); err != nil {
		t.Errorf("valid frame rejected: %v", err)
	}
	// Length mismatch — header says 10 but payload is 3.
	bad := &Frame{Type: TypeDATA, Length: 10, Payload: []byte{1, 2, 3}}
	if err := bad.Validate(); err == nil {
		t.Error("length mismatch not detected")
	}
	// ENCRYPTED flag with zero nonce.
	encNoNonce := &Frame{Type: TypeDATA, Flags: FlagENCRYPTED, Length: 3, Payload: []byte{1, 2, 3}}
	if err := encNoNonce.Validate(); err == nil {
		t.Error("ENCRYPTED flag with zero nonce not detected")
	}
	// Oversize payload.
	oversize := &Frame{Type: TypeDATA, Length: MaxPayloadSize + 1}
	if err := oversize.Validate(); err == nil {
		t.Error("oversized payload not detected")
	}
	// Invalid frame type.
	invalid := &Frame{Type: FrameType(0xFF), Length: 0}
	if err := invalid.Validate(); err == nil {
		t.Error("invalid frame type not detected")
	}
}
