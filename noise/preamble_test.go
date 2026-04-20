//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package noise

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestEncodePreamble(t *testing.T) {
	data, err := EncodePreamble("scope-abcd")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Magic bytes
	if binary.BigEndian.Uint16(data[0:2]) != PreambleMagic {
		t.Errorf("magic = %x, want %x", binary.BigEndian.Uint16(data[0:2]), PreambleMagic)
	}
	// Length
	idLen := binary.BigEndian.Uint16(data[2:4])
	if idLen != 10 {
		t.Errorf("id length = %d, want 10", idLen)
	}
	// Scope ID
	if string(data[4:]) != "scope-abcd" {
		t.Errorf("scope = %q, want %q", string(data[4:]), "scope-abcd")
	}
	// Total size
	if len(data) != PreambleHeaderSize+10 {
		t.Errorf("total size = %d, want %d", len(data), PreambleHeaderSize+10)
	}
}

func TestEncodePreamble_Empty(t *testing.T) {
	_, err := EncodePreamble("")
	if err != ErrTenantIDEmpty {
		t.Fatalf("err = %v, want ErrTenantIDEmpty", err)
	}
}

func TestEncodePreamble_TooLong(t *testing.T) {
	long := strings.Repeat("x", MaxScopeIDLength+1)
	_, err := EncodePreamble(long)
	if err != ErrTenantIDTooLong {
		t.Fatalf("err = %v, want ErrTenantIDTooLong", err)
	}
}

func TestDecodePreamble_Roundtrip(t *testing.T) {
	original := "my-scope-42"
	encoded, err := EncodePreamble(original)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Append some trailing data (simulating CRC32 + noise msg)
	trailing := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02}
	packet := append(encoded, trailing...)

	scopeID, rest, err := DecodePreamble(packet)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if scopeID != original {
		t.Errorf("scopeID = %q, want %q", scopeID, original)
	}
	if len(rest) != len(trailing) {
		t.Errorf("rest length = %d, want %d", len(rest), len(trailing))
	}
	for i, b := range rest {
		if b != trailing[i] {
			t.Errorf("rest[%d] = %x, want %x", i, b, trailing[i])
		}
	}
}

func TestDecodePreamble_TooShort(t *testing.T) {
	_, _, err := DecodePreamble([]byte{0x54})
	if err != ErrPreambleTooShort {
		t.Fatalf("err = %v, want ErrPreambleTooShort", err)
	}
}

func TestDecodePreamble_InvalidMagic(t *testing.T) {
	data := []byte{0xFF, 0xFF, 0x00, 0x02, 'A', 'B'}
	_, _, err := DecodePreamble(data)
	if err == nil {
		t.Fatal("expected error for invalid magic")
	}
}

func TestDecodePreamble_Truncated(t *testing.T) {
	// Magic OK, length says 10 bytes, but only 3 bytes follow
	data := make([]byte, PreambleHeaderSize+3)
	binary.BigEndian.PutUint16(data[0:2], PreambleMagic)
	binary.BigEndian.PutUint16(data[2:4], 10)
	copy(data[4:], "abc")

	_, _, err := DecodePreamble(data)
	if err != ErrPreambleTruncated {
		t.Fatalf("err = %v, want ErrPreambleTruncated", err)
	}
}

func TestHasPreamble_True(t *testing.T) {
	data, _ := EncodePreamble("test")
	if !HasPreamble(data) {
		t.Error("expected HasPreamble=true for valid preamble")
	}
}

func TestHasPreamble_False_NoPreamble(t *testing.T) {
	// Simulate a CRC32 fingerprint packet (no preamble)
	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data[:4], 0xDEADBEEF)
	if HasPreamble(data) {
		t.Error("expected HasPreamble=false for CRC32-only packet")
	}
}

func TestHasPreamble_False_TooShort(t *testing.T) {
	if HasPreamble([]byte{0x54}) {
		t.Error("expected HasPreamble=false for 1-byte data")
	}
}

func TestEncodePreamble_MaxLength(t *testing.T) {
	id := strings.Repeat("x", MaxScopeIDLength)
	data, err := EncodePreamble(id)
	if err != nil {
		t.Fatalf("encode max length: %v", err)
	}
	if len(data) != PreambleHeaderSize+MaxScopeIDLength {
		t.Errorf("size = %d, want %d", len(data), PreambleHeaderSize+MaxScopeIDLength)
	}
	// Verify roundtrip
	decoded, _, err := DecodePreamble(data)
	if err != nil {
		t.Fatalf("decode max length: %v", err)
	}
	if decoded != id {
		t.Error("max length roundtrip mismatch")
	}
}
