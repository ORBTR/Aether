//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package noise

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Preamble protocol for shared multi-scope transports.
//
// When multiple platform tenants share a single NoiseTransport (UDP port), the
// initiator prepends a preamble to the first handshake message so the responder
// can resolve the correct PSK before the Noise XX handshake begins.
//
// Wire format (prepended to msg1 before the CRC32 fingerprint):
//
//	[2 bytes: magic 0x54 0x50 ("TP")]
//	[2 bytes: scope ID length, big-endian uint16]
//	[N bytes: scope ID string, UTF-8]
//
// The standard CRC32 fingerprint + Noise msg1 follow after the preamble.
//
// Detection: if the first two bytes equal PreambleMagic, a preamble is present.
// Otherwise the packet starts with a raw CRC32 fingerprint (dedicated transport,
// backward-compatible).
//
// Security note: the preamble is unencrypted (it's pre-handshake) but only
// carries the scope identifier — the PSK is never transmitted. A mismatch
// between the preamble's scope ID and the initiator's actual PSK causes the
// Noise prologue to differ, which makes the handshake fail cryptographically.

const (
	// PreambleMagic identifies a preamble-bearing packet ("TP" = Scope Preamble).
	PreambleMagic uint16 = 0x5450

	// PreambleHeaderSize is the fixed overhead before the scope ID bytes.
	PreambleHeaderSize = 4 // 2 magic + 2 length

	// MaxScopeIDLength caps the scope ID to prevent oversized allocations.
	MaxScopeIDLength = 256
)

var (
	ErrPreambleTooShort    = errors.New("preamble: data too short")
	ErrTenantIDTooLong     = errors.New("preamble: scope ID exceeds maximum length")
	ErrTenantIDEmpty       = errors.New("preamble: scope ID is empty")
	ErrPreambleTruncated   = errors.New("preamble: data truncated before scope ID")
)

// EncodePreamble builds the preamble bytes for a given scope ID.
// The caller appends the standard [CRC32][noise_msg1] after the returned bytes.
func EncodePreamble(scopeID string) ([]byte, error) {
	if scopeID == "" {
		return nil, ErrTenantIDEmpty
	}
	if len(scopeID) > MaxScopeIDLength {
		return nil, ErrTenantIDTooLong
	}
	buf := make([]byte, PreambleHeaderSize+len(scopeID))
	binary.BigEndian.PutUint16(buf[0:2], PreambleMagic)
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(scopeID)))
	copy(buf[4:], scopeID)
	return buf, nil
}

// HasPreamble returns true if data starts with the preamble magic bytes.
// Requires at least PreambleHeaderSize bytes.
func HasPreamble(data []byte) bool {
	if len(data) < PreambleHeaderSize {
		return false
	}
	return binary.BigEndian.Uint16(data[0:2]) == PreambleMagic
}

// DecodePreamble extracts the scope ID from a preamble-bearing packet and
// returns the remaining bytes (which start with the CRC32 fingerprint).
// Returns ErrPreambleTooShort if the data is too small to contain a preamble.
func DecodePreamble(data []byte) (scopeID string, rest []byte, err error) {
	if len(data) < PreambleHeaderSize {
		return "", nil, ErrPreambleTooShort
	}

	magic := binary.BigEndian.Uint16(data[0:2])
	if magic != PreambleMagic {
		return "", nil, fmt.Errorf("preamble: invalid magic 0x%04x", magic)
	}

	idLen := int(binary.BigEndian.Uint16(data[2:4]))
	if idLen == 0 {
		return "", nil, ErrTenantIDEmpty
	}
	if idLen > MaxScopeIDLength {
		return "", nil, ErrTenantIDTooLong
	}

	end := PreambleHeaderSize + idLen
	if len(data) < end {
		return "", nil, ErrPreambleTruncated
	}

	scopeID = string(data[PreambleHeaderSize:end])
	rest = data[end:]
	return scopeID, rest, nil
}
