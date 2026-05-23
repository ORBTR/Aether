//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package noise

import (
	"encoding/binary"
	"errors"

	aether "github.com/ORBTR/aether"
)

// Routing preamble — scaffold for the intra-org noise-UDP forwarder.
//
// SCOPE: this file currently provides the WIRE-FORMAT codec and constants.
// The forwarder logic (listener-side branching, inner relay protocol between
// the anycast-receiving machine and the target machine over 6PN, per-flow
// relay table) is documented in
// HSTLES/Library/docs/superpowers/plans/2026-05-23-cross-org-anycast-forwarder.md
// and intentionally NOT shipped here — it requires sustained design + test
// + staged rollout work that warrants its own focused session.
//
// What this scaffold buys: the wire format is fixed now, so a dialer
// upgraded later can emit preambled msg1 packets and have them be
// distinguishable from legacy msg1 by the discriminator byte. Receivers
// without forwarder support pass preambled msg1 through to the normal
// noise path UNMODIFIED, which means a forwarded preamble for THIS
// machine's NodeID works correctly the moment the rest of the listener
// logic is wired (and a preamble for a non-local NodeID just fails the
// handshake — graceful degradation).

// Wire format (prepended to noise msg1 before any TenantPreamble):
//
//	[2 bytes: magic 0x41 0x45 ("AE")]
//	[1 byte : version (0x01)]
//	[1 byte : flags    (reserved, 0x00)]
//	[30 bytes: target NodeID (textual canonical form, "vl1_<26 chars>")]
//
// Total: 34 bytes. The standard noise msg1 (and optional TenantPreamble)
// follow immediately after. NodeID is the textual canonical form so the
// receiver can compare against its own NodeID string directly without
// reconstructing the SHA-256 fingerprint mapping.
//
// The "AE" magic is distinct from:
//   - the tenant-scope preamble magic "TP" (0x5450)
//   - a raw noise msg1 starting with the CRC32 fingerprint (a uint32 whose
//     first byte is the fingerprint MSB — never 0x41, since CRC32 of the
//     network-key set is effectively random)
//   - a Curve25519 ephemeral public key first byte (statistically uniform)
//
// Detection at receive time: peek the first byte. 0x41 → routing preamble;
// 0x54 → tenant preamble; anything else → raw msg1.

const (
	// RoutingPreambleMagic identifies a routing-preamble-bearing packet
	// ("AE" = AEther routing).
	RoutingPreambleMagic uint16 = 0x4145

	// RoutingPreambleVersion is the current wire-format version. Bumped
	// only if the framing changes; the version is 0x01 from launch.
	RoutingPreambleVersion uint8 = 0x01

	// RoutingPreambleNodeIDSize is the byte length of the textual NodeID
	// field. Matches NodeID's canonical 30-char form ("vl1_" + 26 base32
	// chars). Fixed-width so the decoder can split the wire deterministically.
	RoutingPreambleNodeIDSize = 30

	// RoutingPreambleSize is the fixed total size of the preamble.
	RoutingPreambleSize = 2 + 1 + 1 + RoutingPreambleNodeIDSize // 34 bytes
)

var (
	ErrRoutingPreambleTooShort       = errors.New("route-preamble: data too short")
	ErrRoutingPreambleMagicMismatch  = errors.New("route-preamble: not a routing preamble")
	ErrRoutingPreambleVersion        = errors.New("route-preamble: unsupported version")
)

// EncodeRoutingPreamble builds the 34-byte routing preamble for a given
// target NodeID. The caller prepends the result to outbound msg1.
//
// The NodeID is the canonical textual form ("vl1_<26 chars>" = 30 bytes).
// Encoders MUST pass a normalized NodeID (use aether.NormalizeNodeID or
// NodeID.Canonical() if unsure); we copy what we're given. Flags is
// reserved for future use (e.g. 0x80 = reply marker).
func EncodeRoutingPreamble(target aether.NodeID) []byte {
	out := make([]byte, RoutingPreambleSize)
	binary.BigEndian.PutUint16(out[0:2], RoutingPreambleMagic)
	out[2] = RoutingPreambleVersion
	out[3] = 0x00 // flags reserved
	// Right-pad with NUL if the NodeID is shorter than the fixed width.
	// The canonical form is exactly RoutingPreambleNodeIDSize bytes so
	// this is normally a tight copy.
	copy(out[4:4+RoutingPreambleNodeIDSize], []byte(target))
	return out
}

// IsRoutingPreamble reports whether data starts with the routing-preamble
// magic. Cheap discriminator — call before DecodeRoutingPreamble to avoid
// the full validation cost on every packet.
func IsRoutingPreamble(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	return binary.BigEndian.Uint16(data[0:2]) == RoutingPreambleMagic
}

// DecodeRoutingPreamble parses the preamble and returns (target NodeID,
// remaining bytes, error). The remaining bytes are what the noise state
// machine should see — i.e. the raw msg1 (possibly preceded by a tenant
// preamble) with the routing preamble stripped.
func DecodeRoutingPreamble(data []byte) (aether.NodeID, []byte, error) {
	if len(data) < RoutingPreambleSize {
		return "", nil, ErrRoutingPreambleTooShort
	}
	if binary.BigEndian.Uint16(data[0:2]) != RoutingPreambleMagic {
		return "", nil, ErrRoutingPreambleMagicMismatch
	}
	if data[2] != RoutingPreambleVersion {
		return "", nil, ErrRoutingPreambleVersion
	}
	// flags = data[3]; reserved, not consumed yet.
	// Trim any trailing NUL padding (encoder right-pads if the NodeID is
	// shorter than the fixed width — rare, but defensive).
	raw := data[4 : 4+RoutingPreambleNodeIDSize]
	end := len(raw)
	for end > 0 && raw[end-1] == 0 {
		end--
	}
	target := aether.NodeID(string(raw[:end]))
	return target, data[RoutingPreambleSize:], nil
}
