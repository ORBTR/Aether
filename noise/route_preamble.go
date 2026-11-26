//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package noise

import (
	"encoding/binary"
	"errors"

	aether "github.com/ORBTR/aether"
)

// Routing preamble: the WIRE-FORMAT codec and constants of the
// intra-origin noise-UDP forwarder. This file holds only the codec. The
// dialer prepends the preamble in handshake.go and listener_forward.go
// (buildNoiseConnWriteFunc); the anycast-receiving machine reads it in
// listener_forward.go (handleForwarderPacket) and relays to the target
// machine over 6PN with the inner relay protocol and per-flow relay tables
// in inner_relay.go.
//
// The discriminator byte keeps a preambled msg1 distinguishable from one
// sent without a preamble. A receiver without forwarder support passes a
// preambled msg1 through to the normal noise path UNMODIFIED, so a preamble
// naming THIS machine's NodeID still completes the handshake and one naming
// another NodeID fails it.

// Wire format (prepended to noise msg1 before any scope preamble):
//
//	[2 bytes: magic 0x41 0x45 ("AE")]
//	[1 byte : version (0x01)]
//	[1 byte : flags    (reserved, 0x00)]
//	[30 bytes: target NodeID (textual canonical form, "vl1_<26 chars>")]
//
// Total: 34 bytes. The standard noise msg1 (and optional scope preamble)
// follow immediately after. NodeID is the textual canonical form so the
// receiver can compare against its own NodeID string directly without
// reconstructing the SHA-256 fingerprint mapping.
//
// The "AE" magic is distinct from:
//   - the scope preamble magic "TP" (0x5450)
//   - a raw noise msg1 starting with the CRC32 fingerprint (a uint32 whose
//     first byte is the fingerprint MSB — never 0x41, since CRC32 of the
//     network-key set is effectively random)
//   - a Curve25519 ephemeral public key first byte (statistically uniform)
//
// Detection at receive time: peek the first byte. 0x41 → routing preamble;
// 0x54 → scope preamble; anything else → raw msg1.

const (
	// MetadataKeyCrossOriginPreamble is the well-known aether.Target.Metadata
	// key that signals the Noise dialer should prepend a routing preamble
	// (target = the dial Target.NodeID) to msg1 + retransmits + msg3.
	// The value must be "1" (any other value is treated as unset). A dialer
	// sets it when dialing a peer of another origin at its public anycast
	// IPv4 so the receiving machine M_r can forward to the target machine
	// M_t over 6PN. NoiseTransport.Dial reads it in the dialing process; the
	// key itself never goes on the wire, only the preamble it switches on.
	MetadataKeyCrossOriginPreamble = "aether.cross_origin_preamble"

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
	ErrRoutingPreambleTooShort      = errors.New("route-preamble: data too short")
	ErrRoutingPreambleMagicMismatch = errors.New("route-preamble: not a routing preamble")
	ErrRoutingPreambleVersion       = errors.New("route-preamble: unsupported version")
	ErrRoutingPreambleFlags         = errors.New("route-preamble: unknown flag bits set")
)

// EncodeRoutingPreamble builds the 34-byte routing preamble for a given
// target NodeID. The caller prepends the result to outbound msg1.
//
// The NodeID is the canonical textual form ("vl1_<26 chars>" = 30 bytes).
// Encoders MUST pass a normalized NodeID (use aether.NormalizeNodeID or
// NodeID.Canonical() if unsure). Flags is reserved for future use
// (e.g. 0x80 = reply marker).
//
// Returns nil for a NodeID longer than RoutingPreambleNodeIDSize.
// ParseNodeID accepts a documented 52-char form (56 bytes) that is longer
// than 30, so a public-API NodeID value can reach here during a
// cross-origin dial. Truncating would forward to the wrong machine and a
// panic would crash the process; returning nil makes the caller emit the
// packet WITHOUT a routing preamble (degrading to a direct dial). Canonical
// NodeIDs are exactly 30 bytes.
func EncodeRoutingPreamble(target aether.NodeID) []byte {
	if len(target) > RoutingPreambleNodeIDSize {
		dbgNoise.Printf("EncodeRoutingPreamble: NodeID %q exceeds %d bytes — emitting no preamble",
			target.Short(), RoutingPreambleNodeIDSize)
		return nil
	}
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
// machine should see — i.e. the raw msg1 (possibly preceded by a partition
// preamble) with the routing preamble stripped.
//
// Forward-compat: unknown flag bits return ErrRoutingPreambleFlags. A
// future version that defines a new flag must bump RoutingPreambleVersion
// so old decoders reject the packet on the version check first (rather
// than mishandling a flag they don't understand).
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
	// flags = data[3]; every bit is reserved at v0x01, so any non-zero
	// flag byte is an unknown extension that we MUST reject so a future
	// flag-defining version doesn't get silently mishandled by us.
	if data[3] != 0 {
		return "", nil, ErrRoutingPreambleFlags
	}
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
