/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
)

// STUNClient is the seam through which a NAT-traversing host gives the Noise
// transport (noise.NoiseTransportConfig.STUN) and the relay fallback dialer
// (relay.FallbackConfig.STUN) STUN discovery. The packages that use it import no
// STUN implementation, so a host that only dials, such as a client session over
// WebSocket, links no STUN code and no NAT traversal (the nat package, which
// implements this with pion/stun, and pion itself). nat.STUNClient implements it.
//
// BindingRequest and BindingResponse let the Noise transport run a binding
// transaction on its own listener socket, so the reflexive address it learns is
// the one its peers reach: the request's raw bytes with its transaction ID, and,
// from a response the listener demultiplexed as STUN (IsSTUNMessage), the
// transaction ID it answers and the XOR-MAPPED-ADDRESS it carries.
type STUNClient interface {
	Config() STUNConfig
	DiscoverReflexiveAddr(ctx context.Context, localAddr *net.UDPAddr) (*ReflexiveAddress, error)
	DetectNATType(ctx context.Context, localAddr *net.UDPAddr) (NATType, error)
	DetectNATBehaviour(ctx context.Context, localAddr *net.UDPAddr) (NATBehaviour, error)
	BindingRequest() (transactionID [12]byte, raw []byte)
	BindingResponse(raw []byte) (transactionID [12]byte, addr *ReflexiveAddress, err error)
}

// ErrSTUNNotComposed is NewSTUNClient's refusal when no STUN implementation is
// linked into the binary: STUNConfig.Enabled asks for STUN, and the host has
// neither passed a client through its transport's STUN field nor linked the nat
// package, which registers its client (RegisterSTUNClient). A transport refuses to
// construct on it, so a traversing host that forgot to compose STUN fails at start
// and never runs without the discovery it asked for.
var ErrSTUNNotComposed = errors.New("aether: STUN enabled and no STUN client composed")

var stunClientConstructor atomic.Pointer[func(STUNConfig) STUNClient]

// RegisterSTUNClient records the constructor NewSTUNClient calls. The nat package
// calls it when it is linked; a later call replaces an earlier one.
func RegisterSTUNClient(newClient func(STUNConfig) STUNClient) {
	stunClientConstructor.Store(&newClient)
}

// NewSTUNClient builds a STUN client for cfg with the registered constructor, or
// returns ErrSTUNNotComposed when none is registered. The Noise transport and the
// relay fallback dialer call it when their config enables STUN and passes no client.
func NewSTUNClient(cfg STUNConfig) (STUNClient, error) {
	p := stunClientConstructor.Load()
	if p == nil {
		return nil, fmt.Errorf("%w: pass one in the transport's STUN field, or link github.com/ORBTR/aether/nat", ErrSTUNNotComposed)
	}
	return (*p)(cfg), nil
}

// stunMagicCookie is the fixed value at bytes 4 to 8 of every STUN message
// (RFC 5389 section 6); stunHeaderSize is the message header's length.
const (
	stunMagicCookie = 0x2112A442
	stunHeaderSize  = 20
)

// IsSTUNMessage reports whether b can be a STUN message: at least a header long,
// with the magic cookie in place. The Noise listener reads it to tell a STUN
// response from a Noise packet on one socket.
func IsSTUNMessage(b []byte) bool {
	return len(b) >= stunHeaderSize &&
		uint32(b[4])<<24|uint32(b[5])<<16|uint32(b[6])<<8|uint32(b[7]) == stunMagicCookie
}

// MappingBehaviour describes how the NAT assigns a reflexive address (RFC 5780).
type MappingBehaviour int

const (
	MappingUnknown              MappingBehaviour = iota
	MappingEndpointIndependent                   // EIM — same reflexive for all targets
	MappingAddressDependent                      // ADM — changes with target IP
	MappingAddressPortDependent                  // APDM — changes with target IP+port (symmetric)
)

func (m MappingBehaviour) String() string {
	switch m {
	case MappingEndpointIndependent:
		return "endpoint-independent"
	case MappingAddressDependent:
		return "address-dependent"
	case MappingAddressPortDependent:
		return "address-port-dependent"
	default:
		return "unknown"
	}
}

// FilteringBehaviour describes who can reach the reflexive address (RFC 5780).
type FilteringBehaviour int

const (
	FilteringUnknown              FilteringBehaviour = iota
	FilteringEndpointIndependent                     // EIF — anyone can reach
	FilteringAddressDependent                        // ADF — only hosts we've sent to
	FilteringAddressPortDependent                    // APDF — only IP+port we've sent to
)

func (f FilteringBehaviour) String() string {
	switch f {
	case FilteringEndpointIndependent:
		return "endpoint-independent"
	case FilteringAddressDependent:
		return "address-dependent"
	case FilteringAddressPortDependent:
		return "address-port-dependent"
	default:
		return "unknown"
	}
}

// NATBehaviour is the full RFC 5780 classification. It is defined here, beside the
// STUNClient seam whose DetectNATBehaviour returns it; the nat package names it
// nat.NATBehaviour, an alias, for its strategy engine and its callers.
type NATBehaviour struct {
	Mapping   MappingBehaviour
	Filtering FilteringBehaviour
}

// LegacyType maps the RFC 5780 classification to the single-valued
// NATType enum (Open/FullCone/Restricted/PortRestricted/Symmetric)
// that ReflexiveAddress.NATType carries and the STUN detector reports, for
// consumers that key on that one value rather than the mapping/filtering
// pair. Uses the matrix:
//
//	               | EIF              | ADF              | APDF
//	---------------|------------------|------------------|--------------------
//	EIM            | NATFullCone      | NATRestricted    | NATPortRestricted
//	ADM            | NATSymmetric     | NATSymmetric     | NATSymmetric
//	APDM           | NATSymmetric     | NATSymmetric     | NATSymmetric
func (b NATBehaviour) LegacyType() NATType {
	if b.Mapping != MappingEndpointIndependent {
		return NATSymmetric
	}
	switch b.Filtering {
	case FilteringEndpointIndependent:
		return NATFullCone
	case FilteringAddressDependent:
		return NATRestricted
	case FilteringAddressPortDependent:
		return NATPortRestricted
	}
	return NATUnknown
}

// String returns a compact human-readable description.
func (b NATBehaviour) String() string {
	return fmt.Sprintf("mapping=%s filtering=%s", b.Mapping, b.Filtering)
}
