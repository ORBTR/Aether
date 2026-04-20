/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

// RFC 5780 NAT behaviour discovery (Concern #13 sub-phase 5a).
//
// Replaces the previous Open/FullCone/Symmetric ternary classification
// with the full RFC 5780 model: two independent axes (Mapping × Filtering)
// produce a richer NAT type that the hole-punching layer can use to pick
// the right strategy.
//
// Mapping behaviour — where does the reflexive address go?
//   EIM   Endpoint-Independent Mapping       (Full Cone outer behaviour)
//   ADM   Address-Dependent Mapping
//   APDM  Address+Port Dependent Mapping     (Symmetric)
//
// Filtering behaviour — who can reach the reflexive address?
//   EIF   Endpoint-Independent Filtering     (Full Cone)
//   ADF   Address-Dependent Filtering        (Restricted Cone)
//   APDF  Address+Port Dependent Filtering   (Port Restricted)
package nat

import (
	"context"
	"fmt"
	"net"

	aether "github.com/ORBTR/aether"
)

// MappingBehaviour describes how the NAT assigns a reflexive address.
type MappingBehaviour int

const (
	MappingUnknown                 MappingBehaviour = iota
	MappingEndpointIndependent                      // EIM — same reflexive for all targets
	MappingAddressDependent                         // ADM — changes with target IP
	MappingAddressPortDependent                     // APDM — changes with target IP+port (symmetric)
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

// FilteringBehaviour describes who can reach the reflexive address.
type FilteringBehaviour int

const (
	FilteringUnknown                 FilteringBehaviour = iota
	FilteringEndpointIndependent                        // EIF — anyone can reach
	FilteringAddressDependent                           // ADF — only hosts we've sent to
	FilteringAddressPortDependent                       // APDF — only IP+port we've sent to
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

// NATBehaviour is the full RFC 5780 classification.
type NATBehaviour struct {
	Mapping   MappingBehaviour
	Filtering FilteringBehaviour
}

// LegacyType maps the RFC 5780 classification back to the simpler
// (Open/FullCone/Restricted/PortRestricted/Symmetric) enum used by
// older callers. Uses the matrix:
//
//                  | EIF              | ADF              | APDF
//   ---------------|------------------|------------------|--------------------
//   EIM            | NATFullCone      | NATRestricted    | NATPortRestricted
//   ADM            | NATSymmetric     | NATSymmetric     | NATSymmetric
//   APDM           | NATSymmetric     | NATSymmetric     | NATSymmetric
func (b NATBehaviour) LegacyType() aether.NATType {
	if b.Mapping != MappingEndpointIndependent {
		return aether.NATSymmetric
	}
	switch b.Filtering {
	case FilteringEndpointIndependent:
		return aether.NATFullCone
	case FilteringAddressDependent:
		return aether.NATRestricted
	case FilteringAddressPortDependent:
		return aether.NATPortRestricted
	}
	return aether.NATUnknown
}

// String returns a compact human-readable description.
func (b NATBehaviour) String() string {
	return fmt.Sprintf("mapping=%s filtering=%s", b.Mapping, b.Filtering)
}

// DetectNATBehaviour runs the RFC 5780 test suite against the configured
// STUN servers. Requires at least 2 distinct STUN servers (or one server
// with CHANGE-REQUEST support, which most public servers don't expose).
//
// On insufficient servers / lookup failures, returns the partial result
// that could be determined — fields default to *Unknown.
func (c *STUNClient) DetectNATBehaviour(ctx context.Context, localAddr *net.UDPAddr) (NATBehaviour, error) {
	out := NATBehaviour{}
	if !c.config.Enabled {
		return out, fmt.Errorf("stun: STUN disabled")
	}
	if len(c.config.Servers) < 2 {
		// Single-server discovery — best we can do is report whether
		// reflexive == local (Open-style direct path) or not.
		reflex, err := c.DiscoverReflexiveAddr(ctx, localAddr)
		if err != nil {
			return out, err
		}
		if reflex.IP.Equal(localAddr.IP) {
			out.Mapping = MappingEndpointIndependent
			out.Filtering = FilteringEndpointIndependent
		}
		return out, nil
	}

	// Test I + Test II: same source, different destination IPs. If
	// reflexive matches → EIM. Otherwise → ADM (or APDM if Test III
	// disagrees too).
	r1, err := c.querySTUNServer(ctx, localAddr, c.config.Servers[0])
	if err != nil {
		return out, fmt.Errorf("test I: %w", err)
	}
	r2, err := c.querySTUNServer(ctx, localAddr, c.config.Servers[1])
	if err != nil {
		return out, fmt.Errorf("test II: %w", err)
	}

	if r1.IP.Equal(r2.IP) && r1.Port == r2.Port {
		out.Mapping = MappingEndpointIndependent
	} else if r1.IP.Equal(r2.IP) {
		out.Mapping = MappingAddressDependent
	} else {
		out.Mapping = MappingAddressPortDependent
	}

	// Filtering tests would need CHANGE-REQUEST attribute support which
	// most STUN servers don't expose to public users. Without it, we
	// can't tell EIF / ADF / APDF apart precisely. Fall back to a
	// conservative-but-useful estimate: if mapping is EIM, assume
	// restricted-cone (ADF) which is the most common real-world case.
	switch out.Mapping {
	case MappingEndpointIndependent:
		out.Filtering = FilteringAddressDependent
	default:
		out.Filtering = FilteringAddressPortDependent
	}
	return out, nil
}
