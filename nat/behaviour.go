//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

// RFC 5780 NAT behaviour discovery.
//
// Uses the full RFC 5780 model: two independent axes (Mapping × Filtering)
// produce a richer NAT type than the Open/FullCone/Symmetric ternary,
// giving the hole-punching layer enough information to pick the right
// strategy.
//
// Mapping behaviour — where does the reflexive address go?
//
//	EIM   Endpoint-Independent Mapping       (Full Cone outer behaviour)
//	ADM   Address-Dependent Mapping
//	APDM  Address+Port Dependent Mapping     (Symmetric)
//
// Filtering behaviour — who can reach the reflexive address?
//
//	EIF   Endpoint-Independent Filtering     (Full Cone)
//	ADF   Address-Dependent Filtering        (Restricted Cone)
//	APDF  Address+Port Dependent Filtering   (Port Restricted)
package nat

import (
	"context"
	"fmt"
	"net"

	aether "github.com/ORBTR/aether"
)

// The RFC 5780 classification is defined in the aether package beside the
// aether.STUNClient seam whose DetectNATBehaviour returns it, so a package that
// takes the seam needs no import of this one; these names keep the strategy
// engine and its callers reading it as nat.NATBehaviour.
type (
	MappingBehaviour   = aether.MappingBehaviour
	FilteringBehaviour = aether.FilteringBehaviour
	NATBehaviour       = aether.NATBehaviour
)

const (
	MappingUnknown              = aether.MappingUnknown
	MappingEndpointIndependent  = aether.MappingEndpointIndependent
	MappingAddressDependent     = aether.MappingAddressDependent
	MappingAddressPortDependent = aether.MappingAddressPortDependent

	FilteringUnknown              = aether.FilteringUnknown
	FilteringEndpointIndependent  = aether.FilteringEndpointIndependent
	FilteringAddressDependent     = aether.FilteringAddressDependent
	FilteringAddressPortDependent = aether.FilteringAddressPortDependent
)

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
