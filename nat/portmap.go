/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

// UPnP / NAT-PMP / PCP port mapping interface.
//
// The interface is defined here; concrete implementations live in build-
// tagged files because they pull in OS-specific protocol libraries.
// Aether ships with a no-op `nullPortMapper` so callers can always wire
// the strategy engine; production deployments inject a real mapper.
package nat

import (
	"context"
	"errors"
	"time"
)

// MappingRequest describes a port-mapping request.
type MappingRequest struct {
	Protocol     string        // "udp" or "tcp"
	InternalPort int
	ExternalPort int           // 0 = let gateway pick
	TTL          time.Duration // mapping lifetime
	Description  string        // human-readable label, e.g. "aether-mesh"
}

// MappingResult is what the gateway gave us.
type MappingResult struct {
	Protocol     string
	InternalPort int
	ExternalPort int
	ExternalIP   string
	Expires      time.Time
}

// Gateway describes a discovered NAT gateway.
type Gateway struct {
	URL      string // for UPnP, the control URL
	Protocol string // "upnp" / "nat-pmp" / "pcp"
	LocalIP  string
}

// PortMapper is the abstract NAT port-mapping API. Implementations should
// try PCP → NAT-PMP → UPnP IGD in preference order on Discover.
type PortMapper interface {
	// Discover finds the local NAT gateway and returns its descriptor.
	Discover(ctx context.Context) (*Gateway, error)
	// RequestMapping opens an external port. ExternalPort=0 means
	// "any" — gateway returns the assigned port.
	RequestMapping(ctx context.Context, req MappingRequest) (*MappingResult, error)
	// ReleaseMapping closes a previously-opened port.
	ReleaseMapping(ctx context.Context, mapping *MappingResult) error
}

// ErrNoGateway is returned when no UPnP/NAT-PMP/PCP gateway responds.
var ErrNoGateway = errors.New("nat: no port-mapping gateway found")

// NullPortMapper is a no-op fallback used when the operator hasn't
// configured a real mapper. Discover always returns ErrNoGateway.
type NullPortMapper struct{}

func (NullPortMapper) Discover(_ context.Context) (*Gateway, error) {
	return nil, ErrNoGateway
}

func (NullPortMapper) RequestMapping(_ context.Context, _ MappingRequest) (*MappingResult, error) {
	return nil, ErrNoGateway
}

func (NullPortMapper) ReleaseMapping(_ context.Context, _ *MappingResult) error {
	return nil
}
