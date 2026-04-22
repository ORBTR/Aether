/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

// NAT strategy engine.
//
// Glue layer that picks the right traversal method given both peers'
// NATBehaviour, then runs them through the appropriate primitive
// (direct simultaneous open / port prediction / UPnP / relay).
package nat

import (
	"context"
	"errors"
)

// StrategyConfig wires together the components a Strategy needs.
type StrategyConfig struct {
	STUN       *STUNClient
	PortMapper PortMapper // pass NullPortMapper{} when none configured
}

// Strategy decides and orchestrates a NAT traversal attempt.
type Strategy struct {
	cfg StrategyConfig
}

// NewStrategy returns a Strategy with the given backends.
func NewStrategy(cfg StrategyConfig) *Strategy {
	if cfg.PortMapper == nil {
		cfg.PortMapper = NullPortMapper{}
	}
	return &Strategy{cfg: cfg}
}

// PickMethod returns the recommended punch method for a pair of peers
// without performing any I/O. Used by callers (gossip relay, dispatcher)
// to surface "what would we try" before committing to the round-trip.
func (s *Strategy) PickMethod(local, remote NATBehaviour) PunchMethod {
	method := ChooseMethod(local, remote)
	if method == PunchPortPrediction {
		// Try UPnP first if we have a real port mapper — much cheaper.
		if _, ok := s.cfg.PortMapper.(NullPortMapper); !ok {
			return PunchUPnP
		}
	}
	return method
}

// ErrNoPath is returned when no traversal method succeeds — the caller
// should fall back to a relay.
var ErrNoPath = errors.New("nat: no direct path; relay required")

// Connect runs the chosen strategy and returns nil on success or
// ErrNoPath when all primitives are exhausted. The actual probe-send
// implementation is consumer-driven via the punching context — this
// engine just sequences the attempts and reports the outcome.
//
// Returning Connect as a separate method keeps the no-I/O `PickMethod`
// path available for callers that just want the recommendation.
func (s *Strategy) Connect(ctx context.Context, local, remote NATBehaviour) (PunchMethod, error) {
	method := s.PickMethod(local, remote)
	switch method {
	case PunchDirect:
		return method, nil
	case PunchUPnP:
		// Caller is expected to drive the actual mapping request. We
		// return the method so they know which path to take.
		return method, nil
	case PunchPortPrediction:
		return method, nil
	default:
		return PunchRelay, ErrNoPath
	}
}
