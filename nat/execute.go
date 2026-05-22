/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

// Coordinated hole-punch execution.
//
// holepunch.go defines the signed PunchRequest/PunchOffer payloads and
// method selection; this file is the synchronized execution that
// consumes them. It is transport-agnostic — the caller injects a DialFunc
// (initiator half) or a ProbeFunc (responder half) — so the same
// execution logic serves any mesh: the HSTLES endpoint fleet and the
// ORBTR agent both drive it, each supplying its own dial/probe wiring.
//
// The mechanism is a true simultaneous open. Both peers derive the same
// fire time T0 from the request, then at T0:
//   - the initiator runs ExecutePunch — a full Noise dial at every
//     offered candidate, as the sole handshake initiator;
//   - the responder runs ExecuteProbe — a PunchProbe at every requester
//     candidate, opening its NAT mapping without a handshake, and lets
//     its always-running listener accept the initiator's inbound dial.
// This resolves the asymmetric Noise XX role problem: exactly one side
// initiates, both NATs open at once.
package nat

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	aether "github.com/ORBTR/aether"
)

const (
	// PunchLeadTime is how far past a PunchRequest's Timestamp the
	// synchronized fire time T0 sits. It must exceed the request's
	// one-way signaling latency plus the clock skew between the two
	// hosts — NTP-synced hosts are typically within a few ms, and
	// aether's Noise msg1 retransmit absorbs the residual jitter.
	PunchLeadTime = 750 * time.Millisecond

	// MaxPunchCandidates caps the simultaneous-dial fan-out so a wide
	// port-prediction set cannot spawn hundreds of concurrent handshakes.
	MaxPunchCandidates = 64
)

// PunchFireTime derives the synchronized dial instant T0 from a request.
// Both peers compute it from the same PunchRequest, so they agree on
// when to fire without a clock-synced handshake.
func PunchFireTime(req *PunchRequest) time.Time {
	return time.Unix(0, req.Timestamp).Add(PunchLeadTime)
}

// DialFunc dials a single candidate address as a Noise-UDP target,
// returning the established connection. It is the initiator-half
// injection point — the caller binds it to its own transport and the
// peer's NodeID.
type DialFunc func(ctx context.Context, addr net.UDPAddr) (aether.Connection, error)

// ProbeFunc opens the local NAT/firewall mapping toward a candidate
// address without completing a handshake. NoiseTransport.PunchProbe,
// adapted to a by-value address, satisfies it. It is the responder-half
// injection point.
type ProbeFunc func(ctx context.Context, addr net.UDPAddr) error

// PunchResult carries the outcome of an ExecutePunch attempt. A nil Conn
// with NotViable set means the chosen method has no implementation for
// this mesh (PunchRelay when the caller runs no relay) and the caller
// should keep its existing fallback path. A nil Conn with NotViable
// false is a genuine punch failure.
type PunchResult struct {
	Conn      aether.Connection
	NotViable bool
}

// PunchCandidates selects the destination address set for a punch from
// the offer's Method:
//
//	PunchDirect          — the offered addresses as-is
//	PunchPortPrediction  — offered addresses widened by PredictPorts
//	                       (symmetric-NAT birthday-paradox port guessing)
//	PunchUPnP            — treated as Direct: the offered addresses are
//	                       already the peer's reflexive addresses
//
// The result is capped at MaxPunchCandidates.
func PunchCandidates(offer *PunchOffer) []net.UDPAddr {
	base := make([]net.UDPAddr, 0, len(offer.LocalAddrs)+len(offer.ReflexiveAddrs))
	base = append(base, offer.LocalAddrs...)
	base = append(base, offer.ReflexiveAddrs...)
	if offer.Method == PunchPortPrediction {
		base = PredictPorts(base, 0) // 0 → default ±128 window
	}
	if len(base) > MaxPunchCandidates {
		base = base[:MaxPunchCandidates]
	}
	return base
}

// ExecutePunch runs the synchronized simultaneous-dial half of a
// coordinated hole-punch. It waits until t0, then fires a Noise-UDP
// handshake at every candidate address concurrently — the simultaneous
// open that makes both NATs install an outbound mapping for the other
// side at the same moment. The first handshake to complete wins; the
// rest are cancelled.
//
// PunchRelay returns a NotViable result without dialing: the caller
// keeps its existing fallback path.
func ExecutePunch(ctx context.Context, offer *PunchOffer, t0 time.Time, dial DialFunc) (PunchResult, error) {
	if offer.Method == PunchRelay {
		return PunchResult{NotViable: true}, nil
	}
	candidates := PunchCandidates(offer)
	if len(candidates) == 0 {
		return PunchResult{}, errors.New("nat: punch offer carried no candidate addresses")
	}

	// Block until the synchronized fire time. A T0 already in the past
	// (slow signaling round-trip) falls straight through to the dial.
	if wait := time.Until(t0); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return PunchResult{}, ctx.Err()
		case <-timer.C:
		}
	}

	// Simultaneous open: dial every candidate at once, first win cancels
	// the rest.
	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type dialOutcome struct {
		conn aether.Connection
		err  error
	}
	outcomes := make(chan dialOutcome, len(candidates))
	for _, addr := range candidates {
		go func(a net.UDPAddr) {
			conn, err := dial(dialCtx, a)
			outcomes <- dialOutcome{conn: conn, err: err}
		}(addr)
	}

	var lastErr error
	for range candidates {
		select {
		case <-ctx.Done():
			return PunchResult{}, ctx.Err()
		case o := <-outcomes:
			if o.err == nil && o.conn != nil {
				cancel() // stop the remaining handshakes
				return PunchResult{Conn: o.conn}, nil
			}
			if o.err != nil {
				lastErr = o.err
			}
		}
	}
	return PunchResult{}, fmt.Errorf("nat: all %d punch candidates failed: %w", len(candidates), lastErr)
}

// ExecuteProbe runs the responder half of a coordinated hole-punch. It
// waits until t0, then fires a probe at every requester candidate
// concurrently so this node's NAT installs an outbound mapping for the
// initiator before the initiator's dial (fired at the same t0) arrives.
//
// It returns nothing: the responder does not complete a handshake — its
// always-running listener accepts the initiator's inbound dial. A nil
// probe func or an empty candidate set is a safe no-op.
func ExecuteProbe(ctx context.Context, req *PunchRequest, t0 time.Time, probe ProbeFunc) {
	if probe == nil || len(req.LocalAddrs) == 0 {
		return
	}
	if wait := time.Until(t0); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
	var wg sync.WaitGroup
	for _, addr := range req.LocalAddrs {
		wg.Add(1)
		go func(a net.UDPAddr) {
			defer wg.Done()
			_ = probe(ctx, a)
		}(addr)
	}
	wg.Wait()
}
