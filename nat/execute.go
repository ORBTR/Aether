//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

// Coordinated hole-punch execution.
//
// holepunch.go defines the signed PunchRequest/PunchOffer payloads and
// method selection; this file is the synchronized execution that
// consumes them. It is transport-agnostic — the caller injects a DialFunc
// (initiator half) or a ProbeFunc (responder half) — so the same
// execution logic serves any mesh: the ORBTR endpoint fleet and the
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

	// MaxPunchWait bounds how far in the future a synchronized fire time
	// T0 may sit before ExecutePunch/ExecuteProbe refuse to schedule it.
	// PunchFireTime derives T0 from a peer-supplied, self-signed Timestamp
	// with no freshness window (Verify checks only the signature), so a
	// malicious authenticated peer could otherwise park the blocking timer
	// arbitrarily long. It must comfortably exceed PunchLeadTime plus
	// worst-case one-way signaling latency and clock skew. (AE-P-17)
	MaxPunchWait = 30 * time.Second
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
	// AE-P-16: bound the peer-controlled seed set BEFORE PredictPorts. Port
	// prediction expands each seed 257x (a ±128 port window), so an uncapped
	// base would materialize a 257·len(base) backing array at the PredictPorts
	// make() before the trim below — a memory-amplification lever on a
	// peer-controlled address list. AE-P-03 now signs those addresses, but a
	// validly-signed offer from an authenticated-but-hostile (or compromised)
	// peer can still carry an arbitrarily large seed count; the signature binds
	// the addresses, not their number. Capping the seeds to MaxPunchCandidates
	// first bounds that allocation without dropping any candidate that survives
	// the final cap: PredictPorts emits each seed's window in input order and a
	// single valid seed alone already yields >MaxPunchCandidates ports, so the
	// leading seed(s) fill the post-expansion cap either way. Mirrors the
	// loop-time cap ProbeCandidates applies on the responder half.
	if len(base) > MaxPunchCandidates {
		base = base[:MaxPunchCandidates]
	}
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
		// AE-P-17: t0 is derived (via PunchFireTime) from the peer-supplied,
		// self-signed PunchRequest.Timestamp, which Verify does not
		// freshness-check — a malicious authenticated peer can set a
		// far-future Timestamp and park this timer arbitrarily long. Refuse a
		// T0 more than MaxPunchWait past now instead of scheduling it. Honest
		// traffic fires within PunchLeadTime of the request, well under the
		// bound, so no legitimate punch is lost.
		if wait > MaxPunchWait {
			return PunchResult{}, fmt.Errorf("nat: punch fire time is %v in the future, exceeding the %v bound", wait, MaxPunchWait)
		}
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

	// AE-L-09: a simultaneous open can complete more than one candidate at
	// once. The buffered outcomes channel (cap == len(candidates)) means every
	// dial goroutine sends exactly one outcome even after a winner returns, and
	// a late winner carries a live aether.Connection. drainAndClose consumes the
	// outcomes the still-in-flight dials owe and Close()es any conn they carry,
	// so an abandoned punch — resolved either by a winner or by ctx cancellation
	// — cannot leak the losing sockets. The read count is exact and no send can
	// block, so the goroutine always terminates.
	drainAndClose := func(remaining int) {
		go func() {
			for i := 0; i < remaining; i++ {
				lost := <-outcomes
				if lost.conn != nil {
					_ = lost.conn.Close()
				}
			}
		}()
	}

	var lastErr error
	for received := 0; received < len(candidates); received++ {
		select {
		case <-ctx.Done():
			// AE-L-09: abandon the punch but close conns already dialed.
			drainAndClose(len(candidates) - received)
			return PunchResult{}, ctx.Err()
		case o := <-outcomes:
			if o.err == nil && o.conn != nil {
				cancel() // stop the remaining handshakes
				// AE-L-09: close any late winners the losing dials still owe.
				drainAndClose(len(candidates) - received - 1)
				return PunchResult{Conn: o.conn}, nil
			}
			if o.err != nil {
				lastErr = o.err
			}
		}
	}
	return PunchResult{}, fmt.Errorf("nat: all %d punch candidates failed: %w", len(candidates), lastErr)
}

// ProbeCandidates selects the responder's probe-target set from a
// PunchRequest's LocalAddrs. That slice is peer-controlled and is NOT
// covered by PunchRequest.SignBytes, so it is deduplicated, stripped of
// unroutable targets (nil/unspecified IP, out-of-range port), and capped
// at MaxPunchCandidates to bound ExecuteProbe's goroutine fan-out and UDP
// burst (AE-H-06). Mirror of PunchCandidates on the initiator half.
func ProbeCandidates(req *PunchRequest) []net.UDPAddr {
	out := make([]net.UDPAddr, 0, MaxPunchCandidates)
	seen := make(map[string]struct{}, MaxPunchCandidates)
	for _, a := range req.LocalAddrs {
		if a.IP == nil || a.IP.IsUnspecified() || a.Port <= 0 || a.Port >= 65536 {
			continue
		}
		key := a.String()
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, a)
		if len(out) >= MaxPunchCandidates {
			break
		}
	}
	return out
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
	// AE-H-06: req.LocalAddrs is peer-controlled and unsigned (SignBytes
	// omits the address slices), so probing it directly would spawn one
	// goroutine + a 5-datagram burst per address at attacker-chosen
	// victims. ProbeCandidates dedupes, drops unroutable targets, and caps
	// at MaxPunchCandidates — the bound ExecutePunch already applies via
	// PunchCandidates.
	candidates := ProbeCandidates(req)
	if probe == nil || len(candidates) == 0 {
		return
	}
	if wait := time.Until(t0); wait > 0 {
		// AE-P-17: refuse a far-future T0 (peer-controlled via the unfreshened
		// PunchRequest.Timestamp) rather than parking this goroutine+timer.
		if wait > MaxPunchWait {
			return
		}
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
	var wg sync.WaitGroup
	for _, addr := range candidates {
		wg.Add(1)
		go func(a net.UDPAddr) {
			defer wg.Done()
			_ = probe(ctx, a)
		}(addr)
	}
	wg.Wait()
}
