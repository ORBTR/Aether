/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package aether

import (
	"fmt"
)

// Profile defines the strict behavioral profile for an Aether session.
// Two profiles exist — same stream semantics, different feature sets.
type Profile uint8

const (
	// ProfileFull activates ALL Aether layers. Used for Noise-UDP where the
	// transport provides only encryption and identity.
	// Active: frame codec, mux, reliability (SACK/retransmit/FEC), flow control,
	// congestion (CUBIC/BBR), anti-replay, scheduler with latency classes,
	// header compression, observability.
	ProfileFull Profile = 0

	// ProfileLite activates only stream lifecycle + scheduler + control plane.
	// Used for QUIC/TCP/WS/gRPC where the transport provides reliability,
	// flow control, and congestion control natively.
	// Active: stream lifecycle (OPEN/CLOSE/RESET), DATA framing, PING/PONG,
	// control plane (WHOIS/RENDEZVOUS/NETWORK_CONFIG/HANDSHAKE), scheduler
	// with latency classes, observability (STATS/TRACE/PATH_PROBE).
	// Inactive: reliability, congestion, FEC, anti-replay, flow control.
	ProfileLite Profile = 1
)

// String returns a human-readable profile name.
func (p Profile) String() string {
	switch p {
	case ProfileFull:
		return "A-FULL"
	case ProfileLite:
		return "A-LITE"
	default:
		return fmt.Sprintf("profile(%d)", p)
	}
}

// ProfileForProtocol returns the strict profile for a given transport protocol.
func ProfileForProtocol(proto Protocol) Profile {
	switch proto {
	case ProtoNoise:
		return ProfileFull // Noise-UDP: full Aether stack
	default:
		return ProfileLite // QUIC, TCP, WS, gRPC: lite profile
	}
}

// NeedsReliability returns true if the profile requires Aether reliability (SACK/retransmit).
func (p Profile) NeedsReliability() bool { return p == ProfileFull }

// NeedsFlowControl returns true if the profile requires Aether flow control (WINDOW_UPDATE).
func (p Profile) NeedsFlowControl() bool { return p == ProfileFull }

// NeedsCongestion returns true if the profile requires Aether congestion control (CUBIC/BBR).
func (p Profile) NeedsCongestion() bool { return p == ProfileFull }

// NeedsFEC returns true if the profile requires forward error correction.
func (p Profile) NeedsFEC() bool { return p == ProfileFull }

// NeedsAntiReplay returns true if the profile requires anti-replay protection.
func (p Profile) NeedsAntiReplay() bool { return p == ProfileFull }

// NeedsMux returns true if the profile requires Aether stream multiplexing.
// ProfileFull muxes over a single conn; ProfileLite uses native streams.
func (p Profile) NeedsMux() bool { return p == ProfileFull }

// NeedsScheduler returns true if the profile uses the Aether priority scheduler.
// Both profiles use the scheduler — even LITE benefits from latency class ordering.
func (p Profile) NeedsScheduler() bool { return true }

// NeedsObservability returns true if the profile supports STATS/TRACE/PATH_PROBE.
// Both profiles support observability.
func (p Profile) NeedsObservability() bool { return true }
