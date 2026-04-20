/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package aether

import (
	"fmt"
	"time"
)

// TransportClass classifies transports by their packet-level behavior.
// Used to degrade Aether behavior on transports that don't provide
// packet-level control (WS/gRPC introduce buffering and HOL blocking).
type TransportClass uint8

const (
	// ClassRAW is for packet-oriented transports (UDP, QUIC).
	// Full Aether protocol with aggressive retransmit and congestion control.
	ClassRAW TransportClass = 0

	// ClassSTREAM is for byte-stream transports (TCP, TLS).
	// Conservative retransmit (TCP handles), reduced keepalive.
	ClassSTREAM TransportClass = 1

	// ClassPROXY is for proxy-buffered transports (WS, gRPC).
	// No retransmit (transport handles), increased keepalive frequency
	// (prevent proxy timeout), reduced max frame size.
	ClassPROXY TransportClass = 2
)

// String returns a human-readable class name.
func (c TransportClass) String() string {
	switch c {
	case ClassRAW:
		return "RAW"
	case ClassSTREAM:
		return "STREAM"
	case ClassPROXY:
		return "PROXY"
	default:
		return fmt.Sprintf("class(%d)", c)
	}
}

// TransportClassForProtocol returns the transport class for a given protocol.
func TransportClassForProtocol(proto Protocol) TransportClass {
	switch proto {
	case ProtoNoise, ProtoQUIC:
		return ClassRAW
	case ProtoWebSocket, ProtoGRPC:
		return ClassPROXY
	case ProtoTCP:
		return ClassSTREAM
	default:
		return ClassSTREAM
	}
}

// TransportClassDefaults holds per-class tuning parameters.
type TransportClassDefaults struct {
	KeepaliveInterval    time.Duration // how often to send PING
	MaxFrameSize         int           // maximum Aether frame payload
	RetransmitEnabled    bool          // whether Aether retransmit is active
	AggressiveRetransmit bool          // use short RTO for fast recovery
}

// DefaultsForClass returns the tuning parameters for a transport class.
func DefaultsForClass(c TransportClass) TransportClassDefaults {
	switch c {
	case ClassRAW:
		return TransportClassDefaults{
			KeepaliveInterval:    15 * time.Second,
			MaxFrameSize:         1400, // MTU-safe for UDP
			RetransmitEnabled:    true,
			AggressiveRetransmit: true, // short RTO
		}
	case ClassSTREAM:
		return TransportClassDefaults{
			KeepaliveInterval:    30 * time.Second,
			MaxFrameSize:         65536, // TCP can handle large frames
			RetransmitEnabled:    false, // TCP provides reliability
			AggressiveRetransmit: false,
		}
	case ClassPROXY:
		return TransportClassDefaults{
			KeepaliveInterval:    10 * time.Second, // frequent — prevent proxy timeout
			MaxFrameSize:         32768,            // reduced — avoid proxy buffer overflow
			RetransmitEnabled:    false,            // transport provides reliability
			AggressiveRetransmit: false,
		}
	default:
		return DefaultsForClass(ClassSTREAM)
	}
}
