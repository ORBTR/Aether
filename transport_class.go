/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import "fmt"

// TransportClass classifies transports by their packet-level behavior. Its one
// per-class value is the frame ceiling DefaultsForClass gives, which
// adapter.MaxAppMessageBudget reads. Whether a session acknowledges and
// retransmits is its reliability profile's (Full on Noise, Lite on the
// natively reliable transports), not its class's.
type TransportClass uint8

const (
	// ClassRAW is for packet-oriented transports (UDP, QUIC): an MTU-safe
	// frame ceiling.
	ClassRAW TransportClass = 0

	// ClassSTREAM is for byte-stream transports (TCP, TLS): a large frame
	// ceiling.
	ClassSTREAM TransportClass = 1

	// ClassPROXY is for proxy-buffered transports (WS, gRPC): a reduced
	// frame ceiling. How often a session on one probes is quality.Keepalive's
	// decision from the session's own round trips, as on every class.
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
	MaxFrameSize int // maximum Aether frame payload
}

// DefaultsForClass returns the tuning parameters for a transport class.
func DefaultsForClass(c TransportClass) TransportClassDefaults {
	switch c {
	case ClassRAW:
		return TransportClassDefaults{
			MaxFrameSize: 1400, // MTU-safe for UDP
		}
	case ClassSTREAM:
		return TransportClassDefaults{
			MaxFrameSize: 65536, // TCP can handle large frames
		}
	case ClassPROXY:
		return TransportClassDefaults{
			MaxFrameSize: 32768, // reduced — avoid proxy buffer overflow
		}
	default:
		return DefaultsForClass(ClassSTREAM)
	}
}
