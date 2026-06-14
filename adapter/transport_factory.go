//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package adapter

import (
	"errors"
	"fmt"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/grpc"
	"github.com/ORBTR/aether/noise"
	"github.com/ORBTR/aether/quic"
	"github.com/ORBTR/aether/websocket"
)

// ErrUnknownProtocol is returned by NewTransport when the requested
// Protocol value does not match any registered transport. Use
// errors.Is(err, ErrUnknownProtocol) to detect.
var ErrUnknownProtocol = errors.New("aether adapter: unknown protocol")

// ErrProtocolDisabled is returned by NewTransport when the requested
// Protocol is recognised but the matching sub-config on aether.Config
// is nil (e.g. proto=ProtoQUIC but cfg.QUIC == nil). Distinguishes
// "we don't know that protocol" from "you asked for it but didn't
// configure it". Use errors.Is(err, ErrProtocolDisabled) to detect.
var ErrProtocolDisabled = errors.New("aether adapter: protocol disabled (sub-config nil)")

// ErrNilConfig is returned by the string-keyed NewTransport when the
// caller passes a nil *aether.Config. NewTransportForProtocol takes
// Config by value and does not need this sentinel.
var ErrNilConfig = errors.New("aether adapter: nil config")

// NewTransport dispatches construction to the per-protocol transport
// constructor named by proto. proto accepts the wire-name strings
// "noise" / "noise-udp", "quic", "ws" / "websocket", "grpc"; an empty
// or unrecognised value yields ErrUnknownProtocol. cfg is the unified
// aether.Config; a nil cfg is rejected with ErrNilConfig before any
// sub-package is consulted.
//
// String dispatch goes through aether.ParseProtocol so the legacy
// "vl1" alias and the dual "ws"/"websocket" names route to the same
// constructor as the typed factory below — callers picking a protocol
// off the wire don't have to normalise names themselves.
//
// All other behaviour (config-nil → ErrProtocolDisabled, defensive
// nil-transport guard, returned interface type) matches
// NewTransportForProtocol; see that function for the full contract,
// including the Noise NetworkKeys caveat.
func NewTransport(proto string, cfg *aether.Config) (aether.Transport, error) {
	if cfg == nil {
		return nil, ErrNilConfig
	}
	p := aether.ParseProtocol(proto)
	if p == aether.ProtoUnknown {
		return nil, fmt.Errorf("%w: %q", ErrUnknownProtocol, proto)
	}
	return NewTransportForProtocol(p, *cfg)
}

// NewTransportForProtocol is the typed-enum form of NewTransport.
// Prefer NewTransport when the protocol is a wire string; reach for
// this when the caller already holds a Protocol value (e.g. iterating
// cfg.EnabledProtocols, parameterising a test).
//
// The factory lives in the adapter package — not the aether root —
// because the four transport sub-packages (noise/, quic/, websocket/,
// grpc/) all import the aether root; making the root import them back
// would form a cycle. The adapter package is the existing integration
// seam that already imports both root and sub-packages and is therefore
// the only legal home for a unified factory.
//
// Noise caveat: NewNoiseTransport requires at least one PSK in
// NoiseTransportConfig.NetworkKeys, and aether.Config.Noise does NOT
// surface that field. Calling NewTransportForProtocol(ProtoNoise, cfg)
// therefore fails at NewNoiseTransport with "crypto: at least one
// network key is required" unless aether.Config.Noise is extended to
// carry NetworkKeys. Callers that need a Noise transport today must
// use noise.NewNoiseTransport directly. The factory still serves QUIC /
// WebSocket / gRPC fully and returns ErrProtocolDisabled or the
// underlying construction error for ProtoNoise — so it remains safe
// to use from a runtime dispatch that filters by enabled protocols.
//
// Returned errors:
//
//   - ErrUnknownProtocol when proto is not one of ProtoNoise, ProtoQUIC,
//     ProtoWebSocket, ProtoGRPC. ProtoTCP is recognised by the rest of
//     aether but has no standalone transport package — it is provided
//     by this adapter layer's TCP session — and is reported here as
//     unknown to keep the factory's contract honest about what it can
//     construct.
//   - ErrProtocolDisabled when the requested protocol's sub-config on
//     cfg is nil. The per-package *FromConfig functions return (nil,
//     nil) in that case; NewTransportForProtocol surfaces it as an
//     error so a caller asking for a specific protocol can distinguish
//     "no transport, no error" from "your build is misconfigured".
//
// On success the returned aether.Transport satisfies the standard
// Dial / Listen / Close interface. The concrete type is the
// per-package *XxxTransport, which is fine to type-assert when callers
// need protocol-specific extension points (e.g. *noise.NoiseTransport
// exposes SetForwarder).
func NewTransportForProtocol(proto aether.Protocol, cfg aether.Config) (aether.Transport, error) {
	switch proto {
	case aether.ProtoNoise:
		if cfg.Noise == nil {
			return nil, fmt.Errorf("%w: ProtoNoise", ErrProtocolDisabled)
		}
		t, err := noise.NewNoiseTransportFromConfig(cfg)
		if err != nil {
			return nil, err
		}
		if t == nil {
			// Defensive: NewNoiseTransportFromConfig returns (nil, nil)
			// when cfg.Noise == nil, but we already checked above. If
			// the per-package contract ever changes, surface the same
			// disabled-error rather than handing back an untyped nil
			// interface (which would Compare != nil through Transport).
			return nil, fmt.Errorf("%w: ProtoNoise", ErrProtocolDisabled)
		}
		return t, nil

	case aether.ProtoQUIC:
		if cfg.QUIC == nil {
			return nil, fmt.Errorf("%w: ProtoQUIC", ErrProtocolDisabled)
		}
		t, err := quic.NewQuicTransportFromConfig(cfg)
		if err != nil {
			return nil, err
		}
		if t == nil {
			return nil, fmt.Errorf("%w: ProtoQUIC", ErrProtocolDisabled)
		}
		return t, nil

	case aether.ProtoWebSocket:
		if cfg.WebSocket == nil {
			return nil, fmt.Errorf("%w: ProtoWebSocket", ErrProtocolDisabled)
		}
		t, err := websocket.NewWebsocketTransportFromConfig(cfg)
		if err != nil {
			return nil, err
		}
		if t == nil {
			return nil, fmt.Errorf("%w: ProtoWebSocket", ErrProtocolDisabled)
		}
		return t, nil

	case aether.ProtoGRPC:
		if cfg.GRPC == nil {
			return nil, fmt.Errorf("%w: ProtoGRPC", ErrProtocolDisabled)
		}
		t, err := grpc.NewGrpcTransportFromConfig(cfg)
		if err != nil {
			return nil, err
		}
		if t == nil {
			return nil, fmt.Errorf("%w: ProtoGRPC", ErrProtocolDisabled)
		}
		return t, nil

	default:
		return nil, fmt.Errorf("%w: %s (value=%d)", ErrUnknownProtocol, proto.String(), uint8(proto))
	}
}
