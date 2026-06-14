//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package adapter

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/ORBTR/aether"
)

// TestNewTransport_AllProtocols asserts the factory returns a non-nil
// Transport for each enum value that maps to a built-in transport
// package (Noise / QUIC / WebSocket / gRPC) when the matching sub-
// config is populated.
func TestNewTransport_AllProtocols(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	nodeID, err := aether.NewNodeID(pub)
	if err != nil {
		t.Fatalf("derive node id: %v", err)
	}

	cfg := aether.DefaultConfig()
	cfg.NodeID = nodeID
	cfg.PrivateKey = priv
	// DefaultConfig leaves Noise.ListenAddr at ":41641" — that's fine
	// for construction (Listen is not called), but pick an ephemeral
	// port to avoid any chance of a transient bind side-effect during
	// future test extensions.
	cfg.Noise.ListenAddr = ":0"
	cfg.QUIC.ListenAddr = ":0"
	cfg.WebSocket.ListenAddr = ":0"
	cfg.GRPC.ListenAddr = ":0"

	cases := []struct {
		name  string
		proto aether.Protocol
		skip  string // non-empty → t.Skip with this reason
	}{
		// Noise is skipped because NewNoiseTransport requires at least
		// one PSK in NoiseTransportConfig.NetworkKeys, and the unified
		// aether.Config.Noise does NOT surface that field — see the
		// "knobs the unified Config does not surface" comment on
		// NewTransport. The factory path works for runtime protocol
		// dispatch but cannot construct a Noise transport on its own;
		// callers needing Noise must use noise.NewNoiseTransport with
		// a populated NoiseTransportConfig.
		{"Noise", aether.ProtoNoise, "Config.Noise does not surface NetworkKeys; use noise.NewNoiseTransport directly"},
		{"QUIC", aether.ProtoQUIC, ""},
		{"WebSocket", aether.ProtoWebSocket, ""},
		{"GRPC", aether.ProtoGRPC, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skip != "" {
				t.Skip(tc.skip)
			}
			tr, err := NewTransportForProtocol(tc.proto, cfg)
			if err != nil {
				t.Fatalf("NewTransport(%s): %v", tc.proto, err)
			}
			if tr == nil {
				t.Fatalf("NewTransport(%s) returned nil transport with nil error", tc.proto)
			}
			// Don't Listen — that's not in scope. Just Close to release
			// any resources (most transports are inert until Listen, but
			// Close is safe and asserts the interface).
			if err := tr.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		})
	}
}

// TestNewTransport_UnknownProtocol asserts the factory rejects unknown
// Protocol values with ErrUnknownProtocol so callers can branch on
// errors.Is.
func TestNewTransport_UnknownProtocol(t *testing.T) {
	cfg := aether.DefaultConfig()
	// ProtoUnknown (0) and ProtoTCP (5) both fall through the switch.
	for _, proto := range []aether.Protocol{aether.ProtoUnknown, aether.ProtoTCP, 99} {
		tr, err := NewTransportForProtocol(proto, cfg)
		if tr != nil {
			t.Errorf("proto=%d: expected nil transport, got %T", proto, tr)
		}
		if !errors.Is(err, ErrUnknownProtocol) {
			t.Errorf("proto=%d: expected ErrUnknownProtocol, got %v", proto, err)
		}
	}
}

// TestNewTransport_StringDispatch covers the string-keyed NewTransport:
// canonical names, the legacy "vl1" alias, the "noise-udp"/"websocket"
// aliases, the empty-string + unknown-name unknown-protocol paths, and
// the nil-cfg guard.
func TestNewTransport_StringDispatch(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	nodeID, err := aether.NewNodeID(pub)
	if err != nil {
		t.Fatalf("derive node id: %v", err)
	}
	cfg := aether.DefaultConfig()
	cfg.NodeID = nodeID
	cfg.PrivateKey = priv
	cfg.Noise.ListenAddr = ":0"
	cfg.QUIC.ListenAddr = ":0"
	cfg.WebSocket.ListenAddr = ":0"
	cfg.GRPC.ListenAddr = ":0"

	// Construct + Close for the buildable protocols. Noise is omitted
	// per the NetworkKeys caveat documented on NewTransportForProtocol.
	for _, proto := range []string{"quic", "ws", "websocket", "grpc"} {
		tr, err := NewTransport(proto, &cfg)
		if err != nil {
			t.Fatalf("NewTransport(%q): %v", proto, err)
		}
		if tr == nil {
			t.Fatalf("NewTransport(%q): nil transport with nil error", proto)
		}
		if err := tr.Close(); err != nil {
			t.Errorf("Close after NewTransport(%q): %v", proto, err)
		}
	}

	// Unknown names route to ErrUnknownProtocol. Empty + nonsense
	// fail at aether.ParseProtocol; "tcp" parses cleanly but has no
	// standalone transport package, so NewTransportForProtocol's
	// default arm returns the same sentinel.
	for _, proto := range []string{"", "carrier-pigeon", "tcp"} {
		tr, err := NewTransport(proto, &cfg)
		if tr != nil {
			t.Errorf("proto=%q: expected nil transport, got %T", proto, tr)
		}
		if !errors.Is(err, ErrUnknownProtocol) {
			t.Errorf("proto=%q: expected ErrUnknownProtocol, got %v", proto, err)
		}
	}

	// nil cfg is rejected before any sub-package is consulted.
	if tr, err := NewTransport("quic", nil); tr != nil || !errors.Is(err, ErrNilConfig) {
		t.Errorf("nil cfg: expected (nil, ErrNilConfig), got (%T, %v)", tr, err)
	}
}

// TestNewTransport_Disabled asserts the factory surfaces a clear error
// when the caller asks for a known protocol whose sub-config is nil,
// rather than silently returning (nil, nil) the way the per-package
// *FromConfig functions do.
func TestNewTransport_Disabled(t *testing.T) {
	cfg := aether.Config{} // every sub-config nil

	cases := []struct {
		name  string
		proto aether.Protocol
	}{
		{"Noise", aether.ProtoNoise},
		{"QUIC", aether.ProtoQUIC},
		{"WebSocket", aether.ProtoWebSocket},
		{"GRPC", aether.ProtoGRPC},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr, err := NewTransportForProtocol(tc.proto, cfg)
			if tr != nil {
				t.Errorf("expected nil transport, got %T", tr)
			}
			if !errors.Is(err, ErrProtocolDisabled) {
				t.Errorf("expected ErrProtocolDisabled, got %v", err)
			}
		})
	}
}
