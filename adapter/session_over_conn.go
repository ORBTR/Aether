/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

// Package adapter provides session-level wrappers over low-level
// transport substrates. session_over_conn.go bridges the noise
// package's substrate-agnostic handshake (DialOverConn / AcceptOverConn,
// defined in aether/noise) with this package's session layer
// (NewNoiseSession — stream multiplexing, flow control, per-stream
// ACK engine, scheduler).
//
// Why it lives here:
//
//   - aether/noise runs the Noise XX handshake over a caller-supplied
//     net.Conn (UDP socket, TCP, WebSocket, WebRTC DataChannel, net.Pipe)
//     and returns a post-handshake connection that decrypts on Read
//     and encrypts on Write. It knows nothing about Aether streams,
//     per-stream windows, or the scheduler — those live in this
//     package.
//
//   - aether/adapter.NewNoiseSession takes any net.Conn that delivers
//     PLAINTEXT Aether frames and wraps it with the full session
//     machinery. It assumes the conn already handles encryption (if
//     any) — which is exactly what a post-handshake noiseConn does.
//
//   - noise can't import adapter (adapter depends on noise, not the
//     other way around), so the wrapper function that composes them
//     has to live in adapter. That's this file.
//
// The two entry points (DialSessionOverConn / AcceptSessionOverConn)
// collapse the two-step `noise.DialOverConn(...) → adapter.NewSession(...)`
// pattern into a single call so callers don't have to know about the
// layered construction.

package adapter

import (
	"context"
	"fmt"
	"net"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/noise"
)

// DialSessionOverConn runs an initiator Noise XX handshake over conn
// and returns a full aether.Session (stream multiplexing + flow
// control + scheduler). This is what browser WASM and ephemeral peer
// scenarios should call instead of DialBrowserWS / the UDP-listener
// based paths.
//
// The returned session owns conn via its noiseConn wrapper; closing
// the session closes the post-handshake crypto layer, which closes
// the underlying net.Conn.
//
// opts controls session-level features (FEC, compression, auto-tune,
// MaxConcurrentStreams, SessionStallThreshold, CongestionAlgo). Pass
// aether.DefaultSessionOptions() for conservative defaults.
func DialSessionOverConn(ctx context.Context, cfg noise.DialConnConfig, conn net.Conn, opts aether.SessionOptions) (*NoiseSession, error) {
	aetherConn, err := noise.DialOverConn(ctx, cfg, conn)
	if err != nil {
		return nil, fmt.Errorf("adapter: DialSessionOverConn: %w", err)
	}
	return wrapPostHandshakeAsSession(aetherConn, cfg.LocalNodeID, opts), nil
}

// AcceptSessionOverConn is the responder-side counterpart. Validates
// any presented ticket via cfg.TrustedTicketSigner / ValidateTicketFn
// (see noise.AcceptConnConfig), then wraps the post-handshake
// connection with the full session layer.
func AcceptSessionOverConn(ctx context.Context, cfg noise.AcceptConnConfig, conn net.Conn, opts aether.SessionOptions) (*NoiseSession, error) {
	aetherConn, err := noise.AcceptOverConn(ctx, cfg, conn)
	if err != nil {
		return nil, fmt.Errorf("adapter: AcceptSessionOverConn: %w", err)
	}
	return wrapPostHandshakeAsSession(aetherConn, cfg.LocalNodeID, opts), nil
}

// wrapPostHandshakeAsSession extracts the post-handshake net.Conn
// from an aether.Connection (produced by noise.Dial/AcceptOverConn)
// and builds a full NoiseSession over it. The noiseConn inside the
// BaseConnection implements net.Conn with decrypting Read / encrypting
// Write, so feeding it into NewNoiseSession gives a session that
// operates on plaintext Aether frames — exactly the contract
// NewNoiseSession expects.
func wrapPostHandshakeAsSession(aetherConn aether.Connection, localNodeID aether.NodeID, opts aether.SessionOptions) *NoiseSession {
	postHandshakeConn := aetherConn.NetConn()
	return NewNoiseSession(postHandshakeConn, localNodeID, aetherConn.RemoteNodeID(), opts)
}

// DialBrowserWS opens a browser WebSocket to url and wraps it with a
// full Aether session. The caller supplies a net.Conn wrapper (the
// browser-specific piece that uses syscall/js); this function then
// runs Noise over it + adds the session layer.
//
// The return type is *NoiseSession — callers that previously held
// *BrowserWSSession should switch to *NoiseSession or aether.Session,
// both of which expose OpenStream / AcceptStream identically. The
// underlying browser WS → net.Conn wrapping is the caller's
// responsibility and lives in each endpoint's WASM package.
func DialSessionOverBrowserWS(ctx context.Context, localNodeID aether.NodeID, staticPriv, staticPub []byte, conn net.Conn, opts aether.SessionOptions) (*NoiseSession, error) {
	return DialSessionOverConn(ctx, noise.DialConnConfig{
		LocalNodeID: localNodeID,
		StaticPriv:  staticPriv,
		StaticPub:   staticPub,
	}, conn, opts)
}
