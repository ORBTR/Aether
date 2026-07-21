/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
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
	"crypto/rand"
	"fmt"
	"net"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/noise"
	fnoise "github.com/flynn/noise"
)

// DialSessionOverConn runs an initiator Noise XX handshake over conn
// and returns a full aether.Session (stream multiplexing + flow
// control + scheduler). This is what browser WASM and ephemeral peer
// scenarios should call instead of the UDP-listener based paths.
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

// DialSessionOverBrowserWS wraps an already-open browser WebSocket
// (supplied as conn — the browser-specific net.Conn using syscall/js,
// opened by the endpoint's own WASM package, e.g. browser_ws.go's
// DialWebSocket) with a full Aether session: it runs Noise XX over conn
// and adds the session layer. This function does NOT open the WebSocket
// itself — that moved out of adapter into the WASM glue so aether carries
// no syscall/js browser I/O.
//
// The return type is *NoiseSession — callers that previously held
// *BrowserWSSession should switch to *NoiseSession or aether.Session,
// both of which expose OpenStream / AcceptStream identically. Prefer
// DialSessionOverConn directly for new code; this is a thin keyed wrapper.
func DialSessionOverBrowserWS(ctx context.Context, localNodeID aether.NodeID, staticPriv, staticPub []byte, conn net.Conn, opts aether.SessionOptions) (*NoiseSession, error) {
	return DialSessionOverConn(ctx, noise.DialConnConfig{
		LocalNodeID: localNodeID,
		StaticPriv:  staticPriv,
		StaticPub:   staticPub,
	}, conn, opts)
}

// DialSessionOverConnEphemeral runs DialSessionOverConn with a freshly
// generated, throwaway Curve25519 static keypair — for KEYLESS callers, i.e.
// the browser `connect` path, whose peer identity is NOT the static key.
//
// On the DialOverConn path the static key is DH material only: the handshake
// exchanges a minimal NodeInfo, `remoteIdentity` is left nil, and there is no
// AE-P-26 signed-identity binding — the browser is a CLIENT, not a mesh peer
// (ratified #R-707). So a per-connection ephemeral key is equivalent in
// security to the old keyless BrowserWS dial: it authenticates nothing on its
// own, and generating it here keeps the JS `connect` API keyless (no
// staticPriv/staticPub plumbed through the WASM boundary).
//
// ticket is OPTIONAL — pass nil when the responder does not require an
// aether-level ticket (e.g. the legacy /bridge/{nodeID} raw-proxy relay route,
// where authorization is the relay's job, not aether's). noise.DialConnConfig
// treats an empty ticket as "no ticket"; the responder enforces one ONLY when
// its noise.AcceptConnConfig.TrustedTicketSigner is non-nil (otherwise the
// ticket block is skipped and a ticketless conn is accepted). Pass a non-nil
// ticket when the accept side sets TrustedTicketSigner.
func DialSessionOverConnEphemeral(ctx context.Context, localNodeID aether.NodeID, ticket []byte, conn net.Conn, opts aether.SessionOptions) (*NoiseSession, error) {
	kp, err := fnoise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("adapter: DialSessionOverConnEphemeral: generate ephemeral keypair: %w", err)
	}
	return DialSessionOverConn(ctx, noise.DialConnConfig{
		LocalNodeID: localNodeID,
		StaticPriv:  kp.Private,
		StaticPub:   kp.Public,
		Ticket:      ticket,
	}, conn, opts)
}
