//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package noise

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"

	"github.com/flynn/noise"
	aether "github.com/ORBTR/aether"
	transportHealth "github.com/ORBTR/aether/health"
	"github.com/ORBTR/aether/relay"
)

// relayForwardTimeout bounds a single relay forward to an external session so
// a wedged/backpressured target can't pin the relaying goroutine (AER-041).
const relayForwardTimeout = 5 * time.Second

// relayDedicatedScopeKey is the rate-limiter bucket used for dedicated /
// empty-scope relay traffic so it is still metered (AER-040).
const relayDedicatedScopeKey = "__aether_dedicated__"

// handleRelayRequest processes an incoming relay request from a Noise session.
// Checks Noise sessions first, then external (WS/QUIC) sessions as fallback.
// Enforces scope isolation: source and target must belong to the same scope.
func (t *NoiseTransport) handleRelayRequest(c *noiseConn, payload []byte) error {
	if !t.relayConfig.Enabled {
		return relay.ErrRelayNotEnabled
	}
	if len(payload) < relay.RelayHeaderSize {
		return relay.ErrInvalidPacket
	}

	targetNodeID := aether.NodeID(payload[:relay.RelayHeaderSize])
	data := payload[relay.RelayHeaderSize:]

	// Try Noise session (fast path)
	targetConn, err := t.resolveRelayTarget(c, payload)
	if err == nil {
		return targetConn.sendRelayPacket(c.remoteNode, data)
	}

	// Fallback: try external session (WS/QUIC bridge) via RelayService.
	// AE-H-08: enforce scope isolation on the bridge path too — a Noise peer
	// must not relay into an external session belonging to another scope.
	// Empty scope on either side = dedicated mode (no restriction), matching
	// resolveRelayTarget's Noise-path check.
	if t.relayService != nil {
		if extSess, targetScope, ok := t.relayService.ExternalScope(targetNodeID); ok {
			if !scopeAllowed(c.scopeID, targetScope) {
				return relay.ErrTenantMismatch
			}
			// Build relay data frame for external session: [sourceNodeID][payload]
			frame := make([]byte, relay.RelayHeaderSize+len(data))
			copy(frame[:relay.RelayHeaderSize], c.remoteNode)
			copy(frame[relay.RelayHeaderSize:], data)
			// AER-041: bound the forward with a deadline. context.Background()
			// let a wedged/backpressured target session pin this relaying
			// goroutine indefinitely, so a slow or malicious target could
			// slowloris-pin relay goroutines.
			ctx, cancel := context.WithTimeout(context.Background(), relayForwardTimeout)
			defer cancel()
			return extSess.Send(ctx, frame)
		}
	}

	return relay.ErrTargetUnreachable
}

// scopeAllowed reports whether a relay between scopes a and b is permitted.
// Both scopes must match; an empty scope on either side means dedicated mode
// (no restriction), mirroring resolveRelayTarget's Noise-path check. AE-H-08.
func scopeAllowed(a, b string) bool {
	return a == "" || b == "" || a == b
}

// resolveRelayTarget finds the target connection for a relay request and validates
// scope isolation. Returns the target noiseConn or an error.
func (t *NoiseTransport) resolveRelayTarget(source *noiseConn, payload []byte) (*noiseConn, error) {
	if !t.relayConfig.Enabled {
		return nil, relay.ErrRelayNotEnabled
	}

	if len(payload) < relay.RelayHeaderSize {
		return nil, relay.ErrInvalidPacket
	}
	targetNodeID := string(payload[:relay.RelayHeaderSize])

	var targetConn *noiseConn

	// Check incoming sessions
	t.listenerMu.Lock()
	if t.listener != nil {
		targetConn = connFromSession(t.listener.sessions.Get(aether.NodeID(targetNodeID)))
	}
	t.listenerMu.Unlock()

	// Check outgoing sessions if not found
	if targetConn == nil {
		t.outgoingMu.Lock()
		if conn, ok := t.outgoingSessions[targetNodeID]; ok {
			targetConn = conn
		}
		t.outgoingMu.Unlock()
	}

	if targetConn == nil {
		return nil, relay.ErrTargetUnreachable
	}

	// Enforce scope isolation: both sessions must be in the same scope.
	// Empty scopeID = dedicated mode (no restriction).
	sourceTenant := source.scopeID
	targetTenant := targetConn.scopeID
	if sourceTenant != "" && targetTenant != "" && sourceTenant != targetTenant {
		return nil, relay.ErrTenantMismatch
	}

	// Per-scope relay rate limiting. AER-040: also rate-limit dedicated /
	// empty-scope traffic. The old `activeTenant != ""` guard skipped limiting
	// entirely when both scopes were empty, so a dedicated relay was an
	// unmetered forwarder. Bucket empty-scope traffic under a sentinel key so
	// per-peer limits still apply.
	activeTenant := sourceTenant
	if activeTenant == "" {
		activeTenant = targetTenant
	}
	limiterKey := activeTenant
	if limiterKey == "" {
		limiterKey = relayDedicatedScopeKey
	}
	if t.scopeLimiter != nil {
		if err := t.scopeLimiter.AllowRelay(limiterKey); err != nil {
			return nil, err
		}
		pairKey := string(source.remoteNode) + "→" + targetNodeID
		if err := t.scopeLimiter.CheckRelayPair(limiterKey, pairKey); err != nil {
			return nil, err
		}
		t.scopeLimiter.TrackRelayPair(limiterKey, pairKey)
	}

	return targetConn, nil
}

// handleRelayData processes incoming relayed data
func (t *NoiseTransport) handleRelayData(c *noiseConn, payload []byte) error {
	if len(payload) < relay.RelayHeaderSize {
		return relay.ErrInvalidPacket
	}

	// Extract source NodeID
	sourceNodeID := string(payload[:relay.RelayHeaderSize])
	data := payload[relay.RelayHeaderSize:]

	// 1. Try to find existing session for this source
	t.listenerMu.Lock()
	if t.listener != nil {
		if nc := connFromSession(t.listener.sessions.Get(aether.NodeID(sourceNodeID))); nc != nil {
			t.listenerMu.Unlock()
			// Inject data into the session
			// Note: data is the raw encrypted packet from A to B
			return nc.decryptAndDeliver(data)
		}
	}
	t.listenerMu.Unlock()

	// 2. No session, check if it's a handshake initiation
	// Handshake packet starts with 4-byte fingerprint
	if len(data) < 4 {
		return relay.ErrInvalidPacket
	}

	fingerprint := binary.BigEndian.Uint32(data[:4])
	if _, ok := t.keyManager.LookupByFingerprint(fingerprint); !ok {
		// Not for us, or invalid fingerprint
		return relay.ErrInvalidPacket
	}

	// It's a handshake!
	t.listenerMu.Lock()
	defer t.listenerMu.Unlock()
	if t.listener != nil {
		return t.listener.handleRelayedHandshake(c, sourceNodeID, data)
	}
	return nil
}

func (l *noiseListener) handleRelayedHandshake(relayConn *noiseConn, sourceNodeID string, msg []byte) error {
	l.mu.Lock()
	hs := l.handshakes[sourceNodeID]

	// New handshake initiation
	if hs == nil {
		// Strip fingerprint + pattern flag for Noise processing
		if len(msg) < 5 {
			l.mu.Unlock()
			return errors.New("vl1: relayed handshake too short")
		}
		fingerprint := binary.BigEndian.Uint32(msg[:4])
		patFlag := msg[4]
		noiseMsg := msg[5:]
		prologue, _ := l.transport.keyManager.LookupByFingerprint(fingerprint)

		hsPattern := noise.HandshakeXX
		if patFlag == patternFlagXK {
			hsPattern = noise.HandshakeXK
		}

		state, err := noise.NewHandshakeState(noise.Config{
			Pattern:     hsPattern,
			Initiator:   false,
			Prologue:    prologue,
			CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
			StaticKeypair: noise.DHKey{
				Private: append([]byte(nil), l.transport.staticPriv...),
				Public:  append([]byte(nil), l.transport.staticPub...),
			},
			Random: rand.Reader,
		})
		if err != nil {
			l.mu.Unlock()
			return err
		}
		hs = &listenerHandshake{state: state, created: time.Now()}
		l.evictOldestHandshakeLocked() // AE-P-21: hard cap on incomplete-handshake map
		l.handshakes[sourceNodeID] = hs

		// Process the first message (stripped of fingerprint)
		if _, _, _, err := state.ReadMessage(nil, noiseMsg); err != nil {
			delete(l.handshakes, sourceNodeID)
			l.mu.Unlock()
			return err
		}
		payload, err := l.transport.encodeNodeInfo()
		if err != nil {
			delete(l.handshakes, sourceNodeID)
			l.mu.Unlock()
			return err
		}
		response, _, _, err := state.WriteMessage(nil, payload)
		if err != nil {
			delete(l.handshakes, sourceNodeID)
			l.mu.Unlock()
			return err
		}

		// Send response via Relay
		// We are B, sending to R, asking to forward to A (sourceNodeID)
		if _, err := relayConn.sendRelayRequest(aether.NodeID(sourceNodeID), response); err != nil {
			delete(l.handshakes, sourceNodeID)
			l.mu.Unlock()
			return err
		}

		hs.responded = true
		l.mu.Unlock()
		return nil
	}

	// Existing handshake (third message)
	state := hs.state

	payload, cs1, cs2, err := state.ReadMessage(nil, msg)
	if err != nil {
		delete(l.handshakes, sourceNodeID)
		l.mu.Unlock()
		return err
	}
	remoteNode, _, remoteCaps, remoteMaxAckDelayUS, err := l.transport.verifyNodeInfo(state.PeerStatic(), payload, "")
	if err != nil {
		delete(l.handshakes, sourceNodeID)
		l.mu.Unlock()
		return err
	}

	// Create a new noiseConn that routes via the relay
	// In Noise XX, after handshake:
	// - cs1 is for initiator→responder (responder uses for recv)
	// - cs2 is for responder→initiator (responder uses for send)
	cfg := aether.DefaultSessionConfig()
	nc := &noiseConn{
		conn:             relayConn.conn, // Share the substrate conn (UDP on native, DC/WS on browser)
		remote:           relayConn.remote,
		remoteNode:       remoteNode,
		send:             cs2,
		recv:             cs1,
		inbox:            make(chan []byte, 256),
		closed:           make(chan struct{}),
		maxPacket:        l.transport.maxPacket,
		localAddr:        relayConn.localAddr,
		transport:        l.transport,
		health: transportHealth.NewMonitor(0.2),
		rekey:  NewRekeyTracker(cfg.RekeyAfterBytes, cfg.RekeyAfterDuration),
		writeFunc: func(data []byte) (int, error) {
			return relayConn.sendRelayRequest(remoteNode, data)
		},
	}
	// Set scope from the relay connection's scope (relayed sessions inherit scope)
	nc.scopeID = relayConn.scopeID
	nc.peerMaxAckDelay = decodeMaxAckDelay(remoteMaxAckDelayUS)

	// Negotiate explicit nonce mode if both sides support it
	if remoteCaps&capExplicitNonce != 0 {
		nc.enableExplicitNonce()
	}

	nc.parentStop = func() {
		l.sessions.Remove(remoteNode)
	}

	l.sessions.Put(remoteNode, sourceNodeID, nc.scopeID, &noiseConnSession{conn: nc, nodeID: remoteNode})
	delete(l.handshakes, sourceNodeID)
	l.mu.Unlock()

	s := aether.NewConnection(l.transport.localNode, remoteNode, nc, aether.ProtoNoise)
	s.OnClose(func() { nc.Close() })

	// Notify listener of new session
	// We need to be careful not to block if channel is full
	go func() {
		select {
		case l.incoming <- aether.IncomingSession{Session: s, Reader: nc, Writer: nc}:
		case <-time.After(1 * time.Second):
			// Drop if listener not accepting
			nc.Close()
		}
	}()

	return nil
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// External session relay bridge (WebSocket, QUIC, gRPC)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// RegisterExternalSession adds a non-Noise session (e.g., WebSocket) to the
// relay's session table via RelayService. This allows the relay to forward
// frames between Noise peers and external transport sessions.
func (t *NoiseTransport) RegisterExternalSession(nodeID aether.NodeID, sess aether.Connection, scopeID string) {
	if t.relayService != nil {
		t.relayService.RegisterExternal(nodeID, sess, scopeID)
	}
}

// UnregisterExternalSession removes a non-Noise session from the relay table
// via RelayService.
func (t *NoiseTransport) UnregisterExternalSession(nodeID aether.NodeID) {
	if t.relayService != nil {
		t.relayService.UnregisterExternal(nodeID)
	}
}

// HandleExternalRelayFrame processes a relay frame received from an external
// (non-Noise) session. The frame format is the standard relay request:
// [targetNodeID:32][payload].
//
// This is the reverse path: external session → relay → Noise peer.
func (t *NoiseTransport) HandleExternalRelayFrame(sourceNodeID aether.NodeID, data []byte) error {
	if !t.relayConfig.Enabled {
		return relay.ErrRelayNotEnabled
	}
	if len(data) < relay.RelayHeaderSize {
		return relay.ErrInvalidPacket
	}

	targetNodeID := aether.NodeID(data[:relay.RelayHeaderSize])
	payload := data[relay.RelayHeaderSize:]

	// AE-H-08: resolve the source bridge session's scope so the same isolation
	// invariant enforced on the Noise path also applies when a frame originates
	// from an external (WS/QUIC/gRPC) bridge session.
	var sourceScope string
	if t.relayService != nil {
		_, sourceScope, _ = t.relayService.ExternalScope(sourceNodeID)
	}

	// Try Noise target (external → Noise peer)
	if targetConn := t.findNoiseSession(targetNodeID); targetConn != nil {
		if !scopeAllowed(sourceScope, targetConn.scopeID) {
			return relay.ErrTenantMismatch
		}
		return targetConn.sendRelayPacket(sourceNodeID, payload)
	}

	// Try external target (external → external, e.g., WS-to-WS relay) via RelayService
	if t.relayService != nil {
		if extSess, targetScope, ok := t.relayService.ExternalScope(targetNodeID); ok {
			if !scopeAllowed(sourceScope, targetScope) {
				return relay.ErrTenantMismatch
			}
			frame := make([]byte, relay.RelayHeaderSize+len(payload))
			copy(frame[:relay.RelayHeaderSize], sourceNodeID)
			copy(frame[relay.RelayHeaderSize:], payload)
			return extSess.Send(context.Background(), frame)
		}
	}

	return relay.ErrTargetUnreachable
}

// findNoiseSession looks up a Noise session by NodeID in both incoming and
// outgoing session tables. Returns nil if not found.
func (t *NoiseTransport) findNoiseSession(nodeID aether.NodeID) *noiseConn {
	// Check incoming sessions
	t.listenerMu.Lock()
	if t.listener != nil {
		if nc := connFromSession(t.listener.sessions.Get(nodeID)); nc != nil {
			t.listenerMu.Unlock()
			return nc
		}
	}
	t.listenerMu.Unlock()

	// Check outgoing sessions
	t.outgoingMu.Lock()
	if conn, ok := t.outgoingSessions[string(nodeID)]; ok {
		t.outgoingMu.Unlock()
		return conn
	}
	t.outgoingMu.Unlock()

	return nil
}
