//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 *
 * RelayService provides protocol-agnostic relay forwarding. It looks up
 * target sessions via a SessionIndex interface (injected by the transport
 * manager or protocol adapter) and forwards frames between any combination
 * of session types (Noise↔WS, WS↔WS, Noise↔Noise, etc.).
 */
package relay

import (
	"context"
	"sync"
	"time"

	aether "github.com/ORBTR/aether"
)

// SessionIndex provides session lookup for relay forwarding.
// Implemented by protocol adapters or a unified session registry.
type SessionIndex interface {
	// LookupByNodeID finds an active session by peer NodeID.
	LookupByNodeID(id aether.NodeID) aether.Connection

	// LookupExternal finds a non-primary (e.g., WebSocket bridge) session.
	LookupExternal(id aether.NodeID) aether.Connection
}

// RelayService handles relay request/data forwarding across any transport sessions.
// It uses a SessionIndex to find targets via primary session lookup, and manages
// external (non-primary) sessions (WebSocket, QUIC, gRPC bridges) directly.
type RelayService struct {
	mu               sync.RWMutex
	sessions         SessionIndex                          // primary session lookup (injected)
	externalSessions map[aether.NodeID]aether.Connection // WS/QUIC/gRPC bridge sessions
	config           RelayConfig
}

// NewRelayService creates a RelayService with the given config and session index.
func NewRelayService(config RelayConfig, sessions SessionIndex) *RelayService {
	return &RelayService{
		config:           config,
		sessions:         sessions,
		externalSessions: make(map[aether.NodeID]aether.Connection),
	}
}

// SetSessionIndex replaces the session index (used when the index is built after construction).
func (rs *RelayService) SetSessionIndex(idx SessionIndex) {
	rs.mu.Lock()
	rs.sessions = idx
	rs.mu.Unlock()
}

// HandleRelayRequest processes a relay request: find the target and forward the payload.
// The frame format is [targetNodeID:32][payload].
func (rs *RelayService) HandleRelayRequest(sourceNodeID aether.NodeID, data []byte) error {
	if !rs.config.Enabled {
		return ErrRelayNotEnabled
	}
	if len(data) < RelayHeaderSize {
		return ErrInvalidPacket
	}

	targetNodeID := aether.NodeID(data[:RelayHeaderSize])
	payload := data[RelayHeaderSize:]

	// Try primary sessions via injected SessionIndex
	rs.mu.RLock()
	idx := rs.sessions
	rs.mu.RUnlock()
	if idx != nil {
		if sess := idx.LookupByNodeID(targetNodeID); sess != nil {
			frame := makeRelayFrame(sourceNodeID, payload)
			return sess.Send(context.Background(), frame)
		}
	}

	// Fallback: external session (WS/QUIC/gRPC bridge)
	rs.mu.RLock()
	extSess := rs.externalSessions[targetNodeID]
	rs.mu.RUnlock()
	if extSess != nil {
		frame := makeRelayFrame(sourceNodeID, payload)
		return extSess.Send(context.Background(), frame)
	}

	return ErrTargetUnreachable
}

// HandleRelayData processes incoming relayed data (already forwarded to us).
// The frame format is [sourceNodeID:32][payload].
func (rs *RelayService) HandleRelayData(sourceNodeID aether.NodeID, data []byte) error {
	if len(data) < RelayHeaderSize {
		return ErrInvalidPacket
	}
	// Source is embedded in the frame for the receiving session to identify the sender
	return nil // Actual dispatch to session handled by the protocol layer
}

// Enabled returns whether relay forwarding is active.
func (rs *RelayService) Enabled() bool {
	return rs.config.Enabled
}

// Config returns the current relay configuration.
func (rs *RelayService) Config() RelayConfig {
	return rs.config
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// External session management (WebSocket, QUIC, gRPC bridges)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// RegisterExternal adds a non-primary session (e.g., WebSocket bridge) to the
// relay's external session table. This allows relay forwarding between primary
// transport sessions and external bridge sessions.
func (rs *RelayService) RegisterExternal(nodeID aether.NodeID, sess aether.Connection) {
	rs.mu.Lock()
	rs.externalSessions[nodeID] = sess
	rs.mu.Unlock()
}

// UnregisterExternal removes a non-primary session from the external session table.
func (rs *RelayService) UnregisterExternal(nodeID aether.NodeID) {
	rs.mu.Lock()
	delete(rs.externalSessions, nodeID)
	rs.mu.Unlock()
}

// LookupExternal finds a non-primary (bridge) session by NodeID.
func (rs *RelayService) LookupExternal(id aether.NodeID) aether.Connection {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return rs.externalSessions[id]
}

// PruneExternal removes idle external sessions older than maxAge.
// Sessions that implement aether.HealthReporter are checked for liveness;
// sessions that do not implement HealthReporter are left alone.
func (rs *RelayService) PruneExternal(maxAge time.Duration) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	for nodeID, sess := range rs.externalSessions {
		if hr, ok := sess.(aether.HealthReporter); ok {
			if !hr.IsAlive(maxAge) {
				_ = sess.Close()
				delete(rs.externalSessions, nodeID)
			}
		}
	}
}

// ExternalCount returns the number of registered external sessions.
func (rs *RelayService) ExternalCount() int {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return len(rs.externalSessions)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Internal helpers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// makeRelayFrame builds a relay data frame: [sourceNodeID][payload]
func makeRelayFrame(sourceNodeID aether.NodeID, payload []byte) []byte {
	frame := make([]byte, RelayHeaderSize+len(payload))
	copy(frame[:RelayHeaderSize], sourceNodeID)
	copy(frame[RelayHeaderSize:], payload)
	return frame
}
