//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package noise

import (
	"testing"

	aether "github.com/ORBTR/aether"
	"github.com/ORBTR/aether/relay"
)

// ---------- test helpers ----------

// testNodeID creates a aether.NodeID that is exactly 32 bytes (relay.RelayHeaderSize).
func testNodeID(name string) aether.NodeID {
	buf := make([]byte, relay.RelayHeaderSize)
	copy(buf, name)
	return aether.NodeID(buf)
}

// newTestNoiseConn creates a minimal noiseConn with scopeID set.
func newTestNoiseConn(scopeID string, remoteNode aether.NodeID) *noiseConn {
	return &noiseConn{
		remoteNode: remoteNode,
		scopeID:   scopeID,
		inbox:      make(chan []byte, 16),
		closed:     make(chan struct{}),
	}
}

// newTestTransport creates a NoiseTransport with relay enabled and a listener.
func newTestTransport() *NoiseTransport {
	t := &NoiseTransport{
		relayConfig:      relay.RelayConfig{Enabled: true},
		outgoingSessions: make(map[string]*noiseConn),
	}
	t.listener = &noiseListener{
		transport:  t,
		handshakes: make(map[string]*listenerHandshake),
		sessions:   aether.NewConnectionMap(),
		incoming:   make(chan aether.IncomingSession, 8),
	}
	return t
}

func addListenerSession(t *NoiseTransport, scopeID string, nodeID aether.NodeID, nc *noiseConn) {
	l := t.listener
	l.sessions.Put(nodeID, string(nodeID), scopeID, &noiseConnSession{conn: nc, nodeID: nodeID})
}

// buildRelayPayload constructs a relay request payload: [32-byte targetNodeID][data]
func buildRelayPayload(targetNodeID aether.NodeID, data []byte) []byte {
	payload := make([]byte, relay.RelayHeaderSize+len(data))
	copy(payload[:relay.RelayHeaderSize], []byte(targetNodeID))
	copy(payload[relay.RelayHeaderSize:], data)
	return payload
}

// ---------- scope session index tests ----------

func TestTenantSessionIndex_AddRemove(t *testing.T) {
	tr := newTestTransport()
	l := tr.listener

	nodeA := testNodeID("nodeA")
	nodeB := testNodeID("nodeB")

	addListenerSession(tr, "scope-1", nodeA, newTestNoiseConn("scope-1", nodeA))
	addListenerSession(tr, "scope-1", nodeB, newTestNoiseConn("scope-1", nodeB))

	if l.sessions.TenantCount("scope-1") != 2 {
		t.Fatalf("expected 2 sessions for scope-1, got %d", l.sessions.TenantCount("scope-1"))
	}

	// Remove one session
	l.sessions.Remove(nodeA)

	if l.sessions.TenantCount("scope-1") != 1 {
		t.Fatalf("expected 1 session for scope-1 after remove, got %d", l.sessions.TenantCount("scope-1"))
	}

	// Remove last session — scope entry should be cleaned up
	l.sessions.Remove(nodeB)
	if l.sessions.HasTenant("scope-1") {
		t.Fatal("expected scope-1 entry to be cleaned up when empty")
	}
}

func TestTenantSessionIndex_EmptyTenant(t *testing.T) {
	tr := newTestTransport()
	l := tr.listener
	nodeA := testNodeID("nodeA")

	addListenerSession(tr, "", nodeA, newTestNoiseConn("", nodeA))

	if l.sessions.TenantCountAll() != 0 {
		t.Fatal("expected no scope entries for empty scope (dedicated mode)")
	}
}

func TestTenantSessionIndex_MultipleTenants(t *testing.T) {
	tr := newTestTransport()
	l := tr.listener

	nodeA := testNodeID("nodeA")
	nodeB := testNodeID("nodeB")
	nodeC := testNodeID("nodeC")

	addListenerSession(tr, "scope-1", nodeA, newTestNoiseConn("scope-1", nodeA))
	addListenerSession(tr, "scope-2", nodeB, newTestNoiseConn("scope-2", nodeB))
	addListenerSession(tr, "scope-1", nodeC, newTestNoiseConn("scope-1", nodeC))

	if l.sessions.TenantCount("scope-1") != 2 {
		t.Errorf("expected 2 sessions for scope-1, got %d", l.sessions.TenantCount("scope-1"))
	}
	if l.sessions.TenantCount("scope-2") != 1 {
		t.Errorf("expected 1 session for scope-2, got %d", l.sessions.TenantCount("scope-2"))
	}
}

func TestTenantForNode(t *testing.T) {
	tr := newTestTransport()
	l := tr.listener
	nodeA := testNodeID("nodeA")
	addListenerSession(tr, "scope-1", nodeA, newTestNoiseConn("scope-1", nodeA))

	scope := l.tenantForNode(nodeA)
	if scope != "scope-1" {
		t.Fatalf("expected scope-1, got %s", scope)
	}

	scope = l.tenantForNode(testNodeID("unknown"))
	if scope != "" {
		t.Fatalf("expected empty string for unknown node, got %s", scope)
	}
}

// ---------- relay routing + scope isolation tests ----------
// These tests use resolveRelayTarget() directly to test routing and scope
// validation without requiring real Noise cipher states.

func TestResolveRelayTarget_SameTenant_Allowed(t *testing.T) {
	tr := newTestTransport()
	sourceNode := testNodeID("source")
	targetNode := testNodeID("target")

	sourceConn := newTestNoiseConn("scope-1", sourceNode)
	addListenerSession(tr, "scope-1", targetNode, newTestNoiseConn("scope-1", targetNode))

	payload := buildRelayPayload(targetNode, []byte("hello"))
	target, err := tr.resolveRelayTarget(sourceConn, payload)
	if err != nil {
		t.Fatalf("expected success for same-scope relay, got: %v", err)
	}
	if target == nil {
		t.Fatal("target should not be nil")
	}
	if target.scopeID != "scope-1" {
		t.Fatalf("expected target scope scope-1, got %s", target.scopeID)
	}
}

func TestResolveRelayTarget_CrossTenant_Blocked(t *testing.T) {
	tr := newTestTransport()
	sourceNode := testNodeID("source")
	targetNode := testNodeID("target")

	sourceConn := newTestNoiseConn("scope-1", sourceNode)
	addListenerSession(tr, "scope-2", targetNode, newTestNoiseConn("scope-2", targetNode))

	payload := buildRelayPayload(targetNode, []byte("hello"))
	_, err := tr.resolveRelayTarget(sourceConn, payload)
	if err != relay.ErrTenantMismatch {
		t.Fatalf("expected ErrTenantMismatch, got: %v", err)
	}
}

func TestResolveRelayTarget_DedicatedMode_Allowed(t *testing.T) {
	tr := newTestTransport()
	sourceNode := testNodeID("source")
	targetNode := testNodeID("target")

	sourceConn := newTestNoiseConn("", sourceNode) // dedicated
	addListenerSession(tr, "", targetNode, newTestNoiseConn("", targetNode))

	payload := buildRelayPayload(targetNode, []byte("hello"))
	_, err := tr.resolveRelayTarget(sourceConn, payload)
	if err != nil {
		t.Fatalf("expected success for dedicated mode, got: %v", err)
	}
}

func TestResolveRelayTarget_MixedTenant_Allowed(t *testing.T) {
	// Source has scope, target is dedicated (empty) — should be allowed
	tr := newTestTransport()
	sourceNode := testNodeID("source")
	targetNode := testNodeID("target")

	sourceConn := newTestNoiseConn("scope-1", sourceNode)
	addListenerSession(tr, "", targetNode, newTestNoiseConn("", targetNode))

	payload := buildRelayPayload(targetNode, []byte("hello"))
	_, err := tr.resolveRelayTarget(sourceConn, payload)
	if err != nil {
		t.Fatalf("expected success for mixed mode, got: %v", err)
	}
}

func TestResolveRelayTarget_MixedTenant_Reverse(t *testing.T) {
	// Source is dedicated (empty), target has scope — should be allowed
	tr := newTestTransport()
	sourceNode := testNodeID("source")
	targetNode := testNodeID("target")

	sourceConn := newTestNoiseConn("", sourceNode)
	addListenerSession(tr, "scope-2", targetNode, newTestNoiseConn("scope-2", targetNode))

	payload := buildRelayPayload(targetNode, []byte("hello"))
	_, err := tr.resolveRelayTarget(sourceConn, payload)
	if err != nil {
		t.Fatalf("expected success for reverse mixed mode, got: %v", err)
	}
}

func TestResolveRelayTarget_NotEnabled(t *testing.T) {
	tr := newTestTransport()
	tr.relayConfig.Enabled = false

	sourceConn := newTestNoiseConn("scope-1", testNodeID("source"))
	payload := buildRelayPayload(testNodeID("target"), []byte("hello"))

	_, err := tr.resolveRelayTarget(sourceConn, payload)
	if err != relay.ErrRelayNotEnabled {
		t.Fatalf("expected ErrRelayNotEnabled, got: %v", err)
	}
}

func TestResolveRelayTarget_TargetUnreachable(t *testing.T) {
	tr := newTestTransport()
	sourceConn := newTestNoiseConn("scope-1", testNodeID("source"))

	payload := buildRelayPayload(testNodeID("unknown"), []byte("hello"))
	_, err := tr.resolveRelayTarget(sourceConn, payload)
	if err != relay.ErrTargetUnreachable {
		t.Fatalf("expected ErrTargetUnreachable, got: %v", err)
	}
}

func TestResolveRelayTarget_InvalidPacket(t *testing.T) {
	tr := newTestTransport()
	sourceConn := newTestNoiseConn("scope-1", testNodeID("source"))

	_, err := tr.resolveRelayTarget(sourceConn, []byte("short"))
	if err != relay.ErrInvalidPacket {
		t.Fatalf("expected ErrInvalidPacket, got: %v", err)
	}
}

func TestResolveRelayTarget_OutgoingSession_CrossTenant(t *testing.T) {
	tr := newTestTransport()
	sourceNode := testNodeID("source")
	targetNode := testNodeID("target")

	sourceConn := newTestNoiseConn("scope-1", sourceNode)
	targetConn := newTestNoiseConn("scope-2", targetNode)

	tr.outgoingMu.Lock()
	tr.outgoingSessions[string(targetNode)] = targetConn
	tr.outgoingMu.Unlock()

	payload := buildRelayPayload(targetNode, []byte("hello"))
	_, err := tr.resolveRelayTarget(sourceConn, payload)
	if err != relay.ErrTenantMismatch {
		t.Fatalf("expected ErrTenantMismatch for cross-scope outgoing, got: %v", err)
	}
}

func TestResolveRelayTarget_OutgoingSession_SameTenant(t *testing.T) {
	tr := newTestTransport()
	sourceNode := testNodeID("source")
	targetNode := testNodeID("target")

	sourceConn := newTestNoiseConn("scope-1", sourceNode)
	targetConn := newTestNoiseConn("scope-1", targetNode)

	tr.outgoingMu.Lock()
	tr.outgoingSessions[string(targetNode)] = targetConn
	tr.outgoingMu.Unlock()

	payload := buildRelayPayload(targetNode, []byte("hello"))
	target, err := tr.resolveRelayTarget(sourceConn, payload)
	if err != nil {
		t.Fatalf("expected success for same-scope outgoing, got: %v", err)
	}
	if target != targetConn {
		t.Fatal("expected target to be the outgoing session conn")
	}
}
