//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package noise

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	aether "github.com/ORBTR/aether"
	transportCrypto "github.com/ORBTR/aether/crypto/identity"
	"github.com/ORBTR/aether/relay"
	"github.com/flynn/noise"
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
		scopeID:    scopeID,
		inbox:      make(chan []byte, 16),
		closed:     make(chan struct{}),
	}
}

// newTestTransport creates a NoiseTransport with relay enabled and a listener.
func newTestTransport() *NoiseTransport {
	t := &NoiseTransport{
		relayConfig: relay.RelayConfig{Enabled: true},
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

func TestPartitionSessionIndex_AddRemove(t *testing.T) {
	tr := newTestTransport()
	l := tr.listener

	nodeA := testNodeID("nodeA")
	nodeB := testNodeID("nodeB")

	addListenerSession(tr, "scope-1", nodeA, newTestNoiseConn("scope-1", nodeA))
	addListenerSession(tr, "scope-1", nodeB, newTestNoiseConn("scope-1", nodeB))

	if l.sessions.PartitionCount("scope-1") != 2 {
		t.Fatalf("expected 2 sessions for scope-1, got %d", l.sessions.PartitionCount("scope-1"))
	}

	// Remove one session
	l.sessions.Remove(nodeA)

	if l.sessions.PartitionCount("scope-1") != 1 {
		t.Fatalf("expected 1 session for scope-1 after remove, got %d", l.sessions.PartitionCount("scope-1"))
	}

	// Remove last session — scope entry should be cleaned up
	l.sessions.Remove(nodeB)
	if l.sessions.HasPartition("scope-1") {
		t.Fatal("expected scope-1 entry to be cleaned up when empty")
	}
}

func TestPartitionSessionIndex_EmptyPartition(t *testing.T) {
	tr := newTestTransport()
	l := tr.listener
	nodeA := testNodeID("nodeA")

	addListenerSession(tr, "", nodeA, newTestNoiseConn("", nodeA))

	if l.sessions.PartitionCountAll() != 0 {
		t.Fatal("expected no scope entries for empty scope (dedicated mode)")
	}
}

func TestPartitionSessionIndex_MultiplePartitions(t *testing.T) {
	tr := newTestTransport()
	l := tr.listener

	nodeA := testNodeID("nodeA")
	nodeB := testNodeID("nodeB")
	nodeC := testNodeID("nodeC")

	addListenerSession(tr, "scope-1", nodeA, newTestNoiseConn("scope-1", nodeA))
	addListenerSession(tr, "scope-2", nodeB, newTestNoiseConn("scope-2", nodeB))
	addListenerSession(tr, "scope-1", nodeC, newTestNoiseConn("scope-1", nodeC))

	if l.sessions.PartitionCount("scope-1") != 2 {
		t.Errorf("expected 2 sessions for scope-1, got %d", l.sessions.PartitionCount("scope-1"))
	}
	if l.sessions.PartitionCount("scope-2") != 1 {
		t.Errorf("expected 1 session for scope-2, got %d", l.sessions.PartitionCount("scope-2"))
	}
}

func TestPartitionForNode(t *testing.T) {
	tr := newTestTransport()
	l := tr.listener
	nodeA := testNodeID("nodeA")
	addListenerSession(tr, "scope-1", nodeA, newTestNoiseConn("scope-1", nodeA))

	scope := l.partitionForNode(nodeA)
	if scope != "scope-1" {
		t.Fatalf("expected scope-1, got %s", scope)
	}

	scope = l.partitionForNode(testNodeID("unknown"))
	if scope != "" {
		t.Fatalf("expected empty string for unknown node, got %s", scope)
	}
}

// ---------- relay routing + scope isolation tests ----------
// These tests use resolveRelayTarget() directly to test routing and scope
// validation without requiring real Noise cipher states.

func TestResolveRelayTarget_SamePartition_Allowed(t *testing.T) {
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

func TestResolveRelayTarget_CrossPartition_Blocked(t *testing.T) {
	tr := newTestTransport()
	sourceNode := testNodeID("source")
	targetNode := testNodeID("target")

	sourceConn := newTestNoiseConn("scope-1", sourceNode)
	addListenerSession(tr, "scope-2", targetNode, newTestNoiseConn("scope-2", targetNode))

	payload := buildRelayPayload(targetNode, []byte("hello"))
	_, err := tr.resolveRelayTarget(sourceConn, payload)
	if err != relay.ErrPartitionMismatch {
		t.Fatalf("expected ErrPartitionMismatch, got: %v", err)
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

func TestResolveRelayTarget_MixedPartition_Allowed(t *testing.T) {
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

func TestResolveRelayTarget_MixedPartition_Reverse(t *testing.T) {
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

func TestResolveRelayTarget_OutgoingSession_CrossPartition(t *testing.T) {
	tr := newTestTransport()
	sourceNode := testNodeID("source")
	targetNode := testNodeID("target")

	sourceConn := newTestNoiseConn("scope-1", sourceNode)
	targetConn := newTestNoiseConn("scope-2", targetNode)

	// A dialled session enters the listener's session map through
	// registerDialSession, as the dial path registers it.
	tr.listener.registerDialSession(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}, targetConn, targetNode)

	payload := buildRelayPayload(targetNode, []byte("hello"))
	_, err := tr.resolveRelayTarget(sourceConn, payload)
	if err != relay.ErrPartitionMismatch {
		t.Fatalf("expected ErrPartitionMismatch for cross-scope outgoing, got: %v", err)
	}
}

func TestResolveRelayTarget_OutgoingSession_SamePartition(t *testing.T) {
	tr := newTestTransport()
	sourceNode := testNodeID("source")
	targetNode := testNodeID("target")

	sourceConn := newTestNoiseConn("scope-1", sourceNode)
	targetConn := newTestNoiseConn("scope-1", targetNode)

	// A dialled session enters the listener's session map through
	// registerDialSession, as the dial path registers it.
	tr.listener.registerDialSession(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4243}, targetConn, targetNode)

	payload := buildRelayPayload(targetNode, []byte("hello"))
	target, err := tr.resolveRelayTarget(sourceConn, payload)
	if err != nil {
		t.Fatalf("expected success for same-scope outgoing, got: %v", err)
	}
	if target != targetConn {
		t.Fatal("expected target to be the outgoing session conn")
	}
}

// ---------- relayed handshake: the responder's wire-version choice ----------

// relayedResponder is a listener with no socket of its own, which is every
// input handleRelayedHandshake reads: the transport (its offer, static key,
// network keys and NodeInfo), the pending handshakes, the session map, the
// accept queue and the drop counters. The test builds it without Listen so the
// msg2 the responder writes goes nowhere but the relay conn's writeFunc.
type relayedResponder struct {
	transport *NoiseTransport
	listener  *noiseListener
	// relayConn stands for the Noise session to the relay node through which
	// the initiator's packets arrive. Its send cipher is matched by decrypt, so
	// the test can read the msg2 the responder hands sendRelayRequest.
	relayConn *noiseConn
	decrypt   *noise.CipherState
	// written receives every ciphertext the responder writes to the relay conn.
	written chan []byte
}

func newRelayedResponder(t *testing.T, app aether.WireVersions) *relayedResponder {
	t.Helper()
	tr := wvTransport(t, app, nil)
	l := &noiseListener{
		transport:  tr,
		handshakes: make(map[string]*listenerHandshake),
		sessions:   aether.NewConnectionMap(),
		incoming:   make(chan aether.IncomingSession, 1),
	}
	suite := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("key: %v", err)
	}
	r := &relayedResponder{transport: tr, listener: l, decrypt: noise.UnsafeNewCipherState(suite, key, 0), written: make(chan []byte, 4)}
	cfg := aether.DefaultSessionConfig()
	r.relayConn = &noiseConn{
		send:      noise.UnsafeNewCipherState(suite, key, 0),
		closed:    make(chan struct{}),
		transport: tr,
		rekey:     NewRekeyTracker(cfg.RekeyAfterBytes, cfg.RekeyAfterDuration),
		writeFunc: func(ct []byte) (int, error) { r.written <- append([]byte(nil), ct...); return len(ct), nil },
	}
	return r
}

// readRelayed returns the payload of the one relay request the responder wrote
// for source: the frame it asked the relay to forward.
func (r *relayedResponder) readRelayed(t *testing.T, source aether.NodeID) []byte {
	t.Helper()
	var ct []byte
	select {
	case ct = <-r.written:
	case <-time.After(2 * time.Second):
		t.Fatalf("the responder wrote nothing to the relay")
	}
	pt, err := r.decrypt.Decrypt(nil, nil, ct)
	if err != nil {
		t.Fatalf("decrypt the responder's relay frame: %v", err)
	}
	if len(pt) < 1+relay.RelayHeaderSize || pt[0] != relay.PacketTypeRelayRequest || aether.NodeID(pt[1:1+relay.RelayHeaderSize]) != source {
		t.Fatalf("the responder wrote %d bytes of type 0x%02x for %q, want a relay request for %q",
			len(pt), pt[0], pt[1:1+relay.RelayHeaderSize], source)
	}
	return pt[1+relay.RelayHeaderSize:]
}

// wroteNothingMore reports whether the responder wrote no second frame.
func (r *relayedResponder) wroteNothingMore() bool {
	select {
	case <-r.written:
		return false
	case <-time.After(100 * time.Millisecond):
		return true
	}
}

// relayedInitiator drives the initiator's side of a relayed handshake by hand,
// as a peer whose packets reach the responder through a relay node: msg1 as
// the relay delivers it, then msg3 carrying the signed NodeInfo payload3. It
// makes no choice of its own, so the responder's choice is the only one
// between its msg3 and a relayed conn, which is what the tests below need.
func relayedInitiator(t *testing.T, r *relayedResponder, source aether.NodeID, id *transportCrypto.Identity, payload3 []byte) error {
	t.Helper()
	hs, err := noise.NewHandshakeState(noise.Config{
		Pattern:       noise.HandshakeXX,
		Initiator:     true,
		Prologue:      []byte(wvTestNetKey),
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		StaticKeypair: noise.DHKey{Private: id.Curve25519Priv, Public: id.Curve25519Pub},
		Random:        rand.Reader,
	})
	if err != nil {
		t.Fatalf("handshake state: %v", err)
	}
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("msg1: %v", err)
	}
	pkt := make([]byte, 5, 5+len(msg1))
	binary.BigEndian.PutUint32(pkt, transportCrypto.CRC32Hash([]byte(wvTestNetKey)))
	pkt[4] = patternFlagXX
	pkt = append(pkt, msg1...)
	if err := r.listener.handleRelayedHandshake(r.relayConn, string(source), pkt); err != nil {
		t.Fatalf("relayed msg1: %v", err)
	}
	msg2 := r.readRelayed(t, source)
	if _, _, _, err := hs.ReadMessage(nil, msg2); err != nil {
		t.Fatalf("msg2: %v", err)
	}
	msg3, _, _, err := hs.WriteMessage(nil, payload3)
	if err != nil {
		t.Fatalf("msg3: %v", err)
	}
	return r.listener.handleRelayedHandshake(r.relayConn, string(source), msg3)
}

// TestRelayedResponder_RefusesAMismatchedOfferBeforeAnyState: a relayed
// initiator whose offer requires an entry the responder lacks, and one that
// lacks an entry the responder requires, are each refused at msg3 with the
// typed mismatch naming that entry, counted under wire_version_mismatch, and
// leave the responder as it was: no relayed conn, no session-map entry, no
// pending handshake, nothing on the accept queue, no peer key cached for the
// initiator and no second frame written to the relay. The control arm, an
// initiator offering what this build offers, is admitted through the same
// harness and reports the chosen set, so the refusals are the entry's.
func TestRelayedResponder_RefusesAMismatchedOfferBeforeAnyState(t *testing.T) {
	codec := aether.WireVersions{{Name: "gossip.codec", Versions: []uint16{1}, Required: true}}
	for _, tc := range []struct {
		name         string
		responderApp aether.WireVersions
		initiatorApp aether.WireVersions
		entry        string
	}{
		{
			name:         "the initiator requires an entry the responder lacks",
			responderApp: codec,
			initiatorApp: append(aether.WireVersions{}, codec[0], aether.WireVersion{Name: "zz.initiator-only", Versions: []uint16{1}, Required: true}),
			entry:        "zz.initiator-only",
		},
		{
			name:         "the responder requires an entry the initiator lacks",
			responderApp: append(aether.WireVersions{}, codec[0], aether.WireVersion{Name: "zz.responder-only", Versions: []uint16{1}, Required: true}),
			initiatorApp: codec,
			entry:        "zz.responder-only",
		},
		{
			name:         "both offer the same entries",
			responderApp: codec,
			initiatorApp: codec,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRelayedResponder(t, tc.responderApp)
			_, priv, _ := ed25519.GenerateKey(rand.Reader)
			id, err := transportCrypto.NewIdentity(priv)
			if err != nil {
				t.Fatalf("identity: %v", err)
			}
			offer, err := aether.LocalWireVersions(tc.initiatorApp)
			if err != nil {
				t.Fatalf("offer: %v", err)
			}
			payload3, err := id.EncodeNodeInfo(capExplicitNonce, 0, offer)
			if err != nil {
				t.Fatalf("NodeInfo: %v", err)
			}
			source := testNodeID("relayed-initiator")
			err = relayedInitiator(t, r, source, id, payload3)
			l := r.listener

			if tc.entry == "" {
				if err != nil {
					t.Fatalf("control arm refused: %v", err)
				}
				if l.sessions.Get(id.NodeID) == nil {
					t.Fatalf("control arm registered no session")
				}
				select {
				case in := <-l.incoming:
					want := mustChoose(t, r.transport.wireVersions, offer)
					if got := chosenOn(t, in.Session); !got.Equal(want) {
						t.Fatalf("control arm chose %v, want %v", got, want)
					}
					_ = in.Session.Close()
				case <-time.After(time.Second):
					t.Fatalf("control arm delivered no session to the accept queue")
				}
				if len(l.handshakes) != 0 {
					t.Fatalf("control arm left %d pending handshake(s)", len(l.handshakes))
				}
				return
			}

			var mm *aether.WireVersionMismatchError
			if !errors.Is(err, aether.ErrWireVersionMismatch) || !errors.As(err, &mm) || mm.Name != tc.entry {
				t.Fatalf("relayed msg3 err = %v, want the mismatch naming %q", err, tc.entry)
			}
			if got := l.DropSnapshot()[DropWireVersionMismatch.String()]; got != 1 {
				t.Fatalf("wire_version_mismatch counted %d times, want 1", got)
			}
			if l.sessions.Get(id.NodeID) != nil {
				t.Fatalf("a session is registered for the refused initiator")
			}
			if _, pending := l.handshakes[string(source)]; pending {
				t.Fatalf("the refused handshake is still pending")
			}
			select {
			case in := <-l.incoming:
				_ = in.Session.Close()
				t.Fatalf("a relayed conn reached the accept queue after the refusal")
			case <-time.After(100 * time.Millisecond):
			}
			if key := r.transport.lookupPeerKey(id.NodeID); key != nil {
				t.Fatalf("the refused initiator's static key is cached")
			}
			if !r.wroteNothingMore() {
				t.Fatalf("the responder wrote to the relay after refusing msg3")
			}
		})
	}
}
