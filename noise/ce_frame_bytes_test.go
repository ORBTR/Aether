//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package noise

import (
	"bytes"
	"testing"

	transportHealth "github.com/ORBTR/aether/health"
	"github.com/ORBTR/aether/relay"
	fnoise "github.com/flynn/noise"
)

// matchedCipherStates runs a Noise NN handshake and returns the initiator's
// send CipherState and the responder's receive CipherState, so a packet the
// first seals the second opens.
func matchedCipherStates(t *testing.T) (send, recv *fnoise.CipherState) {
	t.Helper()
	suite := fnoise.NewCipherSuite(fnoise.DH25519, fnoise.CipherChaChaPoly, fnoise.HashSHA256)
	initHS, err := fnoise.NewHandshakeState(fnoise.Config{Pattern: fnoise.HandshakeNN, Initiator: true, CipherSuite: suite})
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}
	respHS, err := fnoise.NewHandshakeState(fnoise.Config{Pattern: fnoise.HandshakeNN, CipherSuite: suite})
	if err != nil {
		t.Fatalf("responder: %v", err)
	}
	msg1, _, _, _ := initHS.WriteMessage(nil, nil)
	if _, _, _, err := respHS.ReadMessage(nil, msg1); err != nil {
		t.Fatalf("msg1: %v", err)
	}
	// The responder's first CipherState is initiator-to-responder: its receive side.
	msg2, respRecv, _, err := respHS.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("msg2 write: %v", err)
	}
	_, initSend, _, err := initHS.ReadMessage(nil, msg2)
	if err != nil {
		t.Fatalf("msg2 read: %v", err)
	}
	return initSend, respRecv
}

func ceTestConn(recv *fnoise.CipherState) *noiseConn {
	return &noiseConn{
		remoteNode: testNodeID("cePeer"),
		scopeID:    "scope-ce",
		recv:       recv,
		inbox:      make(chan []byte, 16),
		closed:     make(chan struct{}),
		health:     transportHealth.NewMonitor(0.2),
	}
}

// TestDecryptAndDeliver_CEMarkCountsTheFrameBytesTheSenderWrote: a CE-marked
// DATA datagram adds the payload its packet carries, the frame bytes the
// sending adapter passed to conn.Write, to the CE counter, not the datagram's
// length; the sender caps the CEBytes claim against those frame bytes
// (bytesSentSinceLastCE). An unmarked datagram adds nothing, and so does a
// marked datagram that fails AEAD, which dispatchToSession still claims.
func TestDecryptAndDeliver_CEMarkCountsTheFrameBytesTheSenderWrote(t *testing.T) {
	send, recv := matchedCipherStates(t)
	nc := ceTestConn(recv)
	frame := bytes.Repeat([]byte{0x5a}, 1000)
	seal := func() []byte {
		ct, err := send.Encrypt(nil, nil, append([]byte{relay.PacketTypeData}, frame...))
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		return ct
	}

	marked := seal()
	if len(marked) <= len(frame) {
		t.Fatalf("premise wrong: datagram of %d bytes for a %d-byte frame", len(marked), len(frame))
	}
	if err := nc.decryptAndDeliver(marked, true); err != nil {
		t.Fatalf("marked datagram: %v", err)
	}
	if got := nc.DrainCEBytes(); got != uint64(len(frame)) {
		t.Fatalf("CE bytes after one marked datagram: %d, want the frame's %d (the datagram is %d)", got, len(frame), len(marked))
	}

	if err := nc.decryptAndDeliver(seal(), false); err != nil {
		t.Fatalf("unmarked datagram: %v", err)
	}
	if got := nc.DrainCEBytes(); got != 0 {
		t.Fatalf("CE bytes after an unmarked datagram: %d, want 0", got)
	}

	tr := newTestTransport()
	l := tr.listener
	const key = "127.0.0.1:40000"
	l.sessions.Put(nc.remoteNode, key, nc.scopeID, &noiseConnSession{conn: nc, nodeID: nc.remoteNode})
	forged := bytes.Repeat([]byte{0x01}, len(marked))
	if !l.dispatchToSession(key, forged, true) {
		t.Fatal("premise wrong: the session mapped at the address did not claim the packet")
	}
	if got := nc.DrainCEBytes(); got != 0 {
		t.Fatalf("CE bytes after a marked datagram that failed AEAD: %d, want 0", got)
	}
}
