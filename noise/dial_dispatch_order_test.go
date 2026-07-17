//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package noise

import (
	"context"
	"net"
	"testing"
	"time"

	transportHealth "github.com/ORBTR/aether/health"
)

// TestDialResponseNotSwallowedByStaleSession pins the runReader dispatch order
// that keeps noise-UDP reachable at all.
//
// dispatchToSession claims EVERY packet arriving from an addr that has a
// session entry: it discards decryptAndDeliver's error and returns true
// regardless. A session still mapped at a peer's addr therefore swallows that
// peer's dial RETRY token and msg2 — both are handshake frames, so the AEAD
// open always fails. The dial then times out, AddressTracker marks the udp
// endpoint dead, the upgrade walker's bestAddress() returns "" and skips the
// candidate on every subsequent tick. noise-UDP ends up locked out for that
// peer permanently and the mesh silently rides the WebSocket fallback with no
// recovery path — observed fleet-wide as 0 noise-UDP links while WS/TLS stayed
// healthy. The solicited-dial dispatch must therefore precede the session fast
// path (and the first-contact flood limiters, which a dial response must not
// spend budget on).
func TestDialResponseNotSwallowedByStaleSession(t *testing.T) {
	lconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lconn.Close()

	tr := newTestTransport()
	tr.maxPacket = 2048
	// Deliberately permissive — this test pins dispatch ORDER, not the limits.
	tr.rateLimiter = newTokenBucket(1000, 1000, time.Second)

	l := tr.listener
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.runReader(ctx, lconn)

	sconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("sender listen: %v", err)
	}
	defer sconn.Close()
	senderKey := sconn.LocalAddr().String()

	// Session mapped at the sender's addr carrying REAL cipher state, so
	// decryptAndDeliver returns an AEAD error rather than panicking. This
	// matters: a panic would be caught by dispatchToSession's deferred
	// recover and yield the zero return (false), letting the packet fall
	// through and masking the very swallow this test exists to catch.
	_, recvCS := testSendRecvCipherStates(t)
	stalePeer := testNodeID("stalePeer")
	stale := &noiseConn{
		remoteNode: stalePeer,
		scopeID:    "scope-stale",
		recv:       recvCS,
		inbox:      make(chan []byte, 16),
		closed:     make(chan struct{}),
		health:     transportHealth.NewMonitor(0.2),
	}
	l.sessions.Put(stalePeer, senderKey, "scope-stale",
		&noiseConnSession{conn: stale, nodeID: stalePeer})

	// Register a dial and deliver its nonce-tagged response from that same addr.
	nonce, ch := l.registerPendingDial()
	payload := []byte("msg2-from-responder")
	pkt := append([]byte{dialNoncePrefix}, nonce...)
	pkt = append(pkt, payload...)

	if _, err := sconn.WriteToUDP(pkt, lconn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("send: %v", err)
	}

	select {
	case got := <-ch:
		if string(got) != string(payload) {
			t.Fatalf("payload mismatch: got %q, want %q", got, payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dial response was swallowed by the session mapped at the sender's addr: " +
			"the noise-UDP dial would time out, its address would be marked dead, and the " +
			"upgrade walker would skip that peer forever (permanent WebSocket fallback)")
	}
}
