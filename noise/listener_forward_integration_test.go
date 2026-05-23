//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package noise

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// TestCrossOrgForwarder_HairpinRoundTrip wires three NoiseTransports in
// the same test process to verify the cross-org forwarder hairpin flow:
//
//	[originator] --dial--> [M_r]  -- OpForward --> [M_t]
//	    ^                    |
//	    +-- M_r unwraps -----+ <-- OpReply -------+
//
// The originator dials M_r's address but with target.NodeID = M_t's
// NodeID and Metadata[cross_org_preamble]="1". M_r's listener sees the
// preamble, learns the target is M_t (not local), wraps msg1 in
// OpForward, and ships it to M_t over the loopback "6PN" path. M_t's
// listener accepts via OpForward branch, injects the payload as if it
// came from the originator, runs the handshake, and replies. M_t's
// reply hits its writeFunc → T-table → OpReply → M_r → R-table →
// unwrap → write to originator from M_r's listener socket.
//
// A successful Send/Receive proves all four wire paths work end-to-end:
//   - originator → M_r:           routing-preamble msg1
//   - M_r → M_t:                  OpForward(msg1)
//   - M_t → M_r:                  OpReply(msg2 / data)
//   - M_r → originator:           unwrapped via R-table lookup
func TestCrossOrgForwarder_HairpinRoundTrip(t *testing.T) {
	// The pre-existing TestNoiseRoundTrip skips on Windows due to shared-
	// socket timing sensitivity; this test uses the same retry-with-backoff
	// pattern in its dial loop so it runs cross-platform.
	_ = runtime.GOOS
	const netKey = "cross-org-forwarder-test-key"

	// ─── M_t (target, holds the listener for the dialed NodeID) ─────
	_, mtPriv, _ := ed25519.GenerateKey(rand.Reader)
	mtPub := mtPriv.Public().(ed25519.PublicKey)
	mtNodeID, _ := aether.NewNodeID(mtPub)

	mtTransport, err := NewNoiseTransport(NoiseTransportConfig{
		PrivateKey:  mtPriv,
		LocalNode:   mtNodeID,
		ListenAddr:  "127.0.0.1:0",
		NetworkKeys: []string{netKey},
	})
	if err != nil {
		t.Fatalf("M_t NewNoiseTransport: %v", err)
	}
	// M_t MUST have a forwarder too — its writeFunc consults T-table
	// before each outbound write, and the OpForward ingress branch
	// REGISTERS T-table entries. Without a forwarder attached, M_t
	// can't accept the OpForward at all (the listener_forward.go
	// guard skips both branches when transport.forwarder == nil).
	mtFwd := NewIntraOrgForwarder(mtNodeID, nil)
	mtTransport.SetForwarder(mtFwd)
	t.Cleanup(func() { _ = mtTransport.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	mtListener, err := mtTransport.Listen(ctx)
	if err != nil {
		t.Fatalf("M_t Listen: %v", err)
	}
	mtAddr := mtListener.Addr().(*net.UDPAddr)
	t.Logf("M_t listening on %s (nodeID=%s)", mtAddr, mtNodeID.Short())

	// M_t echo server.
	mtReady := make(chan struct{})
	mtErr := make(chan error, 1)
	go func() {
		session, err := mtListener.Accept(ctx)
		if err != nil {
			mtErr <- err
			return
		}
		close(mtReady)
		for {
			data, rerr := session.Receive(ctx)
			if rerr != nil {
				_ = session.Close()
				return
			}
			if werr := session.Send(ctx, data); werr != nil {
				_ = session.Close()
				return
			}
		}
	}()

	// ─── M_r (anycast-receiving relay) ──────────────────────────────
	// M_r has its OWN NodeID. The lookup callback resolves mtNodeID
	// to M_t's loopback addr — that's the moral equivalent of M_r
	// reading the LAD reach cache and finding M_t's 6PN.
	_, mrPriv, _ := ed25519.GenerateKey(rand.Reader)
	mrPub := mrPriv.Public().(ed25519.PublicKey)
	mrNodeID, _ := aether.NewNodeID(mrPub)

	mrTransport, err := NewNoiseTransport(NoiseTransportConfig{
		PrivateKey:  mrPriv,
		LocalNode:   mrNodeID,
		ListenAddr:  "127.0.0.1:0",
		NetworkKeys: []string{netKey},
	})
	if err != nil {
		t.Fatalf("M_r NewNoiseTransport: %v", err)
	}
	mrFwd := NewIntraOrgForwarder(mrNodeID, func(target aether.NodeID) (*net.UDPAddr, bool) {
		if target == mtNodeID {
			return mtAddr, true
		}
		return nil, false
	})
	mrTransport.SetForwarder(mrFwd)
	t.Cleanup(func() { _ = mrTransport.Close() })

	mrListener, err := mrTransport.Listen(ctx)
	if err != nil {
		t.Fatalf("M_r Listen: %v", err)
	}
	mrAddr := mrListener.Addr().(*net.UDPAddr)
	t.Logf("M_r listening on %s (nodeID=%s)", mrAddr, mrNodeID.Short())

	// ─── Originator (the dialer) ────────────────────────────────────
	origPub, origPriv, _ := ed25519.GenerateKey(rand.Reader)
	origNodeID, _ := aether.NewNodeID(origPub)
	_ = origPub

	origTransport, err := NewNoiseTransport(NoiseTransportConfig{
		PrivateKey:  origPriv,
		LocalNode:   origNodeID,
		ListenAddr:  "127.0.0.1:0",
		NetworkKeys: []string{netKey},
	})
	if err != nil {
		t.Fatalf("originator NewNoiseTransport: %v", err)
	}
	t.Cleanup(func() { _ = origTransport.Close() })

	origListener, err := origTransport.Listen(ctx)
	if err != nil {
		t.Fatalf("originator Listen: %v", err)
	}
	defer origListener.Close()

	// Give all the listener read loops time to start.
	time.Sleep(80 * time.Millisecond)

	// ─── Dial: target = M_t's NodeID, address = M_r's addr, with the
	//        cross-org preamble metadata set so handshake.go emits the
	//        routing preamble on msg1/retransmits/msg3. ──────────────
	var origSession aether.Connection
	for attempt := 0; attempt < 3; attempt++ {
		dialCtx, dialCancel := context.WithTimeout(ctx, 4*time.Second)
		t.Logf("originator dial attempt %d: addr=%s target=%s", attempt+1, mrAddr, mtNodeID.Short())
		origSession, err = origTransport.Dial(dialCtx, aether.Target{
			NodeID:  mtNodeID,
			Address: mrAddr.String(),
			Metadata: map[string]string{
				MetadataKeyCrossOrgPreamble: "1",
			},
		})
		dialCancel()
		if err == nil {
			break
		}
		t.Logf("attempt %d failed: %v", attempt+1, err)
		time.Sleep(120 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("originator Dial via M_r → M_t: %v", err)
	}
	defer origSession.Close()

	// Wait for M_t's Accept to fire — proves the handshake completed
	// end-to-end on the responder side, not just the initiator side.
	select {
	case <-mtReady:
	case err := <-mtErr:
		t.Fatalf("M_t Accept failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for M_t Accept")
	}

	// R-table must hold an entry for the FlowID M_r generated. Can't
	// check FlowID directly (we never see it from outside), but size>0
	// proves M_r's onRoutingPreamble path ran.
	if got := mrFwd.RTableSize(); got == 0 {
		t.Error("M_r R-table empty — onRoutingPreamble didn't register FlowID")
	}
	// T-table on M_t must hold an entry for the originator addr.
	if got := mtFwd.TTableSize(); got == 0 {
		t.Error("M_t T-table empty — OpForward branch didn't register relayed source")
	}

	// ─── Data round-trip via the established session ────────────────
	// This exercises the post-handshake data path: encrypted payload
	// from originator → M_r → M_t → echo → M_r → originator.
	//
	// Note: the responder side sends an aether HANDSHAKE-typed frame
	// carrying 0.5-RTT resume material as the first encrypted payload
	// on the new session. The aether adapter layer normally dispatches
	// that frame internally; here we use raw noiseConn.Receive so we
	// drain non-echo frames until we see our payload.
	payload := []byte("hairpin hello")
	if err := origSession.Send(ctx, payload); err != nil {
		t.Fatalf("Send: %v", err)
	}
	drainCtx, drainCancel := context.WithTimeout(ctx, 5*time.Second)
	defer drainCancel()
	var resp []byte
	for i := 0; i < 4; i++ { // up to 4 drains — resume material + echo
		got, err := origSession.Receive(drainCtx)
		if err != nil {
			t.Fatalf("Receive (attempt %d): %v", i, err)
		}
		if bytes.Equal(got, payload) {
			resp = got
			break
		}
		t.Logf("drained non-echo frame (%d bytes) — likely resume material / control", len(got))
	}
	if resp == nil {
		t.Fatal("never received echo of payload — only control frames")
	}
	t.Logf("hairpin round-trip succeeded — R-table size=%d T-table size=%d", mrFwd.RTableSize(), mtFwd.TTableSize())
}
