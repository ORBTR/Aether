/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package adapter

import (
	"context"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/noise"
	fnoise "github.com/flynn/noise"
)

// The session AcceptSessionOverConn returns reports the node id the
// dialer stated in its handshake, and the peer id cut from it, as the
// dialer wrote them: the session layer adds no check of its own to what
// noise.AcceptOverConn reports.
func TestAcceptSessionOverConn_ReportsTheIDTheDialerStates(t *testing.T) {
	keypair := func() fnoise.DHKey {
		kp, err := fnoise.DH25519.GenerateKeypair(rand.Reader)
		if err != nil {
			t.Fatalf("generate keypair: %v", err)
		}
		return kp
	}
	accepter, dialer := keypair(), keypair()
	const accepterID = aether.NodeID("vl1_accepter")
	for _, stated := range []aether.NodeID{accepterID, "vl1_any-name-the-dialer-likes"} {
		clientConn, serverConn := net.Pipe()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		type accepted struct {
			sess *NoiseSession
			err  error
		}
		out := make(chan accepted, 1)
		go func() {
			s, err := AcceptSessionOverConn(ctx, noise.AcceptConnConfig{
				LocalNodeID:      accepterID,
				StaticPriv:       accepter.Private,
				StaticPub:        accepter.Public,
				HandshakeTimeout: 2 * time.Second,
			}, serverConn, aether.DefaultSessionOptions())
			out <- accepted{s, err}
		}()
		dialed, err := DialSessionOverConn(ctx, noise.DialConnConfig{
			LocalNodeID:      stated,
			StaticPriv:       dialer.Private,
			StaticPub:        dialer.Public,
			HandshakeTimeout: 2 * time.Second,
		}, clientConn, aether.DefaultSessionOptions())
		a := <-out
		cancel()
		if err != nil || a.err != nil {
			t.Fatalf("stating %q: dial %v, accept %v", stated, err, a.err)
		}
		if got := a.sess.RemoteNodeID(); got != stated {
			t.Errorf("stating %q: RemoteNodeID = %q, want the id the dialer stated", stated, got)
		}
		if got, want := a.sess.RemotePeerID(), stated.ToPeerID(); got != want {
			t.Errorf("stating %q: RemotePeerID = %v, want %v, the peer id of the stated id", stated, got, want)
		}
		_ = a.sess.Close()
		_ = dialed.Close()
	}
}
