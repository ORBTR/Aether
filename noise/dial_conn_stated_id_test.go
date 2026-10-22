/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */

package noise

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// acceptFromDialerStating runs one AcceptOverConn under cfg against a
// DialOverConn that presents ticket under the static key (priv, pub) and
// states stated as its own node id, and returns the accepted Connection.
// The caller closes it.
func acceptFromDialerStating(t *testing.T, cfg AcceptConnConfig, priv, pub, ticket []byte, stated aether.NodeID) (aether.Connection, error) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	type accepted struct {
		conn aether.Connection
		err  error
	}
	out := make(chan accepted, 1)
	go func() {
		c, err := AcceptOverConn(ctx, cfg, serverConn)
		out <- accepted{c, err}
	}()
	dialed, dialErr := DialOverConn(ctx, DialConnConfig{
		LocalNodeID:      stated,
		StaticPriv:       priv,
		StaticPub:        pub,
		Ticket:           ticket,
		GrantRealmFn:     realmFromGrant,
		HandshakeTimeout: 2 * time.Second,
	}, clientConn)
	a := <-out
	if dialErr == nil {
		t.Cleanup(func() { _ = dialed.Close() })
	} else {
		_ = clientConn.Close()
	}
	if a.err != nil {
		_ = serverConn.Close()
	}
	return a.conn, a.err
}

// The node id a dialer states in its msg3 payload is reported as it is.
// The accepter here verifies the ticket's signature, binds the ticket to
// the static key msg3 proved and spends the ticket's nonce; none of those
// reads the stated id, so the accepted Connection's RemoteNodeID is
// whatever the dialer wrote: the accepter's own id, which is also the
// grant's target, the id of an Ed25519 key the dialer does not hold, an
// id that names no key, and that id again from a second dialer with a key
// of its own. RemoteIdentity, the
// verified identity key some Connections carry, is nil on this path. This
// is what makes the stated id a label: a consumer that decides on it
// decides on what the dialer chose.
func TestAcceptOverConn_ReportsTheIDTheDialerStates(t *testing.T) {
	signerPub, signerPriv, err := generateTestEd25519(t)
	if err != nil {
		t.Fatalf("gen signer: %v", err)
	}
	cfg := bindingAcceptConfig(t, signerPub, NewTicketNonceCache(16))
	var bound [][]byte
	bind := cfg.ValidatePeerStaticFn
	cfg.ValidatePeerStaticFn = func(body, peerStatic []byte) error {
		bound = append(bound, append([]byte(nil), body...))
		return bind(body, peerStatic)
	}

	otherIdentity, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen identity key: %v", err)
	}
	notHeld, err := aether.NewNodeID(otherIdentity)
	if err != nil {
		t.Fatalf("NewNodeID: %v", err)
	}
	firstPriv, firstPub := newTestKeypair(t)
	secondPriv, secondPub := newTestKeypair(t)
	exp := time.Now().Add(time.Minute)

	for i, tc := range []struct {
		what      string
		priv, pub []byte
		stated    aether.NodeID
	}{
		{"the accepter's own id", firstPriv, firstPub, cfg.LocalNodeID},
		{"the id of a key the dialer does not hold", firstPriv, firstPub, notHeld},
		{"an id that names no key", firstPriv, firstPub, "vl1_any-name-the-dialer-likes"},
		{"that id from a second dialer's key", secondPriv, secondPub, "vl1_any-name-the-dialer-likes"},
	} {
		ticket := grantTicket(t, signerPriv, tc.pub, []byte(fmt.Sprintf("nonce-stated-%04d", i)), exp)
		conn, err := acceptFromDialerStating(t, cfg, tc.priv, tc.pub, ticket, tc.stated)
		if err != nil {
			t.Fatalf("%s: AcceptOverConn refused a dialer holding an admitted grant: %v", tc.what, err)
		}
		if got := conn.RemoteNodeID(); got != tc.stated {
			t.Errorf("%s: RemoteNodeID = %q, want %q, the id the dialer stated", tc.what, got, tc.stated)
		}
		if id, ok := conn.(interface{ RemoteIdentity() ed25519.PublicKey }); ok && id.RemoteIdentity() != nil {
			t.Errorf("%s: RemoteIdentity = %x, want nil: nothing on this path verifies an identity key", tc.what, id.RemoteIdentity())
		}
		_ = conn.Close()
		if len(bound) != i+1 {
			t.Fatalf("%s: the key binding ran %d times over %d accepts, want once per accept", tc.what, len(bound), i+1)
		}
		if !bytes.Equal(bound[i], ticket[:len(ticket)-ed25519.SignatureSize]) {
			t.Errorf("%s: the key binding saw a body that is not the verified grant's", tc.what)
		}
	}
}
