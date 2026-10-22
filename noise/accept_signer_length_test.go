/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package noise

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// An accepter configured with a ticket signer that is not a 32-byte key is
// refused when the accept starts, whatever the dialer sends. ed25519.Verify
// panics on a key of another length, and the accept reaches it as soon as a
// dialer sends 64 bytes of ticket, so without the refusal any dialer stops a
// goroutine of an accepter whose signer was loaded wrong. The signer a
// per-ticket resolver returns is length-checked where it is resolved.
func TestAcceptOverConn_RefusesATicketSignerOfTheWrongLength(t *testing.T) {
	for _, n := range []int{0, 31, 33} {
		t.Run(fmt.Sprintf("%d bytes", n), func(t *testing.T) {
			priv, pub := newTestKeypair(t)
			dPriv, dPub := newTestKeypair(t)
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			out := make(chan string, 1)
			go func() {
				defer func() {
					if r := recover(); r != nil {
						out <- fmt.Sprintf("panic: %v", r)
					}
				}()
				_, err := AcceptOverConn(ctx, AcceptConnConfig{LocalNodeID: "vl1_bob", StaticPriv: priv, StaticPub: pub,
					TrustedTicketSigner: make(ed25519.PublicKey, n), HandshakeTimeout: 2 * time.Second}, serverConn)
				out <- fmt.Sprintf("returned: %v", err)
			}()
			go func() {
				_, _ = DialOverConn(ctx, DialConnConfig{LocalNodeID: "vl1_x", StaticPriv: dPriv, StaticPub: dPub,
					Ticket: make([]byte, 64), GrantRealmFn: fixedRealm, HandshakeTimeout: 2 * time.Second}, clientConn)
			}()

			got := <-out
			if strings.HasPrefix(got, "panic") {
				t.Fatalf("AcceptOverConn with a %d-byte ticket signer: %s", n, got)
			}
			if !strings.Contains(got, "TrustedTicketSigner") {
				t.Fatalf("AcceptOverConn with a %d-byte ticket signer %s; want a refusal naming the signer", n, got)
			}
		})
	}
}
