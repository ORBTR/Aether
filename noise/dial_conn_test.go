/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

package noise

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/flynn/noise"
)

// newTestKeypair generates a Curve25519 static keypair for DialOverConn
// tests. Returns (priv, pub). Uses the noise library's DH25519 suite
// directly — same primitive DialOverConn uses internally.
func newTestKeypair(t *testing.T) ([]byte, []byte) {
	t.Helper()
	suite := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	kp, err := suite.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	return kp.Private, kp.Public
}

// Round-trip: DialOverConn and AcceptOverConn against each other over a
// net.Pipe must complete the handshake and produce sessions that each
// believe the other to be the expected NodeID.
func TestDialAcceptOverConn_RoundTrip(t *testing.T) {
	aPriv, aPub := newTestKeypair(t)
	bPriv, bPub := newTestKeypair(t)

	aID := aether.NodeID("vl1_alice-test")
	bID := aether.NodeID("vl1_bob-test")

	clientConn, serverConn := net.Pipe()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var (
		wg           sync.WaitGroup
		acceptSess   aether.Connection
		acceptErr    error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		acceptSess, acceptErr = AcceptOverConn(ctx, AcceptConnConfig{
			LocalNodeID:      bID,
			StaticPriv:       bPriv,
			StaticPub:        bPub,
			HandshakeTimeout: 2 * time.Second,
		}, serverConn)
	}()

	dialSess, err := DialOverConn(ctx, DialConnConfig{
		LocalNodeID:      aID,
		StaticPriv:       aPriv,
		StaticPub:        aPub,
		HandshakeTimeout: 2 * time.Second,
	}, clientConn)
	if err != nil {
		t.Fatalf("DialOverConn: %v", err)
	}
	wg.Wait()
	if acceptErr != nil {
		t.Fatalf("AcceptOverConn: %v", acceptErr)
	}

	if dialSess.RemoteNodeID() != bID {
		t.Errorf("dial side: remote = %s, want %s", dialSess.RemoteNodeID(), bID)
	}
	if acceptSess.RemoteNodeID() != aID {
		t.Errorf("accept side: remote = %s, want %s", acceptSess.RemoteNodeID(), aID)
	}
	_ = dialSess.Close()
	_ = acceptSess.Close()
}

// Ticket carried in the preamble is validated by the responder. A good
// signature passes, a bad signature fails the handshake before any
// Noise state is advanced.
func TestAcceptOverConn_TicketGoodSignatureAccepted(t *testing.T) {
	aPriv, aPub := newTestKeypair(t)
	bPriv, bPub := newTestKeypair(t)

	signerPub, signerPriv, err := generateTestEd25519(t)
	if err != nil {
		t.Fatalf("gen signer: %v", err)
	}

	body := []byte(`{"target":"vl1_agent-xyz","scope":"tenant-42"}`)
	sig := ed25519Sign(signerPriv, body)
	ticket := append(append([]byte(nil), body...), sig...)

	clientConn, serverConn := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var (
		wg          sync.WaitGroup
		validated   bool
		acceptErr   error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, acceptErr = AcceptOverConn(ctx, AcceptConnConfig{
			LocalNodeID:         "vl1_bob",
			StaticPriv:          bPriv,
			StaticPub:           bPub,
			TrustedTicketSigner: signerPub,
			ValidateTicketFn: func(b []byte) error {
				if string(b) != string(body) {
					return fmt.Errorf("body mismatch")
				}
				validated = true
				return nil
			},
			HandshakeTimeout: 2 * time.Second,
		}, serverConn)
	}()

	if _, err := DialOverConn(ctx, DialConnConfig{
		LocalNodeID:      "vl1_alice",
		StaticPriv:       aPriv,
		StaticPub:        aPub,
		Ticket:           ticket,
		HandshakeTimeout: 2 * time.Second,
	}, clientConn); err != nil {
		t.Fatalf("DialOverConn: %v", err)
	}
	wg.Wait()
	if acceptErr != nil {
		t.Fatalf("AcceptOverConn: %v", acceptErr)
	}
	if !validated {
		t.Fatal("ValidateTicketFn was not invoked after a good sig")
	}
}

// Bad ticket signature is rejected before the Noise handshake runs.
func TestAcceptOverConn_TicketBadSignatureRejected(t *testing.T) {
	aPriv, aPub := newTestKeypair(t)
	bPriv, bPub := newTestKeypair(t)

	signerPub, _, err := generateTestEd25519(t)
	if err != nil {
		t.Fatalf("gen signer: %v", err)
	}

	body := []byte("scope=tenant-42")
	// Sign with a DIFFERENT key — signature won't verify against signerPub.
	_, otherPriv, err := generateTestEd25519(t)
	if err != nil {
		t.Fatalf("gen other: %v", err)
	}
	badSig := ed25519Sign(otherPriv, body)
	ticket := append(append([]byte(nil), body...), badSig...)

	clientConn, serverConn := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var acceptErr error
	go func() {
		_, acceptErr = AcceptOverConn(ctx, AcceptConnConfig{
			LocalNodeID:         "vl1_bob",
			StaticPriv:          bPriv,
			StaticPub:           bPub,
			TrustedTicketSigner: signerPub,
			HandshakeTimeout:    2 * time.Second,
		}, serverConn)
	}()

	if _, err := DialOverConn(ctx, DialConnConfig{
		LocalNodeID: "vl1_alice",
		StaticPriv:  aPriv,
		StaticPub:   aPub,
		Ticket:      ticket,
		HandshakeTimeout: 2 * time.Second,
	}, clientConn); err == nil {
		t.Fatal("DialOverConn succeeded despite bad ticket sig on accept side")
	}
	// Wait for accept goroutine (may have errored already)
	time.Sleep(50 * time.Millisecond)
	if acceptErr == nil {
		t.Error("AcceptOverConn succeeded with bad ticket signature")
	}
}
