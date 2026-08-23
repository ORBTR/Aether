package noise

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// signerFor mirrors how a relay resolves a per-tenant signer: parse the tenant
// scope out of the (unverified) ticket body and return that tenant's public key.
func signerFor(keys map[string]ed25519.PublicKey) func(body []byte) (ed25519.PublicKey, error) {
	return func(body []byte) (ed25519.PublicKey, error) {
		var t struct {
			Scope string `json:"scope"`
		}
		if err := json.Unmarshal(body, &t); err != nil {
			return nil, fmt.Errorf("bad body: %w", err)
		}
		pub, ok := keys[t.Scope]
		if !ok {
			return nil, fmt.Errorf("unknown tenant %q", t.Scope)
		}
		return pub, nil
	}
}

// A per-tenant resolver selects the right tenant's key from the ticket body and
// the handshake completes — the multi-tenant relay path.
func TestAcceptOverConn_PerTenantSignerResolved(t *testing.T) {
	aPriv, aPub := newTestKeypair(t)
	bPriv, bPub := newTestKeypair(t)

	pubA, privA, err := generateTestEd25519(t)
	if err != nil {
		t.Fatalf("gen tenant-A signer: %v", err)
	}
	pubB, _, err := generateTestEd25519(t)
	if err != nil {
		t.Fatalf("gen tenant-B signer: %v", err)
	}
	keys := map[string]ed25519.PublicKey{"tenant-A": pubA, "tenant-B": pubB}

	// A ticket for tenant-A, signed by tenant-A's key.
	body := []byte(`{"target":"vl1_agent-xyz","scope":"tenant-A"}`)
	sig := ed25519Sign(privA, body)
	ticket := append(append([]byte(nil), body...), sig...)

	clientConn, serverConn := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var (
		wg        sync.WaitGroup
		acceptErr error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, acceptErr = AcceptOverConn(ctx, AcceptConnConfig{
			LocalNodeID:           "vl1_relay",
			StaticPriv:            bPriv,
			StaticPub:             bPub,
			TrustedTicketSignerFn: signerFor(keys),
			HandshakeTimeout:      2 * time.Second,
		}, serverConn)
	}()

	if _, err := DialOverConn(ctx, DialConnConfig{
		LocalNodeID:      "vl1_browser",
		StaticPriv:       aPriv,
		StaticPub:        aPub,
		Ticket:           ticket,
		HandshakeTimeout: 2 * time.Second,
	}, clientConn); err != nil {
		t.Fatalf("DialOverConn: %v", err)
	}
	wg.Wait()
	if acceptErr != nil {
		t.Fatalf("AcceptOverConn with resolved tenant-A signer: %v", acceptErr)
	}
}

// Tenant isolation: a ticket whose body claims tenant-A but is signed by a
// different key is rejected — the resolver picks tenant-A's real key, and the
// forged signature fails against it. A ticket forged in one tenant cannot cross
// into another.
func TestAcceptOverConn_PerTenantCrossTenantForgeryRejected(t *testing.T) {
	aPriv, aPub := newTestKeypair(t)
	bPriv, bPub := newTestKeypair(t)

	pubA, _, err := generateTestEd25519(t)
	if err != nil {
		t.Fatalf("gen tenant-A signer: %v", err)
	}
	// The attacker signs with their OWN key, not tenant-A's.
	_, attackerPriv, err := generateTestEd25519(t)
	if err != nil {
		t.Fatalf("gen attacker signer: %v", err)
	}
	keys := map[string]ed25519.PublicKey{"tenant-A": pubA}

	body := []byte(`{"target":"vl1_agent-xyz","scope":"tenant-A"}`)
	sig := ed25519Sign(attackerPriv, body) // signed by the wrong key
	ticket := append(append([]byte(nil), body...), sig...)

	clientConn, serverConn := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var (
		wg        sync.WaitGroup
		acceptErr error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, acceptErr = AcceptOverConn(ctx, AcceptConnConfig{
			LocalNodeID:           "vl1_relay",
			StaticPriv:            bPriv,
			StaticPub:             bPub,
			TrustedTicketSignerFn: signerFor(keys),
			HandshakeTimeout:      2 * time.Second,
		}, serverConn)
	}()

	// The dial may or may not error depending on timing; the accept MUST reject.
	_, _ = DialOverConn(ctx, DialConnConfig{
		LocalNodeID:      "vl1_browser",
		StaticPriv:       aPriv,
		StaticPub:        aPub,
		Ticket:           ticket,
		HandshakeTimeout: 2 * time.Second,
	}, clientConn)
	wg.Wait()
	if acceptErr == nil {
		t.Fatal("AcceptOverConn accepted a ticket signed by the wrong key (cross-tenant forgery)")
	}
}
