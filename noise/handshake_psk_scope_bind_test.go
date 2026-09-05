//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package noise

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	aether "github.com/ORBTR/aether"
)

// scopeKeyResolver is a static in-memory TenantKeyResolver mapping a scope ID
// to the PSK(s) that scope is permitted to present. It is the responder's
// authority for the PSK->ScopeID derivation under test.
type scopeKeyResolver map[string][][]byte

func (r scopeKeyResolver) ResolveKeys(scopeID string) ([][]byte, error) {
	keys, ok := r[scopeID]
	if !ok || len(keys) == 0 {
		return nil, fmt.Errorf("unknown scope %q", scopeID)
	}
	return keys, nil
}

// scopeOf reads the transport-derived scope off an accepted session using the
// SAME public-interface unwrap a real consumer uses: Accept hands back a
// *BaseConnection (an aether.Connection, which itself carries no scope);
// ConnProvider.NetConn() exposes the underlying transport conn, which — for a
// preamble session — implements aether.TenantAwareSession and returns the scope
// the responder DERIVED from the matched PSK.
func scopeOf(t *testing.T, c aether.Connection) string {
	t.Helper()
	cp, ok := c.(aether.ConnProvider)
	if !ok {
		t.Fatalf("accepted session %T is not a ConnProvider — cannot reach the transport scope", c)
	}
	ts, ok := cp.NetConn().(aether.TenantAwareSession)
	if !ok {
		t.Fatalf("underlying conn %T does not implement aether.TenantAwareSession", cp.NetConn())
	}
	return ts.ScopeID()
}

// newScopeTestTransport builds a listening-capable NoiseTransport with a fresh
// identity. resolver is set on the responder (it resolves preamble-bearing
// msg1s); the initiator passes nil and carries its scope+keys per-dial via
// WithDialOverride.
func newScopeTestTransport(t *testing.T, resolver TenantKeyResolver) (*NoiseTransport, aether.NodeID) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	nodeID, err := aether.NewNodeID(pub)
	if err != nil {
		t.Fatalf("node id: %v", err)
	}
	tr, err := NewNoiseTransport(NoiseTransportConfig{
		PrivateKey:  priv,
		LocalNode:   nodeID,
		ListenAddr:  "127.0.0.1:0",
		NetworkKeys: []string{"dedicated-placeholder-key-unused-in-preamble-mode"},
		// The derivation runs on preamble-bearing packets resolved via this
		// resolver; nil on the initiator (scope+keys travel via WithDialOverride).
		TenantKeyResolver: resolver,
		// Amplification retry is orthogonal to PSK->ScopeID derivation; disabling
		// it lets the reject path fire on the first msg1 (fast, deterministic).
		RequireRetryToken: BoolPtr(false),
	})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	return tr, nodeID
}

// TestHandshakePSKtoScopeIDBind proves aether's transport half of Directive-1:
// a Noise session's ScopeID is DERIVED from the tenant PSK the initiator proves
// possession of during the handshake, NOT from the (unauthenticated) scope the
// initiator merely claims in its preamble. This is #R-714 link-1 — the root of
// the enforcement chain the mock-TenantAwareSession matrix (R-742) assumes but
// cannot itself prove.
//
// Before this test the coverage was PIECES only, never the bind:
//   - preamble_test.go            — preamble WIRE encode/decode
//   - session_ticket_scope_test.go — ticket/RESUME path preserves ScopeID
//   - relay_scope_test.go/ael10   — relay ISOLATION given a scope
//
// None drove a real handshake and asserted the derived session scope.
//
// The bind (handshake.go): resolveHandshakeKey resolves the preamble's claimed
// partition to that scope's registered PSKs, requires the msg1 CRC32 fingerprint to
// match one of them, and only then stamps scopeID = tenant on the accepted
// session (handshake.go:1007). Possession is finalised by the full Noise
// handshake, which mixes the matched PSK as the prologue — a claimant without
// the key cannot complete it and never reaches the accept path.
//
//	right PSK for scope  -> session.ScopeID() == that scope
//	wrong PSK for scope  -> handshake REJECTED (DropHandshakeKeyUnresolved)
//	absent/unknown scope -> handshake REJECTED (DropHandshakeKeyUnresolved)
func TestHandshakePSKtoScopeIDBind(t *testing.T) {
	const (
		scopeAlpha = "tenant-alpha"
		scopeBeta  = "tenant-beta"
	)
	keyAlpha := []byte("alpha-network-psk-0000000000-secret")
	keyBeta := []byte("beta-network-psk-1111111111-secret")

	respTr, respNode := newScopeTestTransport(t, scopeKeyResolver{
		scopeAlpha: {keyAlpha},
		scopeBeta:  {keyBeta},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	respLn, err := respTr.Listen(ctx)
	if err != nil {
		t.Fatalf("responder listen: %v", err)
	}
	defer respLn.Close()
	respAddr := respLn.Addr().String()

	nl, ok := respLn.(*noiseListener)
	if !ok {
		t.Fatalf("responder listener is %T, want *noiseListener", respLn)
	}

	// dialScope dials the responder claiming `claimScope` and presenting
	// `presentKeys` as PSK material. Each call uses a FRESH initiator identity
	// so repeated dials never collide on the responder's simultaneous-dial
	// dedup (handshake.go:1034), which would close-not-Accept a second session
	// from the same NodeID. On a completed handshake it returns the
	// RESPONDER-side accepted connection (whose ScopeID the responder DERIVED);
	// on a rejected handshake it returns an error.
	dialScope := func(claimScope string, presentKeys [][]byte, budget time.Duration) (aether.Connection, error) {
		cliTr, _ := newScopeTestTransport(t, nil)
		cliLn, lerr := cliTr.Listen(ctx) // Dial reuses the initiator's shared socket
		if lerr != nil {
			t.Fatalf("initiator listen: %v", lerr)
		}
		t.Cleanup(func() { _ = cliLn.Close() })

		acceptCtx, acceptCancel := context.WithTimeout(ctx, budget+3*time.Second)
		defer acceptCancel()
		accepted := make(chan aether.Connection, 1)
		go func() {
			if c, aerr := respLn.Accept(acceptCtx); aerr == nil {
				accepted <- c
			}
		}()

		dialCtx, dialCancel := context.WithTimeout(ctx, budget)
		defer dialCancel()
		dialCtx = WithDialOverride(dialCtx, claimScope, presentKeys)
		cliConn, derr := cliTr.Dial(dialCtx, aether.Target{Address: respAddr, NodeID: respNode})
		if derr != nil {
			return nil, derr
		}
		t.Cleanup(func() { _ = cliConn.Close() })

		select {
		case c := <-accepted:
			return c, nil
		case <-acceptCtx.Done():
			return nil, fmt.Errorf("dial completed but responder never Accept'd the session: %w", acceptCtx.Err())
		}
	}

	// --- right PSK -> derived scope (tenant-alpha) ---
	connA, err := dialScope(scopeAlpha, [][]byte{keyAlpha}, 10*time.Second)
	if err != nil {
		t.Fatalf("dial claiming %q with its OWN PSK must complete: %v", scopeAlpha, err)
	}
	t.Cleanup(func() { _ = connA.Close() })
	if got := scopeOf(t, connA); got != scopeAlpha {
		t.Fatalf("responder DERIVED ScopeID=%q from the partition-alpha PSK, want %q — session scope is not bound to the proven key", got, scopeAlpha)
	}

	// --- right PSK -> derived scope (tenant-beta): the derivation tracks the
	// MATCHED key; it is not hardcoded to the first/only scope ---
	connB, err := dialScope(scopeBeta, [][]byte{keyBeta}, 10*time.Second)
	if err != nil {
		t.Fatalf("dial claiming %q with its OWN PSK must complete: %v", scopeBeta, err)
	}
	t.Cleanup(func() { _ = connB.Close() })
	if got := scopeOf(t, connB); got != scopeBeta {
		t.Fatalf("responder DERIVED ScopeID=%q from the partition-beta PSK, want %q", got, scopeBeta)
	}

	// --- wrong PSK for a KNOWN scope -> REJECTED. Claiming tenant-alpha while
	// holding only tenant-beta's PSK must NOT yield an alpha-scoped session: the
	// CRC32 fingerprint of beta's key is absent from ResolveKeys(alpha), so
	// resolveHandshakeKey drops the msg1 (DropHandshakeKeyUnresolved) and no
	// session is ever accepted. This is the "wrong PSK -> NOT X" half. ---
	beforeWrong := nl.DropSnapshot()[DropHandshakeKeyUnresolved.String()]
	if c, derr := dialScope(scopeAlpha, [][]byte{keyBeta}, 2*time.Second); derr == nil {
		got := scopeOf(t, c)
		_ = c.Close()
		t.Fatalf("handshake COMPLETED while claiming %q with %q's PSK — scope is forgeable without the tenant's key (got ScopeID=%q)", scopeAlpha, scopeBeta, got)
	}
	if after := nl.DropSnapshot()[DropHandshakeKeyUnresolved.String()]; after <= beforeWrong {
		t.Fatalf("wrong-PSK dial did not trip DropHandshakeKeyUnresolved (before=%d after=%d): responder did not reject on key/scope mismatch", beforeWrong, after)
	}

	// --- absent scope -> REJECTED. A scope the resolver has never heard of has
	// no keys to match; resolveHandshakeKey rejects before any Noise state. ---
	beforeUnknown := nl.DropSnapshot()[DropHandshakeKeyUnresolved.String()]
	if c, derr := dialScope("partition-unregistered", [][]byte{keyAlpha}, 2*time.Second); derr == nil {
		got := scopeOf(t, c)
		_ = c.Close()
		t.Fatalf("handshake COMPLETED for an unregistered scope — got ScopeID=%q", got)
	}
	if after := nl.DropSnapshot()[DropHandshakeKeyUnresolved.String()]; after <= beforeUnknown {
		t.Fatalf("unknown-scope dial did not trip DropHandshakeKeyUnresolved (before=%d after=%d)", beforeUnknown, after)
	}
}
