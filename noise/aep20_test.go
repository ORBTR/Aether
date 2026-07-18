//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package noise

import (
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"

	"github.com/ORBTR/aether"
	transportCrypto "github.com/ORBTR/aether/crypto/identity"
)

// aep20NewTransport builds a minimal NoiseTransport for exercising
// encodeNodeInfo. The constructor always installs a ticketStore (see
// NewNoiseTransport), so the advertised caps include capSessionTicket.
func aep20NewTransport(t *testing.T) *NoiseTransport {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("AE-P-20: generate key: %v", err)
	}
	nodeID, err := aether.NewNodeID(pub)
	if err != nil {
		t.Fatalf("AE-P-20: node id: %v", err)
	}
	tr, err := NewNoiseTransport(NoiseTransportConfig{
		PrivateKey:  priv,
		LocalNode:   nodeID,
		ListenAddr:  "127.0.0.1:0",
		NetworkKeys: []string{"aep20-test-network-key"},
		// AER-006/097: resume/tickets are opt-in now; this test exercises the
		// ticket-cap advertising path, so it enables resume explicitly.
		EnableResume: true,
	})
	if err != nil {
		t.Fatalf("AE-P-20: new transport: %v", err)
	}
	return tr
}

// TestAEP20_EncodeNodeInfoMemoized proves the AE-P-20 fix: encodeNodeInfo
// signs+marshals the NodeInfo payload exactly once and returns the same
// cached backing array on subsequent calls, instead of re-running
// ed25519.Sign + json.Marshal under l.mu on every inbound handshake.
func TestAEP20_EncodeNodeInfoMemoized(t *testing.T) {
	tr := aep20NewTransport(t)

	b1, err1 := tr.encodeNodeInfo()
	if err1 != nil {
		t.Fatalf("AE-P-20: first encodeNodeInfo: %v", err1)
	}
	b2, err2 := tr.encodeNodeInfo()
	if err2 != nil {
		t.Fatalf("AE-P-20: second encodeNodeInfo: %v", err2)
	}
	if len(b1) == 0 || len(b2) == 0 {
		t.Fatalf("AE-P-20: empty payload (len b1=%d b2=%d)", len(b1), len(b2))
	}
	if string(b1) != string(b2) {
		t.Fatalf("AE-P-20: payloads differ across calls")
	}
	// Aliasing the same backing array proves no re-sign / re-marshal.
	if &b1[0] != &b2[0] {
		t.Fatalf("AE-P-20: payload not memoized — second call re-encoded (distinct backing array)")
	}
}

// TestAEP20_EncodeNodeInfoCapsAndSignature verifies the memoized payload still
// carries the correct capabilities and a valid signature — the fix must not
// change what is advertised or break verification of the cached bytes.
func TestAEP20_EncodeNodeInfoCapsAndSignature(t *testing.T) {
	tr := aep20NewTransport(t)
	if tr.ticketStore == nil {
		t.Fatalf("AE-P-20: expected ticketStore to be installed by constructor")
	}

	payload, err := tr.encodeNodeInfo()
	if err != nil {
		t.Fatalf("AE-P-20: encodeNodeInfo: %v", err)
	}

	_, _, caps, _, verr := transportCrypto.VerifyNodeInfo(tr.staticPub, payload, tr.localNode)
	if verr != nil {
		t.Fatalf("AE-P-20: cached payload failed verification: %v", verr)
	}
	if caps&capExplicitNonce == 0 {
		t.Errorf("AE-P-20: caps missing capExplicitNonce (caps=%d)", caps)
	}
	if caps&capSessionTicket == 0 {
		t.Errorf("AE-P-20: caps missing capSessionTicket despite ticketStore != nil (caps=%d)", caps)
	}

	// Re-verify after a second fetch: the shared read-only slice must not have
	// been mutated by any consumer between calls.
	payload2, err := tr.encodeNodeInfo()
	if err != nil {
		t.Fatalf("AE-P-20: second encodeNodeInfo: %v", err)
	}
	if _, _, _, _, verr := transportCrypto.VerifyNodeInfo(tr.staticPub, payload2, tr.localNode); verr != nil {
		t.Fatalf("AE-P-20: cached payload corrupted after reuse: %v", verr)
	}
}

// TestAEP20_EncodeNodeInfoRaceFree exercises concurrent encodeNodeInfo calls to
// confirm the sync.Once memoization and shared-slice reads are race-free.
// Run with `go test -race` for full coverage.
func TestAEP20_EncodeNodeInfoRaceFree(t *testing.T) {
	tr := aep20NewTransport(t)

	const goroutines = 16
	var wg sync.WaitGroup
	wg.Add(goroutines)
	firsts := make([]*byte, goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			b, err := tr.encodeNodeInfo()
			if err != nil {
				t.Errorf("AE-P-20: concurrent encodeNodeInfo: %v", err)
				return
			}
			if len(b) == 0 {
				t.Errorf("AE-P-20: concurrent encodeNodeInfo returned empty payload")
				return
			}
			firsts[idx] = &b[0]
		}(i)
	}
	wg.Wait()

	// Every goroutine must observe the single memoized backing array.
	for i := 1; i < goroutines; i++ {
		if firsts[i] != nil && firsts[0] != nil && firsts[i] != firsts[0] {
			t.Fatalf("AE-P-20: goroutine %d saw a distinct payload backing array — memoization not shared", i)
		}
	}
}
