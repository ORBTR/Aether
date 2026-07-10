//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package discovery

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

// aep15StubTransport is a minimal MDNSTransport stub that replays a fixed set of
// browse results so the otherwise-dormant queryPeers append path can be
// exercised end-to-end. Named uniquely to avoid cross-agent symbol collisions.
type aep15StubTransport struct {
	results []MDNSBrowseResult
}

func (s *aep15StubTransport) Advertise(string, int, []string) error { return nil }
func (s *aep15StubTransport) Browse(context.Context, string) ([]MDNSBrowseResult, error) {
	return s.results, nil
}
func (s *aep15StubTransport) Stop() {}

func aep15KeyLookup(id string, target string, pub ed25519.PublicKey) func(string) ed25519.PublicKey {
	return func(q string) ed25519.PublicKey {
		if q == target {
			return pub
		}
		_ = id
		return nil
	}
}

// TestAEP15_SignedPeerNotDroppedByObserved verifies the core AE-P-15 defect
// (mode a): the transport-observed host:port must be kept OUT of the ed25519
// verification scope so a genuinely-signed peer still verifies, while the
// observed address is still retained as an unsigned dial hint. Under the
// pre-fix code (observed appended before verify) this peer is discarded.
func TestAEP15_SignedPeerNotDroppedByObserved(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	signed := []string{"10.0.0.5:9000"}
	ann := SignMDNSAnnouncement("peerX", signed, priv)

	d := NewMDNSDiscoverer("self", nil, 0, nil, aep15KeyLookup("self", "peerX", pub))
	d.processMDNSResponse("peerX", signed, "192.168.1.9:5555", hex.EncodeToString(ann.Signature))

	d.mu.RLock()
	p, ok := d.discovered["peerX"]
	d.mu.RUnlock()
	if !ok {
		t.Fatalf("signed peer was discarded despite a populated observed address (verification ran over augmented set)")
	}
	if len(p.Addresses) != 2 || p.Addresses[0] != "10.0.0.5:9000" || p.Addresses[1] != "192.168.1.9:5555" {
		t.Fatalf("stored addresses = %v, want [10.0.0.5:9000 192.168.1.9:5555] (signed set + unsigned dial hint)", p.Addresses)
	}
}

// TestAEP15_TamperedSignedSetRejected confirms the fix did not weaken auth: a
// signature over the original set must NOT validate a different signed set.
func TestAEP15_TamperedSignedSetRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	ann := SignMDNSAnnouncement("peerX", []string{"10.0.0.5:9000"}, priv)

	d := NewMDNSDiscoverer("self", nil, 0, nil, aep15KeyLookup("self", "peerX", pub))
	// Present a DIFFERENT signed set with the original signature.
	d.processMDNSResponse("peerX", []string{"10.0.0.6:1"}, "192.168.1.9:5555", hex.EncodeToString(ann.Signature))

	d.mu.RLock()
	_, ok := d.discovered["peerX"]
	d.mu.RUnlock()
	if ok {
		t.Fatalf("peer with a tampered signed set was stored; verification must reject it")
	}
}

// TestAEP15_TOFUKeepsObservedHintAndDedups checks the trust-on-first-use path
// (nil pubkey): the observed hint is retained, and a hint that duplicates a
// signed entry is not stored twice.
func TestAEP15_TOFUKeepsObservedHintAndDedups(t *testing.T) {
	// New observed hint is appended.
	d := NewMDNSDiscoverer("self", nil, 0, nil, nil)
	d.processMDNSResponse("tofu", []string{"10.0.0.7:8000"}, "192.168.1.10:5555", "")
	d.mu.RLock()
	p := d.discovered["tofu"]
	d.mu.RUnlock()
	if len(p.Addresses) != 2 || p.Addresses[1] != "192.168.1.10:5555" {
		t.Fatalf("TOFU stored addresses = %v, want signed entry + observed hint", p.Addresses)
	}

	// Observed hint equal to an existing signed entry is de-duplicated.
	d2 := NewMDNSDiscoverer("self", nil, 0, nil, nil)
	d2.processMDNSResponse("tofu2", []string{"10.0.0.8:9000"}, "10.0.0.8:9000", "")
	d2.mu.RLock()
	p2 := d2.discovered["tofu2"]
	d2.mu.RUnlock()
	if len(p2.Addresses) != 1 {
		t.Fatalf("duplicate observed hint stored: addresses = %v, want single entry", p2.Addresses)
	}
}

// TestAEP15_EndToEndAppendPath drives the full queryPeers -> processMDNSResponse
// -> Discover path via a stub transport, exercising the append site that is
// dormant in the shipped binary. A validly-signed peer whose browse result also
// carries an observed Host/Port must survive verification and surface via
// Discover with BOTH the signed address and the observed dial hint.
func TestAEP15_EndToEndAppendPath(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	signed := []string{"10.0.0.5:9000"}
	ann := SignMDNSAnnouncement("peerE", signed, priv)

	stub := &aep15StubTransport{results: []MDNSBrowseResult{{
		Host: "192.168.1.20",
		Port: 5555,
		TXTRecords: map[string]string{
			"node_id": "peerE",
			"sig":     hex.EncodeToString(ann.Signature),
			"addr":    "10.0.0.5:9000",
		},
	}}}

	d := NewMDNSDiscoverer("self", nil, 0, nil,
		aep15KeyLookup("self", "peerE", pub),
		WithMDNSTransport(stub))
	d.queryPeers(context.Background())

	peers, err := d.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	var haveSigned, haveObserved bool
	for _, p := range peers {
		if p.NodeID != "peerE" {
			t.Fatalf("unexpected peer nodeID %q", p.NodeID)
		}
		if p.Host == "10.0.0.5" && p.Port == 9000 {
			haveSigned = true
		}
		if p.Host == "192.168.1.20" && p.Port == 5555 {
			haveObserved = true
		}
	}
	if !haveSigned {
		t.Fatalf("signed peer dropped end-to-end; Discover returned %+v", peers)
	}
	if !haveObserved {
		t.Fatalf("observed dial hint missing end-to-end; Discover returned %+v", peers)
	}
}
