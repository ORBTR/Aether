//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package noise

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"

	aether "github.com/ORBTR/aether"
)

// seamSTUN is a STUN client the test composes: its binding transaction has a fixed
// ID, and its response parser answers that ID with a fixed address.
type seamSTUN struct {
	id   [12]byte
	addr *aether.ReflexiveAddress
}

func (s *seamSTUN) Config() aether.STUNConfig { return aether.STUNConfig{Enabled: true} }
func (s *seamSTUN) DiscoverReflexiveAddr(context.Context, *net.UDPAddr) (*aether.ReflexiveAddress, error) {
	return s.addr, nil
}
func (s *seamSTUN) DetectNATType(context.Context, *net.UDPAddr) (aether.NATType, error) {
	return aether.NATFullCone, nil
}
func (s *seamSTUN) DetectNATBehaviour(context.Context, *net.UDPAddr) (aether.NATBehaviour, error) {
	return aether.NATBehaviour{}, nil
}
func (s *seamSTUN) BindingRequest() ([12]byte, []byte) { return s.id, []byte("request") }
func (s *seamSTUN) BindingResponse([]byte) ([12]byte, *aether.ReflexiveAddress, error) {
	return s.id, s.addr, nil
}

func seamTransportConfig(t *testing.T) NoiseTransportConfig {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	nodeID, err := aether.NewNodeID(pub)
	if err != nil {
		t.Fatalf("node id: %v", err)
	}
	return NoiseTransportConfig{
		PrivateKey:  priv,
		LocalNode:   nodeID,
		ListenAddr:  "127.0.0.1:0",
		NetworkKeys: []string{"stun-seam-test-network-key"},
	}
}

// TestNoiseTransport_STUNEnabledWithNothingComposedRefuses: this package links no
// STUN implementation, so a config that enables STUN and passes no client refuses
// at construction with aether.ErrSTUNNotComposed; no transport runs without the
// STUN its config asked for.
func TestNoiseTransport_STUNEnabledWithNothingComposedRefuses(t *testing.T) {
	cfg := seamTransportConfig(t)
	cfg.STUNConfig = aether.DefaultSTUNConfig()
	if tr, err := NewNoiseTransport(cfg); !errors.Is(err, aether.ErrSTUNNotComposed) || tr != nil {
		t.Fatalf("NewNoiseTransport: %v, %v; want aether.ErrSTUNNotComposed", tr, err)
	}
}

// TestNoiseTransport_RunsTheComposedSTUNClientOrNone: with no client and STUN not
// enabled the transport runs none (GetSTUNClient nil, discovery refused); with one
// composed, GetSTUNClient returns it and a STUN response the listener hands
// handleSTUNPacket reaches the waiter of the transaction it names.
func TestNoiseTransport_RunsTheComposedSTUNClientOrNone(t *testing.T) {
	plain, err := NewNoiseTransport(seamTransportConfig(t))
	if err != nil {
		t.Fatalf("a transport with no STUN: %v", err)
	}
	if c := plain.GetSTUNClient(); c != nil {
		t.Fatalf("a transport with no STUN reports a client %T", c)
	}
	if _, err := plain.DiscoverReflexiveAddr(context.Background(), nil); err == nil {
		t.Fatal("a transport with no STUN discovered an address")
	}
	plain.handleSTUNPacket([]byte("ignored"))

	want := &aether.ReflexiveAddress{IP: net.IPv4(198, 51, 100, 9), Port: 41641}
	composed := &seamSTUN{id: [12]byte{1, 2, 3}, addr: want}
	cfg := seamTransportConfig(t)
	cfg.STUN = composed
	tr, err := NewNoiseTransport(cfg)
	if err != nil {
		t.Fatalf("a transport with a composed client: %v", err)
	}
	if c := tr.GetSTUNClient(); c != composed {
		t.Fatalf("GetSTUNClient returned %v, want the composed client", c)
	}
	ch := make(chan stunResult, 1)
	tr.stunMu.Lock()
	tr.stunTx[composed.id] = ch
	tr.stunMu.Unlock()
	tr.handleSTUNPacket([]byte("response"))
	select {
	case r := <-ch:
		if r.err != nil || r.addr != want {
			t.Fatalf("the waiter got %+v, %v", r.addr, r.err)
		}
	case <-time.After(time.Second):
		t.Fatal("the response did not reach the transaction's waiter")
	}
}
