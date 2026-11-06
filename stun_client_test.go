//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package aether

import (
	"context"
	"errors"
	"net"
	"os/exec"
	"strings"
	"testing"
)

// TestIsSTUNMessage: a STUN header with the magic cookie reads as STUN; a shorter
// buffer, or one whose bytes 4 to 8 are anything else, does not.
func TestIsSTUNMessage(t *testing.T) {
	msg := make([]byte, stunHeaderSize)
	msg[4], msg[5], msg[6], msg[7] = 0x21, 0x12, 0xA4, 0x42
	if !IsSTUNMessage(msg) {
		t.Fatal("a header with the magic cookie is not read as STUN")
	}
	if IsSTUNMessage(msg[:stunHeaderSize-1]) {
		t.Fatal("a buffer shorter than a STUN header is read as STUN")
	}
	msg[7] = 0x43
	if IsSTUNMessage(msg) {
		t.Fatal("a header without the magic cookie is read as STUN")
	}
}

type fakeSTUNClient struct{ cfg STUNConfig }

func (f *fakeSTUNClient) Config() STUNConfig { return f.cfg }
func (f *fakeSTUNClient) DiscoverReflexiveAddr(context.Context, *net.UDPAddr) (*ReflexiveAddress, error) {
	return nil, errors.New("fake")
}
func (f *fakeSTUNClient) DetectNATType(context.Context, *net.UDPAddr) (NATType, error) {
	return NATUnknown, errors.New("fake")
}
func (f *fakeSTUNClient) DetectNATBehaviour(context.Context, *net.UDPAddr) (NATBehaviour, error) {
	return NATBehaviour{}, errors.New("fake")
}
func (f *fakeSTUNClient) BindingRequest() ([12]byte, []byte) { return [12]byte{}, nil }
func (f *fakeSTUNClient) BindingResponse([]byte) ([12]byte, *ReflexiveAddress, error) {
	return [12]byte{}, nil, errors.New("fake")
}

// TestNewSTUNClient_RefusesWithNothingRegisteredAndBuildsWithTheRegistered: with no
// STUN implementation linked (this package's tests link none) NewSTUNClient refuses
// typed; once a constructor is registered it builds through it, with the config.
func TestNewSTUNClient_RefusesWithNothingRegisteredAndBuildsWithTheRegistered(t *testing.T) {
	saved := stunClientConstructor.Load()
	t.Cleanup(func() { stunClientConstructor.Store(saved) })

	stunClientConstructor.Store(nil)
	if c, err := NewSTUNClient(DefaultSTUNConfig()); !errors.Is(err, ErrSTUNNotComposed) || c != nil {
		t.Fatalf("with nothing registered: %v, %v; want ErrSTUNNotComposed and no client", c, err)
	}
	RegisterSTUNClient(func(cfg STUNConfig) STUNClient { return &fakeSTUNClient{cfg: cfg} })
	cfg := STUNConfig{Enabled: true, Servers: []string{"stun.example:3478"}}
	c, err := NewSTUNClient(cfg)
	if err != nil {
		t.Fatalf("with a constructor registered: %v", err)
	}
	if got := c.Config(); len(got.Servers) != 1 || got.Servers[0] != cfg.Servers[0] {
		t.Fatalf("the registered constructor did not receive the config: %+v", got)
	}
}

// TestADialOnlyCompositionLinksNoSTUN: the packages a host that only dials composes
// (the session adapter and the WebSocket and gRPC transports) link neither the nat
// package nor anything of pion: the Noise transport they reach takes STUN through
// the STUNClient seam, which only a traversing host fills.
func TestADialOnlyCompositionLinksNoSTUN(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps",
		"github.com/ORBTR/aether/adapter", "github.com/ORBTR/aether/websocket", "github.com/ORBTR/aether/grpc").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	pkgs := strings.Fields(string(out))
	if len(pkgs) == 0 {
		t.Fatal("go list -deps returned nothing; the check would pass vacuously")
	}
	var linked []string
	for _, p := range pkgs {
		if p == "github.com/ORBTR/aether/nat" || strings.HasPrefix(p, "github.com/ORBTR/aether/nat/") || strings.HasPrefix(p, "github.com/pion/") {
			linked = append(linked, p)
		}
	}
	if len(linked) > 0 {
		t.Fatalf("a dial-only composition links STUN or NAT traversal code:\n  %s", strings.Join(linked, "\n  "))
	}
	if !strings.Contains(string(out), "github.com/ORBTR/aether/noise\n") {
		t.Fatal("premise: the composition no longer reaches the Noise transport, so the check proves nothing about its seam")
	}
}
