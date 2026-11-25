//go:build !js

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
	"errors"
	"net"
	"testing"
	"time"

	aether "github.com/ORBTR/aether"
)

func TestRoutingPreamble_RoundTrip(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := aether.NewNodeID(pub)
	if err != nil {
		t.Fatal(err)
	}

	// Encode preamble + a fake noise msg1 payload after it.
	msg1 := []byte("pretend this is a noise XX msg1")
	wire := append(EncodeRoutingPreamble(id), msg1...)

	if !IsRoutingPreamble(wire) {
		t.Fatal("IsRoutingPreamble false on freshly encoded preamble")
	}

	gotID, rest, err := DecodeRoutingPreamble(wire)
	if err != nil {
		t.Fatalf("DecodeRoutingPreamble: %v", err)
	}
	if gotID != id {
		t.Fatalf("NodeID mismatch: got %s, want %s", gotID.Short(), id.Short())
	}
	if !bytes.Equal(rest, msg1) {
		t.Fatalf("remainder mismatch: got %q, want %q", rest, msg1)
	}
}

func TestRoutingPreamble_RejectsShort(t *testing.T) {
	if _, _, err := DecodeRoutingPreamble([]byte{0x41, 0x45}); !errors.Is(err, ErrRoutingPreambleTooShort) {
		t.Fatalf("short decode err = %v, want ErrRoutingPreambleTooShort", err)
	}
}

func TestRoutingPreamble_RejectsWrongMagic(t *testing.T) {
	// Partition-preamble magic 0x5450 starts with 'T' (0x54), distinct from
	// routing-preamble magic 0x4145 ('A'). Ensure the discriminator works.
	wire := make([]byte, RoutingPreambleSize)
	wire[0] = 0x54
	wire[1] = 0x50
	if IsRoutingPreamble(wire) {
		t.Fatal("IsRoutingPreamble matched a partition-preamble magic — discriminator broken")
	}
	if _, _, err := DecodeRoutingPreamble(wire); !errors.Is(err, ErrRoutingPreambleMagicMismatch) {
		t.Fatalf("wrong-magic err = %v, want ErrRoutingPreambleMagicMismatch", err)
	}
}

func TestRoutingPreamble_RejectsUnknownVersion(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	id, _ := aether.NewNodeID(pub)
	wire := EncodeRoutingPreamble(id)
	wire[2] = 0xEE // bogus version
	if _, _, err := DecodeRoutingPreamble(wire); !errors.Is(err, ErrRoutingPreambleVersion) {
		t.Fatalf("bad-version err = %v, want ErrRoutingPreambleVersion", err)
	}
}

func TestRoutingPreamble_IsNotMistakenForRawMsg1(t *testing.T) {
	// A raw noise msg1 starts with a Curve25519 ephemeral pub key. The
	// first byte is statistically uniform over [0,255]. We can't prove
	// non-collision in a unit test, but we can verify the discriminator
	// rejects the obvious legacy cases.
	for _, prefix := range [][]byte{
		{0x00, 0x00}, // zeros
		{0xFF, 0xFF}, // ones
		{0x54, 0x50}, // partition-preamble magic — must NOT be confused with routing
	} {
		if IsRoutingPreamble(prefix) {
			t.Fatalf("IsRoutingPreamble false-positive on %x", prefix)
		}
	}
}

// NoiseTransport.Dial prepends the routing preamble exactly when the dial's
// Target.Metadata carries MetadataKeyCrossOriginPreamble="1", and the key is
// spelled by origin. The first datagram the dialer sends is read off a plain
// UDP socket standing in for the peer: with the key it starts with the "AE"
// preamble naming the target, and with no key or any other spelling it does
// not, so a second accepted spelling fails here as well.
func TestDialPrependsTheRoutingPreambleOnlyUnderTheCrossOriginKey(t *testing.T) {
	if MetadataKeyCrossOriginPreamble != "aether.cross_origin_preamble" {
		t.Fatalf("MetadataKeyCrossOriginPreamble = %q, want %q",
			MetadataKeyCrossOriginPreamble, "aether.cross_origin_preamble")
	}

	_, dialerPriv, _ := ed25519.GenerateKey(rand.Reader)
	dialerID, _ := aether.NewNodeID(dialerPriv.Public().(ed25519.PublicKey))
	dialer, err := NewNoiseTransport(NoiseTransportConfig{
		PrivateKey:  dialerPriv,
		LocalNode:   dialerID,
		ListenAddr:  "127.0.0.1:0",
		NetworkKeys: []string{"routing-preamble-key-test"},
	})
	if err != nil {
		t.Fatalf("NewNoiseTransport: %v", err)
	}
	t.Cleanup(func() { _ = dialer.Close() })
	listenCtx, cancelListen := context.WithCancel(context.Background())
	t.Cleanup(cancelListen)
	if _, err := dialer.Listen(listenCtx); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	peerPub, _, _ := ed25519.GenerateKey(rand.Reader)
	peerID, _ := aether.NewNodeID(peerPub)

	cases := []struct {
		name         string
		metadata     map[string]string
		wantPreamble bool
	}{
		{"cross-origin key", map[string]string{MetadataKeyCrossOriginPreamble: "1"}, true},
		{"no metadata", nil, false},
		{"key set to another value", map[string]string{MetadataKeyCrossOriginPreamble: "true"}, false},
		{"another spelling", map[string]string{"aether.cross_org_preamble": "1"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatalf("ListenUDP: %v", err)
			}
			defer func() {
				if err := sink.Close(); err != nil {
					t.Errorf("sink.Close: %v", err)
				}
			}()

			dialCtx, cancelDial := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancelDial()
			done := make(chan struct{})
			go func() {
				defer close(done)
				_, _ = dialer.Dial(dialCtx, aether.Target{
					NodeID:   peerID,
					Address:  sink.LocalAddr().String(),
					Metadata: tc.metadata,
				})
			}()
			defer func() { cancelDial(); <-done }()

			buf := make([]byte, 2048)
			_ = sink.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, _, err := sink.ReadFromUDP(buf)
			if err != nil {
				t.Fatalf("no datagram reached the peer: %v", err)
			}
			first := buf[:n]
			if got := IsRoutingPreamble(first); got != tc.wantPreamble {
				t.Fatalf("first datagram starts with a routing preamble = %v, want %v (% x)",
					got, tc.wantPreamble, first[:min(n, 8)])
			}
			if tc.wantPreamble {
				target, _, err := DecodeRoutingPreamble(first)
				if err != nil {
					t.Fatalf("DecodeRoutingPreamble: %v", err)
				}
				if target != peerID {
					t.Fatalf("routing preamble names %q, want the dial target %q", target, peerID)
				}
			}
		})
	}
}
