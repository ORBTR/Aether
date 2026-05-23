//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package noise

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

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
	// Tenant-preamble magic 0x5450 starts with 'T' (0x54), distinct from
	// routing-preamble magic 0x4145 ('A'). Ensure the discriminator works.
	wire := make([]byte, RoutingPreambleSize)
	wire[0] = 0x54
	wire[1] = 0x50
	if IsRoutingPreamble(wire) {
		t.Fatal("IsRoutingPreamble matched a tenant-preamble magic — discriminator broken")
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
		{0x54, 0x50}, // tenant-preamble magic — must NOT be confused with routing
	} {
		if IsRoutingPreamble(prefix) {
			t.Fatalf("IsRoutingPreamble false-positive on %x", prefix)
		}
	}
}
