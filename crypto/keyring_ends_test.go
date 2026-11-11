/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package crypto

import (
	"bytes"
	"testing"

	"github.com/ORBTR/aether"
)

// The two ends of one session derive their keyrings from the same secret, each
// naming itself first: DeriveKeyring(secret, self, peer).
func sessionEnds(t *testing.T) (a, b *Keyring) {
	t.Helper()
	secret := bytes.Repeat([]byte{0x5a}, 32)
	a, err := DeriveKeyring(secret, "vl1_node_a", "vl1_node_b")
	if err != nil {
		t.Fatal(err)
	}
	b, err = DeriveKeyring(secret, "vl1_node_b", "vl1_node_a")
	if err != nil {
		t.Fatal(err)
	}
	return a, b
}

func endFrame(from, to string, payload string) *aether.Frame {
	return &aether.Frame{
		SenderID:   TruncateNodeID(from),
		ReceiverID: TruncateNodeID(to),
		StreamID:   7,
		Type:       aether.TypeDATA,
		SeqNo:      1,
		Length:     uint32(len(payload)),
		Payload:    []byte(payload),
	}
}

func endEncryptors(t *testing.T, a, b *Keyring) (encA, encB *FrameEncryptor) {
	t.Helper()
	encA, err := a.NewEncryptor(true)
	if err != nil {
		t.Fatal(err)
	}
	encB, err = b.NewEncryptor(true)
	if err != nil {
		t.Fatal(err)
	}
	return encA, encB
}

// A frame one end seals is opened by the other end, in each direction.
func TestKeyring_TheTwoEndsOfASessionOpenEachOthersFrames(t *testing.T) {
	a, b := sessionEnds(t)
	encA, encB := endEncryptors(t, a, b)
	for _, d := range []struct {
		name       string
		from, to   string
		seal, open *FrameEncryptor
	}{
		{"a to b", "vl1_node_a", "vl1_node_b", encA, encB},
		{"b to a", "vl1_node_b", "vl1_node_a", encB, encA},
	} {
		f := endFrame(d.from, d.to, "sealed "+d.name)
		if err := d.seal.Encrypt(f); err != nil {
			t.Fatalf("%s: seal: %v", d.name, err)
		}
		if err := d.open.Decrypt(f); err != nil {
			t.Fatalf("%s: the receiving end cannot open the sending end's frame: %v", d.name, err)
		}
		if string(f.Payload) != "sealed "+d.name {
			t.Fatalf("%s: opened %q", d.name, f.Payload)
		}
	}
}

// A frame an end sealed does not open at that same end: each direction has its
// own key, so a frame reflected back at its sender fails authentication.
func TestKeyring_AFrameDoesNotOpenAtTheEndThatSealedIt(t *testing.T) {
	a, b := sessionEnds(t)
	encA, _ := endEncryptors(t, a, b)
	f := endFrame("vl1_node_a", "vl1_node_b", "reflected")
	if err := encA.Encrypt(f); err != nil {
		t.Fatal(err)
	}
	if err := encA.Decrypt(f); err == nil {
		t.Fatal("the sealing end opened its own frame: one key serves both directions")
	}
}

// The authentication key is one key both ends hold, so an HMAC one end computes
// verifies at the other.
func TestDeriveKeyring_TheTwoEndsHoldOneAuthKey(t *testing.T) {
	a, b := sessionEnds(t)
	if a.AuthKey != b.AuthKey {
		t.Fatal("the two ends of one session derive different authentication keys")
	}
}

// The two identities are bound with their boundary: moving bytes from one name
// to the other derives other keys.
func TestDeriveKeyring_TheBoundaryBetweenTheTwoIdentitiesIsBound(t *testing.T) {
	secret := bytes.Repeat([]byte{0x33}, 32)
	x, err := DeriveKeyring(secret, "vl1_ab", "c")
	if err != nil {
		t.Fatal(err)
	}
	y, err := DeriveKeyring(secret, "vl1_a", "bc")
	if err != nil {
		t.Fatal(err)
	}
	if x.EncryptionKey == y.EncryptionKey || x.AuthKey == y.AuthKey || x.IVKey == y.IVKey {
		t.Fatal("two different identity pairs with the same concatenation derive the same key")
	}
}

// Each end's opening key is the peer's sealing key, and its two direction keys
// differ from each other.
func TestDeriveKeyring_EachEndOpensWithThePeersSealingKey(t *testing.T) {
	a, b := sessionEnds(t)
	if a.OpenKey != b.EncryptionKey || b.OpenKey != a.EncryptionKey {
		t.Fatal("an end's opening key is not the peer's sealing key")
	}
	if a.EncryptionKey == a.OpenKey {
		t.Fatal("an end seals and opens under one key")
	}
	if a.IVKey == b.IVKey {
		t.Fatal("the two directions share one IV key")
	}
}

// A 0x87 frame's payload-carried nonce opens at the receiving end and not at
// the end that sealed it, as the full-header frame does.
func TestKeyring_ANonceCarriedFrameOpensOnlyAtTheReceivingEnd(t *testing.T) {
	a, b := sessionEnds(t)
	encA, encB := endEncryptors(t, a, b)
	seal := func() (*aether.Frame, []byte) {
		f := endFrame("vl1_node_a", "vl1_node_b", "short form")
		if err := encA.Encrypt(f); err != nil {
			t.Fatal(err)
		}
		nonce := append([]byte(nil), f.Nonce[:]...)
		f.Nonce = aether.Nonce{}
		return f, nonce
	}
	f, nonce := seal()
	if err := encA.DecryptWithNonce(f, nonce); err == nil {
		t.Fatal("the sealing end opened its own frame by its carried nonce")
	}
	f, nonce = seal()
	if err := encB.DecryptWithNonce(f, nonce); err != nil {
		t.Fatalf("the receiving end cannot open the frame by its carried nonce: %v", err)
	}
	if string(f.Payload) != "short form" {
		t.Fatalf("opened %q", f.Payload)
	}
}

// A directional encryptor refuses one key as both its keys.
func TestNewDirectionalFrameEncryptor_RefusesOneKeyForBothDirections(t *testing.T) {
	if _, err := NewDirectionalFrameEncryptor(testKey(), testKey(), true); err == nil {
		t.Fatal("one key was accepted as both the sealing and the opening key")
	}
}
