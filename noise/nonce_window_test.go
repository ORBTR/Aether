//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package noise

import (
	"encoding/binary"
	"testing"

	fnoise "github.com/flynn/noise"
)

// testCipherPair creates a matched encryptor/decryptor using Noise ChaChaPoly.
// The encryptor uses the initiator→responder direction and the decryptor uses
// the matching responder-side cipher for the same direction.
func testCipherPair(t *testing.T) (*nonceEncryptor, *nonceWindow) {
	t.Helper()

	suite := fnoise.NewCipherSuite(fnoise.DH25519, fnoise.CipherChaChaPoly, fnoise.HashSHA256)
	kp1, _ := suite.GenerateKeypair(nil)
	kp2, _ := suite.GenerateKeypair(nil)

	init, _ := fnoise.NewHandshakeState(fnoise.Config{
		Pattern:       fnoise.HandshakeNN,
		Initiator:     true,
		CipherSuite:   suite,
		StaticKeypair: kp1,
	})
	resp, _ := fnoise.NewHandshakeState(fnoise.Config{
		Pattern:       fnoise.HandshakeNN,
		Initiator:     false,
		CipherSuite:   suite,
		StaticKeypair: kp2,
	})

	// NN handshake: msg1 (init→resp), msg2 (resp→init)
	msg1, _, _, _ := init.WriteMessage(nil, nil)
	_, _, _, _ = resp.ReadMessage(nil, msg1)
	// Responder returns (cs1, cs2): cs1=initiator→responder, cs2=responder→initiator
	msg2, respCS1, _, _ := resp.WriteMessage(nil, nil)
	// Initiator returns (cs1, cs2): cs1=initiator→responder, cs2=responder→initiator
	_, initCS1, _, _ := init.ReadMessage(nil, msg2)

	// Pair: initiator encrypts with cs1 (init→resp), responder decrypts with cs1 (init→resp)
	enc := newNonceEncryptor(initCS1.Cipher())
	dec := newNonceWindow(respCS1.Cipher(), 64)

	return enc, dec
}

func TestNonceWindow_InOrder(t *testing.T) {
	enc, dec := testCipherPair(t)

	for i := 0; i < 100; i++ {
		ct := enc.Encrypt(nil, nil, []byte("hello"))
		pt, err := dec.Decrypt(nil, nil, ct)
		if err != nil {
			t.Fatalf("decrypt %d: %v", i, err)
		}
		if string(pt) != "hello" {
			t.Fatalf("decrypt %d: got %q, want %q", i, pt, "hello")
		}
	}
}

func TestNonceWindow_OutOfOrder(t *testing.T) {
	enc, dec := testCipherPair(t)

	// Generate 5 packets
	packets := make([][]byte, 5)
	for i := range packets {
		msg := []byte{byte(i)}
		packets[i] = enc.Encrypt(nil, nil, msg)
	}

	// Deliver out of order: 0, 2, 1, 4, 3
	order := []int{0, 2, 1, 4, 3}
	for _, idx := range order {
		pt, err := dec.Decrypt(nil, nil, packets[idx])
		if err != nil {
			t.Fatalf("decrypt packet %d: %v", idx, err)
		}
		if pt[0] != byte(idx) {
			t.Fatalf("decrypt packet %d: got %d, want %d", idx, pt[0], idx)
		}
	}
}

func TestNonceWindow_ReplayRejection(t *testing.T) {
	enc, dec := testCipherPair(t)

	ct := enc.Encrypt(nil, nil, []byte("hello"))

	// First decrypt should succeed
	_, err := dec.Decrypt(nil, nil, ct)
	if err != nil {
		t.Fatalf("first decrypt: %v", err)
	}

	// Replay should be rejected
	_, err = dec.Decrypt(nil, nil, ct)
	if err != errNonceReplayed {
		t.Fatalf("replay: got %v, want %v", err, errNonceReplayed)
	}
}

func TestNonceWindow_TooOld(t *testing.T) {
	enc, dec := testCipherPair(t)

	// Generate 70 packets (window is 64)
	packets := make([][]byte, 70)
	for i := range packets {
		packets[i] = enc.Encrypt(nil, nil, []byte{byte(i)})
	}

	// Deliver packets 1-69 (skip 0)
	for i := 1; i < 70; i++ {
		_, err := dec.Decrypt(nil, nil, packets[i])
		if err != nil {
			t.Fatalf("decrypt packet %d: %v", i, err)
		}
	}

	// Packet 0 is now too old (69 - 0 = 69, > window size 64)
	_, err := dec.Decrypt(nil, nil, packets[0])
	if err != errNonceReplayed {
		t.Fatalf("too-old packet: got %v, want %v", err, errNonceReplayed)
	}
}

func TestNonceWindow_WindowEdge(t *testing.T) {
	enc, dec := testCipherPair(t)

	// Generate 65 packets
	packets := make([][]byte, 65)
	for i := range packets {
		packets[i] = enc.Encrypt(nil, nil, []byte{byte(i)})
	}

	// Deliver packet 63 first (establishes highest=63)
	_, err := dec.Decrypt(nil, nil, packets[63])
	if err != nil {
		t.Fatalf("decrypt packet 63: %v", err)
	}

	// Packet 0 is exactly at window edge (63 - 0 = 63, < window size 64)
	_, err = dec.Decrypt(nil, nil, packets[0])
	if err != nil {
		t.Fatalf("edge packet 0: %v", err)
	}

	// Now deliver packet 64 (shifts window)
	_, err = dec.Decrypt(nil, nil, packets[64])
	if err != nil {
		t.Fatalf("decrypt packet 64: %v", err)
	}

	// Packet 0 is now out of window (64 - 0 = 64, >= window size 64)
	// But it was already seen, so it would be rejected as replay anyway
}

func TestNonceWindow_LargeGap(t *testing.T) {
	enc, dec := testCipherPair(t)

	// Generate a packet, then skip 100 and generate another
	pkt0 := enc.Encrypt(nil, nil, []byte{0})
	for i := 1; i <= 100; i++ {
		enc.Encrypt(nil, nil, []byte{byte(i)}) // discard — simulates lost packets
	}
	pkt101 := enc.Encrypt(nil, nil, []byte{101})

	// Deliver pkt0 first
	_, err := dec.Decrypt(nil, nil, pkt0)
	if err != nil {
		t.Fatalf("decrypt pkt0: %v", err)
	}

	// Deliver pkt101 — large gap (101 > window 64), should succeed
	_, err = dec.Decrypt(nil, nil, pkt101)
	if err != nil {
		t.Fatalf("decrypt pkt101: %v", err)
	}

	// pkt0 replay should fail (too old now)
	_, err = dec.Decrypt(nil, nil, pkt0)
	if err != errNonceReplayed {
		t.Fatalf("pkt0 replay: got %v, want %v", err, errNonceReplayed)
	}
}

func TestNonceEncryptor_NonceIncrement(t *testing.T) {
	enc, _ := testCipherPair(t)

	for i := uint64(0); i < 10; i++ {
		ct := enc.Encrypt(nil, nil, []byte("test"))
		n := binary.BigEndian.Uint64(ct[:8])
		if n != i {
			t.Fatalf("nonce %d: got %d", i, n)
		}
	}
}

func TestNonceEncryptor_ThreadSafe(t *testing.T) {
	enc, dec := testCipherPair(t)

	// Concurrently encrypt from multiple goroutines
	done := make(chan []byte, 100)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 10; j++ {
				ct := enc.Encrypt(nil, nil, []byte{byte(id), byte(j)})
				done <- ct
			}
		}(i)
	}

	// Collect and decrypt all 100 packets
	seen := make(map[uint64]bool)
	for i := 0; i < 100; i++ {
		ct := <-done
		n := binary.BigEndian.Uint64(ct[:8])
		if seen[n] {
			t.Fatalf("duplicate nonce %d", n)
		}
		seen[n] = true

		_, err := dec.Decrypt(nil, nil, ct)
		if err != nil {
			t.Fatalf("decrypt nonce %d: %v", n, err)
		}
	}

	if len(seen) != 100 {
		t.Fatalf("expected 100 unique nonces, got %d", len(seen))
	}
}

func benchCipherPair(b *testing.B) (*nonceEncryptor, *nonceWindow) {
	b.Helper()
	suite := fnoise.NewCipherSuite(fnoise.DH25519, fnoise.CipherChaChaPoly, fnoise.HashSHA256)
	kp1, _ := suite.GenerateKeypair(nil)
	kp2, _ := suite.GenerateKeypair(nil)

	init, _ := fnoise.NewHandshakeState(fnoise.Config{
		Pattern: fnoise.HandshakeNN, Initiator: true, CipherSuite: suite, StaticKeypair: kp1,
	})
	resp, _ := fnoise.NewHandshakeState(fnoise.Config{
		Pattern: fnoise.HandshakeNN, Initiator: false, CipherSuite: suite, StaticKeypair: kp2,
	})
	msg1, _, _, _ := init.WriteMessage(nil, nil)
	_, _, _, _ = resp.ReadMessage(nil, msg1)
	msg2, respCS1, _, _ := resp.WriteMessage(nil, nil)
	_, initCS1, _, _ := init.ReadMessage(nil, msg2)

	enc := newNonceEncryptor(initCS1.Cipher())
	dec := newNonceWindow(respCS1.Cipher(), 64)
	return enc, dec
}

func BenchmarkNonceEncrypt(b *testing.B) {
	enc, _ := benchCipherPair(b)
	payload := make([]byte, 1420)

	b.ResetTimer()
	b.SetBytes(1420)
	for i := 0; i < b.N; i++ {
		enc.Encrypt(nil, nil, payload)
	}
}

func BenchmarkNonceDecrypt(b *testing.B) {
	enc, dec := benchCipherPair(b)
	payload := make([]byte, 1420)

	// Pre-generate ciphertexts
	cts := make([][]byte, b.N)
	for i := range cts {
		cts[i] = enc.Encrypt(nil, nil, payload)
	}

	b.ResetTimer()
	b.SetBytes(1420)
	for i := 0; i < b.N; i++ {
		dec.Decrypt(nil, nil, cts[i])
	}
}
