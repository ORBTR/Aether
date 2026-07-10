//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package noise

import (
	"sync"
	"testing"

	"github.com/ORBTR/aether/relay"
	fnoise "github.com/flynn/noise"
)

// testSendRecvCipherStates runs a Noise NN handshake and returns the
// initiator's (send, recv) CipherState pair — send is init→resp, recv is
// resp→init. Both are live CipherStates suitable for enableExplicitNonce
// (which extracts their raw AEAD ciphers) and for rekeySendCipher (which
// ratchets the send CipherState).
func testSendRecvCipherStates(t *testing.T) (*fnoise.CipherState, *fnoise.CipherState) {
	t.Helper()

	suite := fnoise.NewCipherSuite(fnoise.DH25519, fnoise.CipherChaChaPoly, fnoise.HashSHA256)
	kp1, _ := suite.GenerateKeypair(nil)
	kp2, _ := suite.GenerateKeypair(nil)

	initHS, _ := fnoise.NewHandshakeState(fnoise.Config{
		Pattern:       fnoise.HandshakeNN,
		Initiator:     true,
		CipherSuite:   suite,
		StaticKeypair: kp1,
	})
	respHS, _ := fnoise.NewHandshakeState(fnoise.Config{
		Pattern:       fnoise.HandshakeNN,
		Initiator:     false,
		CipherSuite:   suite,
		StaticKeypair: kp2,
	})

	// NN handshake: msg1 (init→resp), msg2 (resp→init).
	msg1, _, _, _ := initHS.WriteMessage(nil, nil)
	_, _, _, _ = respHS.ReadMessage(nil, msg1)
	msg2, _, _, _ := respHS.WriteMessage(nil, nil)
	// Initiator returns (cs1, cs2): cs1 = init→resp (send), cs2 = resp→init (recv).
	_, sendCS, recvCS, _ := initHS.ReadMessage(nil, msg2)

	return sendCS, recvCS
}

// TestExplicitNonceEncryptorRekeyRace is the AE-M-12 regression guard. Before
// the fix, noiseConn.encryptor was a plain *nonceEncryptor: the concurrent
// send paths (sendPacket) read it while rekeySendCipher wrote it, a
// Go-memory-model data race. The fix converts the field to
// atomic.Pointer[nonceEncryptor] (lock-free Load on sends, Store on rekey),
// keeping the deliberate lock-free concurrent-send design.
//
// Run under `go test -race ./noise/`: before the fix this data-races on the
// c.encryptor field; after it passes clean. The -race detector is the primary
// regression assertion — a report fails the test binary. We also sanity-check
// that the swap always leaves a live encryptor.
func TestExplicitNonceEncryptorRekeyRace(t *testing.T) {
	sendCS, recvCS := testSendRecvCipherStates(t)

	c := &noiseConn{
		send:      sendCS,
		recv:      recvCS,
		writeFunc: func(b []byte) (int, error) { return len(b), nil },
		// Thresholds disabled: maybeInitiateRekey (called at the top of
		// sendPacket for PacketTypeData) never auto-fires, so the only
		// swaps come from our explicit rekeySendCipher goroutine —
		// deterministic and reproducible under -race.
		rekey: NewRekeyTracker(0, 0),
	}
	c.enableExplicitNonce()

	payload := []byte("aem12-race-payload")

	const readers = 8
	const sendsPerReader = 1000
	const rekeys = 200

	var wg sync.WaitGroup

	// Concurrent send readers: model the app-Write, runReader-Pong and
	// SendPing callers that all hit sendPacket's atomic encryptor Load.
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < sendsPerReader; j++ {
				if err := c.sendPacket(relay.PacketTypeData, payload); err != nil {
					// writeFunc never returns an error, so any non-nil
					// error is a real regression. t.Errorf is
					// goroutine-safe; t.Fatal is not, so use Errorf here.
					t.Errorf("sendPacket returned error: %v", err)
					return
				}
			}
		}()
	}

	// Single rekey writer: models the byte-threshold-driven send-cipher
	// swap that Stores a fresh encryptor concurrently with the sends.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for k := 0; k < rekeys; k++ {
			c.rekeySendCipher()
		}
	}()

	wg.Wait()

	if c.encryptor.Load() == nil {
		t.Fatal("encryptor.Load() is nil after concurrent sends + rekeys; the atomic swap must always leave a live encryptor")
	}
}
