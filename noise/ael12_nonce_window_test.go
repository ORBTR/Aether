//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package noise

import "testing"

// TestAEL12_ExplicitNonceHonoursConfiguredWindow is the AE-L-12 regression
// guard. Before the fix, enableExplicitNonce (session.go) and rekeyRecvCipher
// passed a hardcoded literal 64 to newNonceWindow, so the plumbed
// NoiseTransport.nonceWindow (cfg.NonceWindowSize) was silently dead — an
// operator asking for a tighter reorder window (e.g. 32) got 64 anyway. The
// fix routes both call sites through noiseConn.nonceWindowSize(), which reads
// transport.nonceWindow and falls back to 64 only when the transport is nil.
//
// Each sub-case uses a fresh (send, recv) CipherState pair from
// testSendRecvCipherStates because enableExplicitNonce extracts (and thereby
// invalidates) the underlying AEAD ciphers.
func TestAEL12_ExplicitNonceHonoursConfiguredWindow(t *testing.T) {
	t.Run("configured_smaller_window", func(t *testing.T) {
		sendCS, recvCS := testSendRecvCipherStates(t)
		c := &noiseConn{
			send:      sendCS,
			recv:      recvCS,
			transport: &NoiseTransport{nonceWindow: 32},
			rekey:     NewRekeyTracker(0, 0),
			writeFunc: func(b []byte) (int, error) { return len(b), nil },
		}
		c.enableExplicitNonce()
		if c.window == nil {
			t.Fatalf("AE-L-12: window not initialised")
		}
		// Regression assertion: before the fix this was the hardcoded 64.
		if got := c.window.window; got != 32 {
			t.Fatalf("AE-L-12: enableExplicitNonce window = %d, want configured 32", got)
		}
	})

	t.Run("rekey_recv_honours_config", func(t *testing.T) {
		sendCS, recvCS := testSendRecvCipherStates(t)
		c := &noiseConn{
			send:      sendCS,
			recv:      recvCS,
			transport: &NoiseTransport{nonceWindow: 32},
			rekey:     NewRekeyTracker(0, 0),
			writeFunc: func(b []byte) (int, error) { return len(b), nil },
		}
		c.enableExplicitNonce()
		c.rekeyRecvCipher()
		if c.window == nil {
			t.Fatalf("AE-L-12: window not initialised after rekey")
		}
		// Guards session.go rekeyRecvCipher — before the fix this was 64.
		if got := c.window.window; got != 32 {
			t.Fatalf("AE-L-12: rekeyRecvCipher window = %d, want configured 32", got)
		}
	})

	t.Run("nil_transport_falls_back_to_64", func(t *testing.T) {
		sendCS, recvCS := testSendRecvCipherStates(t)
		// No transport: nonceWindowSize must fall back to the safe default so
		// test-constructed conns (and any parentless noiseConn) don't nil-deref.
		c := &noiseConn{
			send:      sendCS,
			recv:      recvCS,
			rekey:     NewRekeyTracker(0, 0),
			writeFunc: func(b []byte) (int, error) { return len(b), nil },
		}
		c.enableExplicitNonce()
		if got := c.window.window; got != 64 {
			t.Fatalf("AE-L-12: nil-transport window = %d, want default 64", got)
		}
	})

	t.Run("upper_clamp_preserved", func(t *testing.T) {
		sendCS, recvCS := testSendRecvCipherStates(t)
		// 100 exceeds the uint64-bitmap maximum; newNonceWindow must clamp to
		// 64 so the configured knob can never raise the limit past the cap.
		c := &noiseConn{
			send:      sendCS,
			recv:      recvCS,
			transport: &NoiseTransport{nonceWindow: 100},
			rekey:     NewRekeyTracker(0, 0),
			writeFunc: func(b []byte) (int, error) { return len(b), nil },
		}
		c.enableExplicitNonce()
		if got := c.window.window; got != 64 {
			t.Fatalf("AE-L-12: over-cap window = %d, want clamped 64", got)
		}
	})
}
