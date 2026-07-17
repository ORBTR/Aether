//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package noise

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
	"time"

	aether "github.com/ORBTR/aether"
	transportCrypto "github.com/ORBTR/aether/crypto/identity"
	"github.com/flynn/noise"
)

// TestRedialAfterLostMsg2_ResponseCarriesCurrentNonce is the regression guard
// for a permanent noise-UDP dial lockout.
//
// THE BUG: listenerHandshake is keyed by the peer's ADDRESS and survives 30s
// (pruneStaleHandshakes). It caches the msg2 it sent — ALREADY WRAPPED in the
// dial nonce of the dial that created it (handshake.go: hs.response = sent).
// When a later msg1 arrives from that same address, handleHandshake takes the
// "existing handshake" branch, tries to read it as msg3, fails (it is a msg1,
// dial envelope still attached), and re-sends hs.response VERBATIM — carrying
// the ORIGINAL nonce.
//
// If the initiator's first dial timed out (one lost msg2 is enough), it has
// unregistered that nonce and re-dialed with a FRESH one. The responder's
// reply then arrives tagged with the stale nonce, dispatchToPendingDial finds
// no channel for it, the packet is dropped, and the new dial times out too —
// which triggers another re-dial, inside the same 30s window, forever. One
// dropped packet becomes a self-sustaining lockout: observed in production as
// 100% of noise-UDP dials failing on "msg2 timeout" while WS/TLS stayed
// healthy.
//
// listenerHandshake ALREADY carries a dialNonce field for exactly this — it is
// stored at construction and never read. The fix uses it: re-wrap the cached
// response with the CURRENT dial's nonce before re-sending.
//
// The initiator here is a raw UDP socket (not a real transport) so the test
// drives the exact sequence deterministically and does not depend on
// shared-socket dispatch timing — it runs on every platform.
func TestRedialAfterLostMsg2_ResponseCarriesCurrentNonce(t *testing.T) {
	const testNetKey = "redial-nonce-regression-key"

	_, respPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("responder keygen: %v", err)
	}
	respNodeID, err := aether.NewNodeID(respPriv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("responder node id: %v", err)
	}
	respTransport, err := NewNoiseTransport(NoiseTransportConfig{
		PrivateKey:  respPriv,
		LocalNode:   respNodeID,
		ListenAddr:  "127.0.0.1:0",
		NetworkKeys: []string{testNetKey},
	})
	if err != nil {
		t.Fatalf("responder transport: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	respListener, err := respTransport.Listen(ctx)
	if err != nil {
		t.Fatalf("responder listen: %v", err)
	}
	defer respListener.Close()
	respAddr := respListener.Addr().(*net.UDPAddr)

	// Raw-socket initiator: full control over the dial nonce per attempt.
	cli, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer cli.Close()

	km, err := transportCrypto.NewNetworkKeyManager([]string{testNetKey})
	if err != nil {
		t.Fatalf("key manager: %v", err)
	}
	activeKey := km.ActiveKey()
	fpBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(fpBuf, transportCrypto.CRC32Hash(activeKey))

	// buildMsg1 returns [fingerprint:4][patternFlagXX:1][noise msg1] for a
	// fresh XX handshake — the exact inner packet the real initiator sends.
	buildMsg1 := func() []byte {
		_, cliPriv, _ := ed25519.GenerateKey(rand.Reader)
		suite := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
		kp, err := suite.GenerateKeypair(rand.Reader)
		if err != nil {
			t.Fatalf("client keypair: %v", err)
		}
		_ = cliPriv
		hs, err := noise.NewHandshakeState(noise.Config{
			Pattern:       noise.HandshakeXX,
			Initiator:     true,
			Prologue:      activeKey,
			CipherSuite:   suite,
			StaticKeypair: kp,
			Random:        rand.Reader,
		})
		if err != nil {
			t.Fatalf("client handshake state: %v", err)
		}
		m1, _, _, err := hs.WriteMessage(nil, nil)
		if err != nil {
			t.Fatalf("client msg1: %v", err)
		}
		out := make([]byte, 0, 5+len(m1))
		out = append(out, fpBuf...)
		out = append(out, patternFlagXX)
		out = append(out, m1...)
		return out
	}

	wrap := func(nonce, cookie, inner []byte) []byte {
		out := make([]byte, 0, 1+dialNonceLen+len(cookie)+len(inner))
		out = append(out, dialNoncePrefix)
		out = append(out, nonce...)
		out = append(out, cookie...)
		out = append(out, inner...)
		return out
	}

	recv := func(what string) []byte {
		buf := make([]byte, 2048)
		_ = cli.SetReadDeadline(time.Now().Add(4 * time.Second))
		n, _, err := cli.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("no %s from responder: %v", what, err)
		}
		return append([]byte(nil), buf[:n]...)
	}

	nonceA := make([]byte, dialNonceLen)
	nonceB := make([]byte, dialNonceLen)
	_, _ = rand.Read(nonceA)
	_, _ = rand.Read(nonceB)
	if string(nonceA) == string(nonceB) {
		t.Fatal("nonces collided")
	}

	// ── Dial #1 (nonceA): plain msg1 → responder issues a RETRY cookie ──
	if _, err := cli.WriteToUDP(wrap(nonceA, nil, buildMsg1()), respAddr); err != nil {
		t.Fatalf("send msg1 #1: %v", err)
	}
	retry := recv("RETRY token")
	if len(retry) < 1+dialNonceLen+retryHeaderSize || retry[0] != dialNoncePrefix {
		t.Fatalf("expected nonce-wrapped RETRY, got %dB first=0x%02X", len(retry), retry[0])
	}
	cookie := retry[1+dialNonceLen:]
	if !HasRetryPrefix(cookie) {
		t.Fatalf("expected retry cookie, got first=0x%02X", cookie[0])
	}

	// ── Dial #1 cont: cookie-bearing msg1 → responder sends msg2 (nonceA).
	// We deliberately DROP it: this is the single lost packet that starts the
	// lockout. The responder now holds hs[cliAddr] with response=0xFD+nonceA+msg2.
	if _, err := cli.WriteToUDP(wrap(nonceA, cookie, buildMsg1()), respAddr); err != nil {
		t.Fatalf("send cookied msg1 #1: %v", err)
	}
	_ = recv("msg2 #1 (dropped on purpose)")

	// ── Dial #2 (nonceB): the initiator gave up on nonceA and re-dialed with a
	// fresh nonce from the same address, well inside the 30s handshake TTL.
	if _, err := cli.WriteToUDP(wrap(nonceB, cookie, buildMsg1()), respAddr); err != nil {
		t.Fatalf("send cookied msg1 #2: %v", err)
	}
	resp := recv("msg2 #2")

	if resp[0] != dialNoncePrefix {
		t.Fatalf("re-dial response not nonce-wrapped: %dB first=0x%02X", len(resp), resp[0])
	}
	got := resp[1 : 1+dialNonceLen]
	if string(got) == string(nonceA) {
		t.Fatalf("RE-DIAL LOCKOUT: responder answered dial #2 with the STALE nonce from dial #1 "+
			"(got %x, want %x). dispatchToPendingDial has no channel for the stale nonce, so this "+
			"packet is dropped and dial #2 times out — which re-dials, inside the same 30s window, "+
			"forever. One lost msg2 becomes a permanent noise-UDP lockout.", got, nonceB)
	}
	if string(got) != string(nonceB) {
		t.Fatalf("re-dial response carried an unknown nonce: got %x, want %x", got, nonceB)
	}
}
