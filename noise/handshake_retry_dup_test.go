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
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/flynn/noise"
	aether "github.com/ORBTR/aether"
)

// TestHandshakeDuplicateRetryToken_NotReadAsMsg2 is the regression guard for
// the shared-socket initiator handshake bug in
// performInitiatorHandshakeSharedAttempt (handshake.go).
//
// THE BUG: the responder mints a fresh source-validation RETRY cookie
// (retry.go IssueToken) for EVERY plain msg1 it receives. On a lossy path the
// ~700ms msg1 retransmit races the first RETRY, so TWO RETRY tokens can be in
// flight back to the initiator. The old recvLoop guard —
//
//	if !retried && HasRetryPrefix(resp) { ... }
//
// filtered only the FIRST retry-shaped packet; once `retried` was true the
// second RETRY fell through to `msg2 = resp` and `hs.ReadMessage` on a 49-byte
// cookie returned flynn/noise's "message is too short", failing the handshake.
// The fix filters EVERY retry-shaped packet by exact length —
//
//	if HasRetryPrefix(resp) && len(resp) <= retryHeaderSize { if retried { continue } ... }
//
// dropping the duplicate cookie instead of mis-reading it as msg2.
//
// HOW THIS TEST REPRODUCES IT: the initiator is a real NoiseTransport driven
// through Dial over its live shared listener socket (the exact code path the
// bug lives in). The "responder" is a deterministic shim on a raw UDP socket
// that emulates a responder with requireRetryToken=true. On first contact the
// shim replies with TWO nonce-tagged RETRY tokens (the duplicate-RETRY race),
// then answers the cookie-bearing msg1 retransmit with a genuine Noise msg2
// (built with flynn/noise + the responder identity's signed NodeInfo).
//
// ORDERING GUARANTEE (why this is deterministic, not flaky): both RETRY tokens
// are put on the wire in response to the initial plain msg1, BEFORE the shim
// has ever seen the cookie-wrapped msg1. The shim can only build msg2 AFTER it
// receives that cookie-wrapped retransmit — which the initiator only sends
// AFTER it has consumed the first RETRY. So both RETRY tokens are enqueued on
// the initiator's pendingDial channel strictly before msg2. The channel is
// FIFO, so the recvLoop MUST dequeue and handle the second RETRY before it can
// reach msg2. A successful handshake therefore PROVES the second (post-`retried`)
// RETRY was handled correctly. On the old code the second RETRY is read as
// msg2 and the dial fails with "message is too short".
func TestHandshakeDuplicateRetryToken_NotReadAsMsg2(t *testing.T) {
	const testNetKey = "retry-dup-regression-key"

	// --- Responder identity (used only by the shim to build a real msg2) ---
	respPub, respPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("responder keygen: %v", err)
	}
	respNodeID, err := aether.NewNodeID(respPub)
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
	// Minimal listener wrapper so the shim can reuse resolveHandshakeKey to
	// parse the initiator's msg1 exactly as the production responder does.
	respListener := &noiseListener{transport: respTransport}

	// --- Deterministic responder shim on a raw UDP socket ---
	shimConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("shim listen: %v", err)
	}
	t.Cleanup(func() { _ = shimConn.Close() })
	shimAddr := shimConn.LocalAddr().(*net.UDPAddr)

	var retriesSent int64      // total RETRY tokens the shim put on the wire
	var cookiedMsg1Seen int64  // set once the initiator answered a RETRY
	var msg2Built int64        // set once the shim produced a genuine msg2
	shimErr := make(chan error, 1)

	// sendNonceTagged writes [0xFD][nonce][payload] — the dial-nonce envelope
	// the initiator's run loop routes back to the pending-dial channel.
	sendNonceTagged := func(dst *net.UDPAddr, nonce, payload []byte) {
		out := make([]byte, 0, 1+len(nonce)+len(payload))
		out = append(out, dialNoncePrefix)
		out = append(out, nonce...)
		out = append(out, payload...)
		_, _ = shimConn.WriteToUDP(out, dst)
	}

	// buildMsg2 runs the responder half of the Noise handshake against the
	// initiator's original msg1 (extracted from the cookie-wrapped retransmit)
	// and returns the bytes to echo back as msg2.
	buildMsg2 := func(realInner []byte) ([]byte, error) {
		prologue, _, patFlag, noiseMsg, ok := respListener.resolveHandshakeKey(realInner)
		if !ok {
			return nil, errShimResolve
		}
		hsPattern := noise.HandshakeXX
		if patFlag == patternFlagXK {
			hsPattern = noise.HandshakeXK
		}
		state, err := noise.NewHandshakeState(noise.Config{
			Pattern:     hsPattern,
			Initiator:   false,
			Prologue:    prologue,
			CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
			StaticKeypair: noise.DHKey{
				Private: append([]byte(nil), respTransport.staticPriv...),
				Public:  append([]byte(nil), respTransport.staticPub...),
			},
			Random: rand.Reader,
		})
		if err != nil {
			return nil, err
		}
		if _, _, _, err := state.ReadMessage(nil, noiseMsg); err != nil {
			return nil, err
		}
		payload, err := respTransport.encodeNodeInfo()
		if err != nil {
			return nil, err
		}
		msg2, _, _, err := state.WriteMessage(nil, payload)
		if err != nil {
			return nil, err
		}
		return msg2, nil
	}

	go func() {
		buf := make([]byte, 4096)
		var cachedMsg2 []byte
		for {
			_ = shimConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, src, rerr := shimConn.ReadFromUDP(buf)
			if rerr != nil {
				if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
					continue // keep serving until the socket is closed
				}
				return // socket closed at cleanup
			}
			pkt := append([]byte(nil), buf[:n]...)

			// Only dial-nonce-enveloped packets are part of the handshake we
			// emulate. The initiator's trailing msg3 (raw noise, no envelope)
			// falls through here and is ignored.
			if len(pkt) < 1+dialNonceLen || pkt[0] != dialNoncePrefix {
				continue
			}
			nonce := pkt[1 : 1+dialNonceLen]
			inner := pkt[1+dialNonceLen:]

			// Cookie-wrapped msg1 retransmit: [0xFE cookie:49][CRC32|patFlag|msg1].
			// A plain msg1 envelope is only 37 bytes (<= retryHeaderSize), so the
			// exact-length test unambiguously separates the two regardless of
			// what the CRC32 fingerprint's first byte happens to be.
			if HasRetryPrefix(inner) && len(inner) > retryHeaderSize {
				atomic.StoreInt64(&cookiedMsg1Seen, 1)
				if cachedMsg2 == nil {
					m2, berr := buildMsg2(inner[retryHeaderSize:])
					if berr != nil {
						select {
						case shimErr <- berr:
						default:
						}
						return
					}
					cachedMsg2 = m2
					atomic.StoreInt64(&msg2Built, 1)
				}
				sendNonceTagged(src, nonce, cachedMsg2)
				continue
			}

			// Plain first-contact msg1: emulate a requireRetryToken=true
			// responder that minted a fresh cookie for THIS msg1 AND for its
			// in-flight retransmit — i.e. issue TWO RETRY tokens. This is the
			// duplicate-RETRY race the fix must survive.
			t1 := respTransport.retryGuard.IssueToken(src, time.Now())
			t2 := respTransport.retryGuard.IssueToken(src, time.Now())
			sendNonceTagged(src, nonce, t1)
			sendNonceTagged(src, nonce, t2)
			atomic.AddInt64(&retriesSent, 2)
		}
	}()

	// --- Initiator: a real transport dialing the shim over its shared socket ---
	cliPub, cliPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("initiator keygen: %v", err)
	}
	cliNodeID, err := aether.NewNodeID(cliPub)
	if err != nil {
		t.Fatalf("initiator node id: %v", err)
	}
	cliTransport, err := NewNoiseTransport(NoiseTransportConfig{
		PrivateKey:  cliPriv,
		LocalNode:   cliNodeID,
		ListenAddr:  "127.0.0.1:0",
		NetworkKeys: []string{testNetKey},
	})
	if err != nil {
		t.Fatalf("initiator transport: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cliListener, err := cliTransport.Listen(ctx)
	if err != nil {
		t.Fatalf("initiator listen: %v", err)
	}
	defer cliListener.Close()

	dialCtx, dialCancel := context.WithTimeout(ctx, 8*time.Second)
	defer dialCancel()
	session, err := cliTransport.Dial(dialCtx, aether.Target{
		Address: shimAddr.String(),
		NodeID:  respNodeID,
	})

	// Surface any shim-side failure first — it explains a dial error better.
	select {
	case serr := <-shimErr:
		t.Fatalf("shim failed to build a genuine msg2: %v", serr)
	default:
	}

	if err != nil {
		if strings.Contains(err.Error(), "message is too short") {
			t.Fatalf("REGRESSED: duplicate RETRY token was read as msg2 — %v", err)
		}
		t.Fatalf("Dial failed (handshake did not survive the duplicate RETRY): %v", err)
	}
	if session == nil {
		t.Fatal("Dial returned nil session with nil error")
	}
	defer session.Close()

	// --- Prove the fixed path was actually exercised ---
	rs := atomic.LoadInt64(&retriesSent)
	if rs < 2 {
		t.Fatalf("shim issued only %d RETRY tokens — the duplicate-RETRY path was not exercised", rs)
	}
	if atomic.LoadInt64(&cookiedMsg1Seen) != 1 {
		t.Fatal("initiator never answered a RETRY with a cookie-wrapped msg1 — retry handling not exercised")
	}
	if atomic.LoadInt64(&msg2Built) != 1 {
		t.Fatal("shim never produced a genuine msg2 — handshake did not complete through the real path")
	}

	if remote := session.RemoteNodeID(); string(remote) != string(respNodeID) {
		t.Fatalf("session established with wrong peer: got %x want %x", remote, respNodeID)
	}

	t.Logf("PASS: shim issued %d RETRY tokens (>=2); initiator answered the first "+
		"with a cookie-wrapped msg1 and still established a session with the "+
		"correct peer. Because both RETRYs were enqueued on the FIFO pendingDial "+
		"channel strictly before msg2, the recvLoop provably dequeued and dropped "+
		"the second (post-`retried`) RETRY instead of reading its 49 bytes as msg2.", rs)
}

// errShimResolve is returned when the shim cannot parse the initiator's msg1.
var errShimResolve = &shimResolveError{}

type shimResolveError struct{}

func (*shimResolveError) Error() string { return "shim: resolveHandshakeKey rejected initiator msg1" }
