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
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	aether "github.com/ORBTR/aether"
	"github.com/flynn/noise"
)

var errShimResolveMsg3 = errors.New("shim: resolveHandshakeKey rejected inner msg1")

// plainMsg1InnerSize is the exact wire size of an un-cookied msg1 inside the
// dial-nonce envelope: [CRC32 fingerprint:4][patternFlag:1][Noise XX e:32].
// It is also why a plain msg1 looks like a 37-byte packet on the wire — the
// shape that appears when a node dials itself and reads its own msg1 back as
// a msg2 ("noise: message is too short").
const plainMsg1InnerSize = 4 + 1 + 32

// TestHandshakeMsg3Retransmit_SurvivesLoss guards the last unprotected message
// in a 3-message handshake running over lossy UDP.
//
// THE BUG: msg1 has a retransmit ticker (bf11f10 "retransmit handshake msg1 so
// it survives packet loss") and msg2 is re-sent from hs.response whenever a
// duplicate msg1 arrives — but msg3 was written once, fire-and-forget, with no
// ack and no retransmit. The initiator then immediately declared the handshake
// complete and installed a session.
//
// A single dropped msg3 therefore left the session HALF-OPEN: the initiator
// holds cipher states and believes it is connected, while the responder never
// completes and prunes its listenerHandshake at the 30s TTL. Everything the
// initiator sends lands on a responder with no session for that addr, is not
// dispatched, and is discarded. Nothing ever comes back, so the session sits
// with inFlight=1 per stream and recv{exp=0}, and STALL-DETECT reaps it at the
// 120s threshold with "session stuck (no forward progress)" /
// "ping timeout (no inbound activity)".
//
// Observed in production as noise-UDP links that establish, win the path
// (ws/tls drained in their favour), then die 34s-2m later and reform — a
// sawtooth that never persists.
//
// Retransmitting msg3 is safe and idempotent: the responder answers a duplicate
// msg1 by re-sending its cached msg2, and a duplicate msg3 on a completed
// handshake is ignored.
//
// The shim below deliberately SWALLOWS the first msg3 (the lost packet) and
// asserts the initiator sends another. Fails before the fix (exactly one msg3
// is ever transmitted); passes after.
func TestHandshakeMsg3Retransmit_SurvivesLoss(t *testing.T) {
	const testNetKey = "msg3-retransmit-regression-key"

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
	respListener := &noiseListener{transport: respTransport}

	shimConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("shim listen: %v", err)
	}
	t.Cleanup(func() { _ = shimConn.Close() })
	shimAddr := shimConn.LocalAddr().(*net.UDPAddr)

	var msg3Seen int64 // raw (un-enveloped) noise messages after msg2 == msg3 arrivals

	sendNonceTagged := func(dst *net.UDPAddr, nonce, payload []byte) {
		out := make([]byte, 0, 1+len(nonce)+len(payload))
		out = append(out, dialNoncePrefix)
		out = append(out, nonce...)
		out = append(out, payload...)
		_, _ = shimConn.WriteToUDP(out, dst)
	}

	buildMsg2 := func(realInner []byte) ([]byte, error) {
		prologue, _, patFlag, noiseMsg, ok := respListener.resolveHandshakeKey(realInner)
		if !ok {
			return nil, errShimResolveMsg3
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
		for {
			_ = shimConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, src, rerr := shimConn.ReadFromUDP(buf)
			if rerr != nil {
				if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
					continue
				}
				return
			}
			pkt := append([]byte(nil), buf[:n]...)

			// A msg3 sent by an OLDER build carries no envelope — count it so
			// this test still describes that peer correctly.
			if len(pkt) < 1+dialNonceLen || pkt[0] != dialNoncePrefix {
				atomic.AddInt64(&msg3Seen, 1)
				continue
			}

			nonce := pkt[1 : 1+dialNonceLen]
			inner := pkt[1+dialNonceLen:]

			// Cookie-bearing msg1 retransmit -> answer with a genuine msg2.
			if HasRetryPrefix(inner) && len(inner) > retryHeaderSize {
				realInner := inner[retryHeaderSize:]
				msg2, berr := buildMsg2(realInner)
				if berr != nil {
					continue
				}
				sendNonceTagged(src, nonce, msg2)
				continue
			}

			// Plain msg1 is exactly [CRC32 fp:4][patFlag:1][XX e:32] = 37B.
			if len(inner) == plainMsg1InnerSize {
				token := respTransport.retryGuard.IssueToken(src, time.Now())
				sendNonceTagged(src, nonce, token)
				continue
			}

			// Anything else enveloped from this peer is msg3 (now carrying the
			// dial-nonce envelope so it is not coin-flipped into the QUIC
			// demux). Count it and SWALLOW it — this is the dropped packet
			// that strands the session half-open.
			atomic.AddInt64(&msg3Seen, 1)
		}
	}()

	cliPubKey, cliPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("client keygen: %v", err)
	}
	cliNodeID, err := aether.NewNodeID(cliPubKey)
	if err != nil {
		t.Fatalf("client node id: %v", err)
	}
	cliTransport, err := NewNoiseTransport(NoiseTransportConfig{
		PrivateKey:  cliPriv,
		LocalNode:   cliNodeID,
		ListenAddr:  "127.0.0.1:0",
		NetworkKeys: []string{testNetKey},
	})
	if err != nil {
		t.Fatalf("client transport: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cliListener, err := cliTransport.Listen(ctx)
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer cliListener.Close()

	dialCtx, dialCancel := context.WithTimeout(ctx, 8*time.Second)
	defer dialCancel()
	sess, derr := cliTransport.Dial(dialCtx, aether.Target{
		Address: shimAddr.String(),
		NodeID:  respNodeID,
	})
	if derr != nil {
		t.Fatalf("dial did not complete (shim answers msg1+msg2, so the handshake "+
			"should reach msg3): %v", derr)
	}
	defer sess.Close()

	// The initiator believes it is connected. The responder never saw msg3, so
	// unless msg3 is retransmitted this session is half-open and will be reaped
	// by STALL-DETECT at 120s having never received a single inbound packet.
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(&msg3Seen) >= 2 {
			return // retransmitted — the half-open is recoverable
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("msg3 was transmitted %d time(s) and never retransmitted after being dropped: "+
		"the session is HALF-OPEN — initiator holds cipher states and believes it is connected, "+
		"responder never completed and prunes at 30s. Every send is discarded, nothing returns, "+
		"and STALL-DETECT reaps the session at 120s with 'no forward progress'. This is the "+
		"noise-UDP sawtooth: links establish, win the path, then die ~2m later, forever.",
		atomic.LoadInt64(&msg3Seen))
}
