//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"context"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// sealedLooking is a full-header DATA frame flagged FlagENCRYPTED as a peer holding a
// frame key writes it: a nonce in the header and a payload that is ciphertext and tag.
func sealedLooking(from, to aether.PeerID, id uint64, seq uint32) *aether.Frame {
	payload := []byte("ciphertext and a sixteen-byte tag")
	f := &aether.Frame{
		SenderID: from, ReceiverID: to, StreamID: id, Type: aether.TypeDATA,
		Flags: aether.FlagENCRYPTED | aether.FlagANTIREPLAY, SeqNo: seq,
		Length: uint32(len(payload)), Payload: payload,
	}
	f.Nonce[11] = 1
	return f
}

// TestNoiseSession_AnEncryptedFullFrameWithNoFrameKeyReachesNoConsumer: a full-header
// frame flagged FlagENCRYPTED that reaches a Noise session holding no frame key (no
// SetSessionKey) has no plaintext reading there, so the session refuses it as
// malformed and nothing of it reaches the stream's consumer; only a relay forwards
// such a frame, and it does so below any session (spec 6.5).
func TestNoiseSession_AnEncryptedFullFrameWithNoFrameKeyReachesNoConsumer(t *testing.T) {
	client, server, _, _ := filteredPair(t, func(o *aether.SessionOptions) { o.SessionWarmupGrace = -1 })
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, ss := openWithCredit(t, ctx, client, server, 922, 0)
	before := server.ForensicSuppressedCount()
	server.processIncomingFrame(sealedLooking(client.LocalPeerID(), server.LocalPeerID(), 922, ss.recvWindow.ExpectedSeqNo()), aether.FullFrameDiscriminator)
	if r := <-receiveAsync(ctx, ss, 300*time.Millisecond); r.err == nil {
		t.Fatalf("the consumer read %q from an encrypted frame no key opened", r.data)
	}
	if got := server.ForensicSuppressedCount() - before; got != 1 {
		t.Fatalf("the refusal was charged %d times, want once", got)
	}
}

// TestTCPSession_AnEncryptedFullFrameReachesNoConsumer: no TCP-family session holds a
// frame key, so a frame flagged FlagENCRYPTED it reads is refused as malformed, and
// its payload, ciphertext there, never reaches the stream's consumer.
func TestTCPSession_AnEncryptedFullFrameReachesNoConsumer(t *testing.T) {
	client, server := tcpPairWithOptions(t, aether.DefaultSessionOptions())
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cs, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: 924, Reliability: aether.ReliableOrdered})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := cs.Send(ctx, []byte("hello")); err != nil {
		t.Fatalf("send: %v", err)
	}
	ss, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if r := <-receiveAsync(ctx, ss, 5*time.Second); r.err != nil || string(r.data) != "hello" {
		t.Fatalf("first receive %q, %v", r.data, r.err)
	}
	before := server.PeerAbuseScore()
	server.dispatchFrame(sealedLooking(client.LocalPeerID(), server.LocalPeerID(), 924, 0))
	if r := <-receiveAsync(ctx, ss, 300*time.Millisecond); r.err == nil {
		t.Fatalf("the consumer read %q from an encrypted frame no key opened", r.data)
	}
	if server.PeerAbuseScore() <= before {
		t.Fatal("the refusal was not charged to the peer")
	}
}
