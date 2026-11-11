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

// TestNoiseSession_AnEncryptedShortFrameItCannotAuthenticateReachesNoConsumer: a 0x87
// frame's payload is its [Nonce][Ciphertext][Tag] envelope, so one that reaches the
// dispatch of a session holding no frame key (its decoder refuses the form first,
// aether.Compressor.AcceptEncryptedShort, which only SetSessionKey sets) is refused and
// charged to the peer as malformed, and nothing of it reaches the stream's consumer.
func TestNoiseSession_AnEncryptedShortFrameItCannotAuthenticateReachesNoConsumer(t *testing.T) {
	client, server, _, _ := filteredPair(t, func(o *aether.SessionOptions) { o.SessionWarmupGrace = -1 })
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, ss := openWithCredit(t, ctx, client, server, 912, 0)
	before := server.ForensicSuppressedCount()
	payload := []byte("plain, no envelope")
	server.processIncomingFrame(&aether.Frame{
		SenderID: client.LocalPeerID(), ReceiverID: server.LocalPeerID(),
		StreamID: 912, Type: aether.TypeDATA, SeqNo: ss.recvWindow.ExpectedSeqNo(),
		Length: uint32(len(payload)), Payload: payload,
	}, aether.ShortEncryptedIndicator)
	if r := <-receiveAsync(ctx, ss, 300*time.Millisecond); r.err == nil {
		t.Fatalf("the consumer read %q from an encrypted short frame no key authenticated", r.data)
	}
	if got := server.ForensicSuppressedCount() - before; got != 1 {
		t.Fatalf("the refusal was charged %d times, want once", got)
	}
}
