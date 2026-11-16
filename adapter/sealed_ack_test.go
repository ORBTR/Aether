//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// TestNoiseSession_AKeyedSessionWithShortFormsReadsEveryACK: both sessions hold the
// frame key before any traffic and write the short forms. Every message arrives, the
// sender's window empties, which only the receiver's ACKs do, and neither session
// refuses a frame as malformed: a sealed ACK that took a short form would lose its
// ENCRYPTED flag and be read as ciphertext.
func TestNoiseSession_AKeyedSessionWithShortFormsReadsEveryACK(t *testing.T) {
	client, server, _, _ := filteredPair(t, func(o *aether.SessionOptions) {
		o.SessionWarmupGrace = -1
		o.HeaderComp = true
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var key [32]byte
	key[0], key[31] = 0x5a, 0xa5
	if err := client.SetSessionKey(key); err != nil {
		t.Fatal(err)
	}
	if err := server.SetSessionKey(key); err != nil {
		t.Fatal(err)
	}
	cs, ss := openWithCredit(t, ctx, client, server, 1120, 0)
	beforeC, beforeS := client.ForensicSuppressedCount(), server.ForensicSuppressedCount()
	const n = 50
	for i := 0; i < n; i++ {
		if err := cs.Send(ctx, []byte(fmt.Sprintf("sealed message %03d", i))); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	for i := 0; i < n; i++ {
		rctx, rc := context.WithTimeout(ctx, 10*time.Second)
		got, err := ss.Receive(rctx)
		rc()
		if err != nil || string(got) != fmt.Sprintf("sealed message %03d", i) {
			t.Fatalf("receive %d: %q, %v", i, got, err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for cs.sendWindow.InFlight() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the sender still holds %d frames 5 s after the receiver took every message; frames refused as malformed: client %d, server %d",
				cs.sendWindow.InFlight(), client.ForensicSuppressedCount()-beforeC, server.ForensicSuppressedCount()-beforeS)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if c, s := client.ForensicSuppressedCount()-beforeC, server.ForensicSuppressedCount()-beforeS; c != 0 || s != 0 {
		t.Fatalf("frames refused as malformed on a keyed pair: client %d, server %d", c, s)
	}
}
