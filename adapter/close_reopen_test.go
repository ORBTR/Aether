//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// TestNoiseStream_ACloseQueuedAfterAResetAndReopenStaysOffTheIDsNextStream: a Close
// whose CLOSE has passed its closeSent check and taken its sequence number when a
// RESET ends the stream and the peer opens the ID again queues nothing: the CLOSE,
// numbered in the ended stream's sequence and naming it, would otherwise sit in the
// queue of the stream that now holds the ID and be written as that stream's frame.
// The seam (beforeCloseQueued) runs the RESET, its acknowledgment and the peer's
// reopening between the CLOSE's sequence number and its queueing.
func TestNoiseStream_ACloseQueuedAfterAResetAndReopenStaysOffTheIDsNextStream(t *testing.T) {
	client, server, toServer, _ := filteredPair(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	const id = 1010
	old, _ := openWithCredit(t, ctx, client, server, id, 0)
	waitSendWindowEmpty(t, old, "the opening message acknowledged")
	oldInc := old.incarnation

	var closesAfterReopen atomic.Int32
	var reopened atomic.Bool
	toServer.setRule(func(f *aether.Frame) bool {
		if reopened.Load() && f.StreamID == id && f.Type == aether.TypeCLOSE && aether.DecodeClosePayload(f.Payload) == oldInc {
			closesAfterReopen.Add(1)
		}
		return false
	})
	var next aether.Stream
	hook := func() {
		if err := old.Reset(aether.ResetCancel); err != nil {
			t.Errorf("reset: %v", err)
			return
		}
		waitLong(t, "the RESET's acknowledgment", func() bool { return client.pendingResetCount.Load() == 0 })
		st, err := server.OpenStream(ctx, aether.StreamConfig{StreamID: id, Reliability: aether.ReliableOrdered, Priority: 128})
		if err != nil {
			t.Errorf("the peer's reopen: %v", err)
			return
		}
		next = st
		waitLong(t, "the peer's stream under the ID", func() bool {
			client.mu.Lock()
			defer client.mu.Unlock()
			cur, ok := client.streams[id]
			return ok && cur != old
		})
		reopened.Store(true)
	}
	old.beforeCloseQueued.Store(&hook)
	if err := old.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if next == nil {
		t.Fatal("the seam did not reopen the ID")
	}
	time.Sleep(500 * time.Millisecond)
	if n := closesAfterReopen.Load(); n != 0 {
		t.Fatalf("the ended stream's CLOSE was written %d times under the ID its next stream holds", n)
	}
	if err := next.Send(ctx, []byte("next")); err != nil {
		t.Fatalf("send on the next stream: %v", err)
	}
	mine, err := client.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept the peer's stream: %v", err)
	}
	if got, err := mine.Receive(ctx); err != nil || string(got) != "next" {
		t.Fatalf("the next stream read %q, %v", got, err)
	}
}
