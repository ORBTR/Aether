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

// TestNoiseStream_ASendChargedAfterTheResetsSettlementGoesBack: a Send that charged
// the stream's window and the connection window after Reset's settlement
// (settleLocalReset) ran is in no RESET's counts and no grant returns it, so
// releaseInFlight gives the connection window what the stream window still holds.
// The charge is made by hand on a stream Reset has removed, the state a Send racing
// the RESET leaves, and releaseInFlight is called again as Reset calls it.
func TestNoiseStream_ASendChargedAfterTheResetsSettlementGoesBack(t *testing.T) {
	client, server, _, _ := filteredPair(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cs, _ := openWithCredit(t, ctx, client, server, 910, 0)
	waitSendWindowEmpty(t, cs, "the opening message acknowledged")
	if err := cs.Reset(aether.ResetCancel); err != nil {
		t.Fatalf("reset: %v", err)
	}
	before := connOutstanding(client)
	const n = 4096
	if err := cs.window.Consume(ctx, n); err != nil {
		t.Fatalf("premise: the stream window charges after the RESET: %v", err)
	}
	if err := client.connWindow.Consume(ctx, n); err != nil {
		t.Fatalf("premise: the connection window charges: %v", err)
	}
	if got := connOutstanding(client); got != before+n {
		t.Fatalf("premise: %d outstanding after the charge, want %d", got, before+n)
	}
	cs.releaseInFlight()
	if got := connOutstanding(client); got != before {
		t.Fatalf("after releaseInFlight the connection has %d outstanding, want %d: the late charge stays held", got, before)
	}
}

// TestNoiseStream_AResetOfALeftStreamWritesNothing: a stream that has left the
// session on both CLOSEs has no peer stream to reset, and a RESET under its ID would
// reach whatever stream the peer holds there now, so its Reset returns nil and writes
// no RESET.
func TestNoiseStream_AResetOfALeftStreamWritesNothing(t *testing.T) {
	client, server, toServer, _ := filteredPair(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cs, ss := openWithCredit(t, ctx, client, server, 911, 0)
	if err := cs.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}
	if err := ss.Close(); err != nil {
		t.Fatalf("server close: %v", err)
	}
	waitFor(t, "the client's stream leaves", func() bool { return !streamPresent(client, 911) })
	if !cs.left.Load() {
		t.Fatal("premise: the stream is out of s.streams but has not left")
	}
	resets, _ := toServer.count(aether.TypeRESET)
	if err := cs.Reset(aether.ResetCancel); err != nil {
		t.Fatalf("reset of a left stream: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if got, _ := toServer.count(aether.TypeRESET); got != resets {
		t.Fatalf("a Reset of a left stream wrote %d RESET frames", got-resets)
	}
}

// TestNoiseStream_ARetransmittedCloseIsAcknowledgedAfterTheReceiveSideEnded: the
// server's ACK of the client's CLOSE is lost after the CLOSE has ended the server's
// receive side (endReceive). The client writes the CLOSE again; the server reads it as
// a duplicate and acknowledges it at once (ACKEngine.OnDuplicateReceived, which no
// delayed-ACK timer gates), so the client's send side ends.
func TestNoiseStream_ARetransmittedCloseIsAcknowledgedAfterTheReceiveSideEnded(t *testing.T) {
	client, server, _, toClient := filteredPair(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cs, ss := openWithCredit(t, ctx, client, server, 912, 0)
	waitSendWindowEmpty(t, cs, "the opening message acknowledged")
	var blocked atomic.Bool
	blocked.Store(true)
	toClient.setRule(func(f *aether.Frame) bool {
		return blocked.Load() && f.StreamID == 912 && f.Type == aether.TypeACK
	})
	if err := cs.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	waitFor(t, "the CLOSE ends the server's receive side", func() bool { return ss.peerClosed.Load() })
	if _, dropped := toClient.count(aether.TypeACK); dropped == 0 {
		t.Fatal("premise: no ACK of the CLOSE was lost")
	}
	if cs.closeDone.Load() {
		t.Fatal("premise: the client's CLOSE counts as acknowledged with every ACK lost")
	}
	blocked.Store(false)
	waitLong(t, "the retransmitted CLOSE acknowledged", func() bool { return cs.closeDone.Load() })
}

// TestNoiseSession_ACloseForAnUnknownStreamIsAnsweredUpToItself: a CLOSE for a stream
// the receiver does not hold is answered with a cumulative ACK whose BaseACK is the
// CLOSE's own sequence number: the peer writes its CLOSE only once every frame below
// it is acknowledged, so the ACK says that and no more.
func TestNoiseSession_ACloseForAnUnknownStreamIsAnsweredUpToItself(t *testing.T) {
	client, _, _, toClient := filteredPair(t, nil)
	const id, seq = 913, 7
	var base atomic.Int64
	base.Store(-1)
	toClient.setRule(func(f *aether.Frame) bool {
		if f.StreamID == id && f.Type == aether.TypeACK {
			if ack := aether.DecodeCompositeACK(f.Payload); ack != nil {
				base.Store(int64(ack.BaseACK))
			}
		}
		return false
	})
	payload := aether.EncodeClosePayload(aether.StreamIncarnation{Generation: 1, WriterOpened: true})
	if err := client.writeFrame(&aether.Frame{
		SenderID:   client.LocalPeerID(),
		ReceiverID: client.RemotePeerID(),
		StreamID:   id,
		Type:       aether.TypeCLOSE,
		SeqNo:      seq,
		Length:     uint32(len(payload)),
		Payload:    payload,
	}); err != nil {
		t.Fatalf("write: %v", err)
	}
	waitFor(t, "the answer to the CLOSE", func() bool { return base.Load() >= 0 })
	if got := base.Load(); got != seq {
		t.Fatalf("the CLOSE at %d is answered with BaseACK %d", seq, got)
	}
}
