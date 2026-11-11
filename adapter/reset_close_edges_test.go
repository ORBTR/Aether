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
// (settleLocalReset) ran is in no RESET's counts and no grant returns it, so the Send
// gives its connection charge back itself: the settlement closed the stream's record
// of connection charges (commitConnCharge), and releaseInFlight, called again as
// Reset calls it, returns nothing more to the connection window. The stream charge is
// made by hand on a stream Reset has removed, the state a Send racing the RESET
// leaves, and the rest of the Send (sendStreamCharged) charges the connection.
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
	msg := make([]byte, 4096)
	n := messageCredit(int64(len(msg)))
	if err := cs.window.Consume(ctx, n); err != nil {
		t.Fatalf("premise: the stream window charges after the RESET: %v", err)
	}
	if err := cs.sendStreamCharged(ctx, msg, n); err == nil {
		t.Fatal("a Send on the reset stream returned nil")
	}
	if got := connOutstanding(client); got != before {
		t.Fatalf("after the Send the connection has %d outstanding, want %d: the late charge stays held", got, before)
	}
	cs.releaseInFlight()
	if got := connOutstanding(client); got != before {
		t.Fatalf("after releaseInFlight the connection has %d outstanding, want %d", got, before)
	}
	if got := cs.window.Outstanding(); got != 0 {
		t.Fatalf("the reset stream's window holds %d after releaseInFlight", got)
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

// TestNoiseStream_AnEndedStreamsRetransmitStaysOffTheIDsNextStream: the reliability
// tick works from a snapshot of s.streams, so it can come to a stream a RESET has
// ended after the next stream has opened under the same ID. The ended stream's
// retransmit queue is emptied as it ends (teardown), and a frame that reaches it
// anyway, as one the write loop writes between the teardown and the scheduler exit
// does, is not queued under the ID: the next stream's peer would read it in its own
// sequence. Between the snapshot and the work (tickSnapshotTaken) the test resets the
// stream, opens the next one, and holds a frame of the ended stream in its queue
// until it is due; the next stream's peer must read only what the next stream sent.
// The client's ACKs on the ID are dropped, so the ended stream's frame stays owed.
func TestNoiseStream_AnEndedStreamsRetransmitStaysOffTheIDsNextStream(t *testing.T) {
	client, server, _, toClient := filteredPair(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const id = 980
	old, _ := openWithCredit(t, ctx, client, server, id, 0)
	waitSendWindowEmpty(t, old, "the opening message acknowledged")
	toClient.setRule(func(f *aether.Frame) bool { return f.StreamID == id && f.Type == aether.TypeACK })
	if err := old.Send(ctx, []byte("ended stream's frame")); err != nil {
		t.Fatalf("send: %v", err)
	}
	var owed *aether.Frame
	waitFor(t, "the ended stream's frame written", func() bool {
		owed, _ = old.sendWindow.HighestWritten()
		return owed != nil
	})
	owedBytes := int64(len("ended stream's frame"))

	type hookResult struct {
		queuedAfterReset int
		next             aether.Stream
		err              error
	}
	ran := make(chan hookResult, 1)
	var once atomic.Bool
	hook := func(s *NoiseSession) {
		if s != client || !holdsSelf(old) || !once.CompareAndSwap(false, true) {
			return
		}
		var r hookResult
		defer func() { ran <- r }()
		if r.err = old.Reset(aether.ResetCancel); r.err != nil {
			return
		}
		r.queuedAfterReset = old.retransmitQ.Len()
		deadline := time.Now().Add(10 * time.Second)
		for {
			r.next, r.err = client.OpenStream(ctx, aether.StreamConfig{StreamID: id, Reliability: aether.ReliableOrdered, Priority: 128})
			if r.err == nil || time.Now().After(deadline) {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if r.err != nil {
			return
		}
		if old.retransmitQ.Len() == 0 {
			old.retransmitQ.EnqueueSized(owed, owedBytes)
		}
		for old.retransmitQ.NextDueIn() > 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
	}
	tickSnapshotTaken.Store(&hook)
	defer tickSnapshotTaken.Store(nil)
	var r hookResult
	select {
	case r = <-ran:
	case <-time.After(20 * time.Second):
		t.Fatal("the tick never ran the hook")
	}
	if r.err != nil {
		t.Fatalf("reset and reopen: %v", r.err)
	}
	if r.queuedAfterReset != 0 {
		t.Errorf("the ended stream's retransmit queue holds %d entries after its Reset", r.queuedAfterReset)
	}
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept the next stream: %v", err)
	}
	if err := r.next.Send(ctx, []byte("next stream's frame")); err != nil {
		t.Fatalf("send on the next stream: %v", err)
	}
	if got, err := accepted.Receive(ctx); err != nil || string(got) != "next stream's frame" {
		t.Fatalf("the next stream's peer read %q, %v", got, err)
	}
	if res := <-receiveAsync(ctx, accepted, 1500*time.Millisecond); res.err == nil {
		t.Fatalf("the next stream's peer read %q, which the ended stream sent", res.data)
	}
	if old.queueRetransmit(owed) || old.queueProbe(owed) {
		t.Fatal("a retransmit or probe of the ended stream was queued under the ID its next stream holds")
	}
}

// TestNoiseStream_AChargeTheSettlementCountedIsNotReturnedAgain: a Send that recorded
// its connection charge (commitConnCharge) before a RESET's settlement and then fails
// gives nothing back itself (returnCharge): the settlement counted the charge and
// returned it on the peer's statement (the RESET's acknowledgment), and a second
// return would hand the connection window the charge of another stream's unread
// message.
func TestNoiseStream_AChargeTheSettlementCountedIsNotReturnedAgain(t *testing.T) {
	client, server := noisePairWithRealms(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cs, _ := openWithCredit(t, ctx, client, server, 984, 0)
	other, _ := openWithCredit(t, ctx, client, server, 986, 0)
	unread := []byte("unread by the peer")
	if err := other.Send(ctx, unread); err != nil {
		t.Fatalf("send on the other stream: %v", err)
	}
	held := messageCredit(int64(len(unread)))
	waitSendWindowEmpty(t, cs, "the opening message acknowledged")
	waitFor(t, "the opening message's grants", func() bool {
		return cs.window.Outstanding() == 0 && client.connWindow.Stats().Outstanding == held
	})
	const n = 64
	if err := cs.window.Consume(ctx, n); err != nil {
		t.Fatalf("stream charge: %v", err)
	}
	if err := client.connWindow.Consume(ctx, n); err != nil {
		t.Fatalf("connection charge: %v", err)
	}
	if !cs.commitConnCharge(n) {
		t.Fatal("premise: the record refused a charge before any settlement")
	}
	if err := cs.Reset(aether.ResetCancel); err != nil {
		t.Fatalf("reset: %v", err)
	}
	waitFor(t, "the settlement on the acknowledgment", func() bool { return client.connWindow.Stats().Outstanding == held })
	cs.returnCharge(n)
	if got := client.connWindow.Stats().Outstanding; got != held {
		t.Fatalf("connection charge %d after the failing Send's return, want %d", got, held)
	}
}
