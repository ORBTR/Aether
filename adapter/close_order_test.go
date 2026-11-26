//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package adapter

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/flow"
	"github.com/ORBTR/aether/reliability"
)

// receiveResult is one Receive's outcome, handed back from a goroutine.
type receiveResult struct {
	data []byte
	err  error
}

// receiveAsync runs one Receive under its own deadline and returns its outcome
// on the channel.
func receiveAsync(ctx context.Context, st aether.Stream, within time.Duration) <-chan receiveResult {
	done := make(chan receiveResult, 1)
	go func() {
		rctx, cancel := context.WithTimeout(ctx, within)
		defer cancel()
		got, err := st.Receive(rctx)
		done <- receiveResult{got, err}
	}()
	return done
}

// TestNoiseStream_AReplyThenCloseReachesAHalfClosedCaller: the caller sends its
// request and closes its send side, as an RPC caller does; the server takes the
// request, sends a reply and closes at once. Every reply reaches the caller
// whole, then io.EOF. The server's CLOSE waits for the ACK of the reply's last
// frame (finishSend), so the caller's endReceive, which ends the stream on
// both sides here, finds the reply already in its queue. The largest reply fits
// the fragment count at the MSS a session starts at (pmtu.SafeFloorMSS): nothing
// here waits for the PMTU sweep to raise it, and Send refuses a message that does
// not fit.
func TestNoiseStream_AReplyThenCloseReachesAHalfClosedCaller(t *testing.T) {
	for _, size := range []int{512, 64 * 1024, 256 * 1024} {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			key := uint32(0x5eed5eed)
			client, server := noisePairWithRealms(t, &key, &key)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			for k := 0; k < 5; k++ {
				id := uint64(500 + k)
				cs, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: id, Reliability: aether.ReliableOrdered, Priority: 128})
				if err != nil {
					t.Fatalf("open: %v", err)
				}
				if err := cs.Send(ctx, []byte("req")); err != nil {
					t.Fatalf("request: %v", err)
				}
				_ = cs.Close()
				ss, err := server.AcceptStream(ctx)
				if err != nil {
					t.Fatalf("accept: %v", err)
				}
				if _, err := ss.Receive(ctx); err != nil {
					t.Fatalf("server receive: %v", err)
				}
				reply := receiveAsync(ctx, cs, 10*time.Second)
				msg := burstMessage(k, size)
				if err := ss.Send(ctx, msg); err != nil {
					t.Fatalf("reply: %v", err)
				}
				_ = ss.Close()
				r := <-reply
				if r.err != nil || !bytes.Equal(r.data, msg) {
					t.Fatalf("rpc %d: the caller got %d of %d bytes: %v", k, len(r.data), size, r.err)
				}
				if r := <-receiveAsync(ctx, cs, 10*time.Second); !errors.Is(r.err, io.EOF) {
					t.Fatalf("rpc %d: after the reply Receive returned %d bytes, %v; want io.EOF", k, len(r.data), r.err)
				}
				waitFor(t, "the stream out of both sessions", func() bool {
					return !streamPresent(client, id) && !streamPresent(server, id)
				})
			}
		})
	}
}

// TestNoiseStream_AReplyWhoseFirstWriteIsLostStillPrecedesTheEnd: the server
// has closed its send side; the client's reply is lost on its first write and
// the client closes at once. The reply arrives by retransmit and is read before
// io.EOF. The client's CLOSE is written only after the reply's ACK: written
// behind the reply's first write it would reach the server first, and the
// server's endReceive would end the stream on both sides there before the
// retransmit came.
func TestNoiseStream_AReplyWhoseFirstWriteIsLostStillPrecedesTheEnd(t *testing.T) {
	client, server, drop := noisePairWithDroppingClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cs, ss := openWithCredit(t, ctx, client, server, 530, 0)
	if err := ss.Close(); err != nil {
		t.Fatalf("server close: %v", err)
	}
	waitFor(t, "the server's CLOSE at the client", func() bool { return cs.peerClosed.Load() })
	waitSendWindowEmpty(t, cs, "the opening message acknowledged")
	waitInFlightBytesZero(t, client, "nothing of the client's in flight")

	// One frame's worth: the session has no realm, so it cannot fragment.
	drop.dropping.Store(true)
	msg := burstMessage(7, 512)
	if err := cs.Send(ctx, msg); err != nil {
		t.Fatalf("send: %v", err)
	}
	waitFor(t, "the reply's first write", func() bool { return client.totalInFlightBytes() > 0 })
	drop.dropping.Store(false)
	_ = cs.Close()

	r := <-receiveAsync(ctx, ss, 20*time.Second)
	if r.err != nil || !bytes.Equal(r.data, msg) {
		t.Fatalf("the server got %d of %d bytes: %v", len(r.data), len(msg), r.err)
	}
	if r := <-receiveAsync(ctx, ss, 20*time.Second); !errors.Is(r.err, io.EOF) {
		t.Fatalf("after the reply Receive returned %d bytes, %v; want io.EOF", len(r.data), r.err)
	}
}

// TestNoiseStream_APeerCloseEndsReceiveWithoutALocalClose: the client sends
// three messages and closes; the server, which has not closed, reads the three
// and then io.EOF. Its send side stays open: a message it sends after the
// client's CLOSE reaches the client, and its own Close then ends the stream,
// which leaves both sessions.
func TestNoiseStream_APeerCloseEndsReceiveWithoutALocalClose(t *testing.T) {
	key := uint32(0x5eed5eed)
	client, server := noisePairWithRealms(t, &key, &key)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cs, ss := openWithCredit(t, ctx, client, server, 540, 0)
	for i := 0; i < 3; i++ {
		if err := cs.Send(ctx, burstMessage(i, 300)); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	_ = cs.Close()
	for i := 0; i < 3; i++ {
		r := <-receiveAsync(ctx, ss, 10*time.Second)
		if r.err != nil || len(r.data) != 300 || int(binary.BigEndian.Uint32(r.data)) != i {
			t.Fatalf("receive %d: %d bytes, %v", i, len(r.data), r.err)
		}
	}
	// A DATA frame for the stream after the peer's CLOSE reaches no reader:
	// the CLOSE ended the queue's admission.
	waitFor(t, "the client's CLOSE at the server", func() bool { return ss.peerClosed.Load() })
	late := burstMessage(9, 300)
	server.handleData(&aether.Frame{
		Type: aether.TypeDATA, StreamID: 540, SeqNo: ss.recvWindow.ExpectedSeqNo(),
		Flags: aether.FlagANTIREPLAY, Length: uint32(len(late)), Payload: late,
	})
	if r := <-receiveAsync(ctx, ss, 10*time.Second); !errors.Is(r.err, io.EOF) {
		t.Fatalf("after the peer's CLOSE Receive returned %d bytes, %v; want io.EOF", len(r.data), r.err)
	}
	if !streamPresent(server, 540) {
		t.Fatal("the stream left the server's session before the server closed")
	}
	if err := ss.Send(ctx, []byte("after")); err != nil {
		t.Fatalf("send after the peer's CLOSE: %v", err)
	}
	if r := <-receiveAsync(ctx, cs, 10*time.Second); r.err != nil || string(r.data) != "after" {
		t.Fatalf("the client got %q, %v", r.data, r.err)
	}
	_ = ss.Close()
	if r := <-receiveAsync(ctx, cs, 10*time.Second); !errors.Is(r.err, io.EOF) {
		t.Fatalf("after the server's CLOSE the client's Receive returned %d bytes, %v; want io.EOF", len(r.data), r.err)
	}
	waitFor(t, "the stream out of both sessions", func() bool {
		return !streamPresent(client, 540) && !streamPresent(server, 540)
	})
}

// TestNoiseSession_AFECRecoveredPayloadIsNotDeliveredBesideItsDATAFrame: a
// Reed-Solomon group whose data shards arrive as repair frames reconstructs in
// the session's decoder; its first shard is a message the client also sends as
// DATA. The server's consumer gets that message once, through its DATA frame,
// and nothing of the group: a recovered payload has no sequence number to place
// it in the stream's receive window (handleFECRepair).
func TestNoiseSession_AFECRecoveredPayloadIsNotDeliveredBesideItsDATAFrame(t *testing.T) {
	key := uint32(0x5eed5eed)
	client, server := noisePairWithRealms(t, &key, &key)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cs, ss := openWithCredit(t, ctx, client, server, 550, 0)
	msg := burstMessage(3, 200)

	k, m := reliability.DefaultRSDataShards, reliability.DefaultRSParityShards
	for i := 0; i < k; i++ {
		shard := make([]byte, len(msg))
		if i == 0 {
			copy(shard, msg)
		}
		payload := append(aether.EncodeFECHeader(aether.FECHeader{GroupID: 9, Index: uint8(i), Total: uint8(k + m)}),
			byte(len(shard)>>8), byte(len(shard)))
		payload = append(payload, shard...)
		server.handleFECRepair(&aether.Frame{
			SenderID:   server.RemotePeerID(),
			ReceiverID: server.LocalPeerID(),
			StreamID:   ss.streamID,
			Type:       aether.TypeFEC_REPAIR,
			Length:     uint32(len(payload)),
			Payload:    payload,
		})
	}
	if err := cs.Send(ctx, msg); err != nil {
		t.Fatalf("send: %v", err)
	}
	if r := <-receiveAsync(ctx, ss, 10*time.Second); r.err != nil || !bytes.Equal(r.data, msg) {
		t.Fatalf("first receive: %d bytes, %v; want the message", len(r.data), r.err)
	}
	if r := <-receiveAsync(ctx, ss, 500*time.Millisecond); r.err == nil {
		t.Fatalf("a second message of %d bytes reached the consumer", len(r.data))
	}
}

// TestNoiseStream_NoCloseFollowsAReset: a stream reset with frames unacknowledged
// and then closed writes no CLOSE. The RESET ended the send side (closeSent), and
// the reset emptied the send window, which would otherwise let Close's
// finishSend write a CLOSE the peer would read for a stream it no longer has.
func TestNoiseStream_NoCloseFollowsAReset(t *testing.T) {
	client, server, drop := noisePairWithDroppingClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cs, _ := openWithCredit(t, ctx, client, server, 560, 0)
	waitSendWindowEmpty(t, cs, "the opening message acknowledged")
	drop.dropping.Store(true)
	if err := cs.Send(ctx, burstMessage(1, 300)); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := cs.Reset(aether.ResetCancel); err != nil {
		t.Logf("reset: %v", err)
	}
	before := client.framesSent.Load()
	_ = cs.Close()
	if after := client.framesSent.Load(); after != before {
		t.Fatalf("Close after Reset wrote %d frames", after-before)
	}
}

// TestNoiseStream_AStreamThatLeftOnBothClosesCreditsItsReads: the client sends two
// messages and closes; the server, not reading, closes too, and its stream leaves
// the session once both CLOSEs are done. A message read off its queue afterwards
// is credited: the client's own leave returned no connection credit
// (leaveSession), so the grant this read makes is what returns those bytes.
func TestNoiseStream_AStreamThatLeftOnBothClosesCreditsItsReads(t *testing.T) {
	key := uint32(0x5eed5eed)
	client, server := noisePairWithRealms(t, &key, &key)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cs, ss := openWithCredit(t, ctx, client, server, 570, 0)
	for i := 0; i < 2; i++ {
		if err := cs.Send(ctx, burstMessage(i, 300)); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	_ = cs.Close()
	waitFor(t, "the client's CLOSE at the server", func() bool { return ss.peerClosed.Load() })
	_ = ss.Close()
	waitFor(t, "the stream out of the server's session", func() bool { return !streamPresent(server, 570) })
	got, credited, ok := ss.recvQ.pop()
	if !ok || len(got) != 300 {
		t.Fatalf("the queue gave %d bytes, ok %v; want the first message", len(got), ok)
	}
	if !credited {
		t.Fatal("a read after the stream left on both CLOSEs is not credited: the client's credit would be stranded")
	}
}

// TestNoiseStream_AStreamAResetEndedCreditsNoRead: after the peer's RESET a read
// off the queue credits nothing: the RESET's sender took back all the stream had
// charged (settleLocalReset), and a grant from here would return those bytes twice.
func TestNoiseStream_AStreamAResetEndedCreditsNoRead(t *testing.T) {
	key := uint32(0x5eed5eed)
	client, server := noisePairWithRealms(t, &key, &key)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cs, ss := openWithCredit(t, ctx, client, server, 571, 0)
	if err := cs.Send(ctx, burstMessage(0, 300)); err != nil {
		t.Fatalf("send: %v", err)
	}
	waitSendWindowEmpty(t, cs, "the message acknowledged")
	if err := cs.Reset(aether.ResetCancel); err != nil {
		t.Fatalf("reset: %v", err)
	}
	waitFor(t, "the stream out of the server's session", func() bool { return !streamPresent(server, 571) })
	got, credited, ok := ss.recvQ.pop()
	if !ok || len(got) != 300 {
		t.Fatalf("the queue gave %d bytes, ok %v; want the message", len(got), ok)
	}
	if credited {
		t.Fatal("a read after a RESET is credited")
	}
}

// TestNoiseStream_ASendInProgressPrecedesTheClose: a Send waiting for
// connection credit when Close is called. The CLOSE waits for that Send to end
// (sendsActive); the Send's message, once credit returns, reaches the server
// before io.EOF. Written at Close, the CLOSE would end the server's receive side
// first, and the message the Send then reported sent would reach no reader.
func TestNoiseStream_ASendInProgressPrecedesTheClose(t *testing.T) {
	key := uint32(0x5eed5eed)
	client, server := noisePairWithRealms(t, &key, &key)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	// Enough streams at the most credit one stream can hold to spend the
	// connection window, which is larger than that.
	var fillers, fillerReaders []*noiseStream
	for id := uint64(582); int64(len(fillers))*flow.MaxGrowableWindow <= flow.CurrentBounds().ConnCredit(); id++ {
		f, fs := openWithCredit(t, ctx, client, server, id, flow.MaxGrowableWindow)
		fillers, fillerReaders = append(fillers, f), append(fillerReaders, fs)
	}
	bs, bss := openWithCredit(t, ctx, client, server, 581, 0)
	msg := burstMessage(5, 1024)
	for avail := client.connWindow.Available(); avail >= messageCredit(int64(len(msg))); avail = client.connWindow.Available() {
		filler := fillers[0]
		if filler.window.Available() < avail && filler.window.Available() < messageCredit(64*1024) {
			fillers = fillers[1:]
			filler = fillers[0]
		}
		n := avail
		if w := filler.window.Available(); w < n {
			n = w
		}
		n -= recvQueueEntryCost
		if n > 64*1024 {
			n = 64 * 1024
		}
		if err := filler.Send(ctx, make([]byte, n)); err != nil {
			t.Fatalf("filling the connection window: %v", err)
		}
	}
	// The Send charges its stream credit, rechecks the stream's state, then
	// waits on the connection window; Close is called once it waits there. The
	// stream charge (less the opening message's grant, which may land meanwhile)
	// shows it got that far, and the pause covers the recheck right after it.
	charged := bs.window.Outstanding() + messageCredit(int64(len(msg))) - messageCredit(int64(len("hello")))
	sent := make(chan error, 1)
	go func() { sent <- bs.Send(ctx, msg) }()
	waitFor(t, "the Send's stream credit charged", func() bool { return bs.window.Outstanding() >= charged })
	time.Sleep(100 * time.Millisecond)
	select {
	case err := <-sent:
		t.Fatalf("premise wrong: the Send ended (%v) before Close", err)
	default:
	}
	_ = bs.Close()
	if bs.closeSent.Load() {
		t.Fatal("the CLOSE was queued while a Send was in progress")
	}
	for _, fs := range fillerReaders {
		for {
			rctx, rcancel := context.WithTimeout(ctx, 200*time.Millisecond)
			_, err := fs.Receive(rctx)
			rcancel()
			if err != nil {
				break
			}
		}
	}
	if err := <-sent; err != nil {
		t.Skipf("the Send was refused before it waited on the connection window (%v); nothing to order", err)
	}
	if r := <-receiveAsync(ctx, bss, 10*time.Second); r.err != nil || !bytes.Equal(r.data, msg) {
		t.Fatalf("the server got %d of %d bytes: %v", len(r.data), len(msg), r.err)
	}
	if r := <-receiveAsync(ctx, bss, 10*time.Second); !errors.Is(r.err, io.EOF) {
		t.Fatalf("after the message Receive returned %d bytes, %v; want io.EOF", len(r.data), r.err)
	}
}
