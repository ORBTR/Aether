//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// tcpPairWithOptions builds a client and server TCPSession over net.Pipe, the
// server with serverOpts, and closes both when the test ends.
func tcpPairWithOptions(t *testing.T, serverOpts aether.SessionOptions) (*TCPSession, *TCPSession) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	client := NewTCPSession(clientConn, "vl1_overrun_client", "vl1_overrun_server", aether.ProtoTCP, aether.DefaultSessionOptions())
	server := NewTCPSession(serverConn, "vl1_overrun_server", "vl1_overrun_client", aether.ProtoTCP, serverOpts)
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
		_ = clientConn.Close()
		_ = serverConn.Close()
	})
	return client, server
}

// indexedMessage is message i of a burst: its index in the first four bytes,
// so the reader can tell a gap from an end.
func indexedMessage(i int) []byte {
	b := make([]byte, 64)
	binary.BigEndian.PutUint32(b, uint32(i))
	return b
}

// TestTCPStream_ABurstPastTheQueueEndsInTheTypedResetAfterEveryQueuedMessage
// sends more messages than a dynamic stream's delivery queue holds to a
// consumer that has read none of them. The receiver's readLoop never waits
// on that consumer: it resets the stream with RESET(ResetFlowCtrl) when the
// queue is full and goes on answering PING. The sender's Send and Receive
// then return aether.ErrStreamOverrun, and the receiver's consumer reads
// every queued message, in order and without a gap, and then the same
// typed end, never io.EOF. No CONGESTION frame reaches the sender.
func TestTCPStream_ABurstPastTheQueueEndsInTheTypedResetAfterEveryQueuedMessage(t *testing.T) {
	client, server := tcpPairWithOptions(t, aether.DefaultSessionOptions())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	const streamID = 30
	queue := tcpDeliveryQueueCapacity(streamID)
	burst := queue + 20

	cs, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: streamID, Reliability: aether.ReliableOrdered, Priority: 128})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ss, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	hitsBefore := client.Throttle().TotalHits()

	for i := 0; i < burst; i++ {
		if err := cs.Send(ctx, indexedMessage(i)); err != nil {
			if errors.Is(err, aether.ErrStreamOverrun) {
				break
			}
			t.Fatalf("send %d: %v", i, err)
		}
	}

	// The sender learns of the overrun as that reason: its Receive returns
	// aether.ErrStreamOverrun once the receiver's RESET arrives.
	rctx, rcancel := context.WithTimeout(ctx, 10*time.Second)
	_, err = cs.Receive(rctx)
	rcancel()
	if !errors.Is(err, aether.ErrStreamOverrun) {
		t.Fatalf("sender Receive after the burst: %v, want aether.ErrStreamOverrun", err)
	}
	if err := cs.Send(ctx, indexedMessage(burst)); !errors.Is(err, aether.ErrStreamOverrun) {
		t.Errorf("sender Send after the reset: %v, want aether.ErrStreamOverrun", err)
	}

	// The receiver's readLoop goes on answering PING while the consumer
	// still has not read: each Ping's PONG adds an RTT sample.
	for i := 0; i < 3; i++ {
		before := client.Health().SampleCount()
		pctx, pcancel := context.WithTimeout(ctx, 5*time.Second)
		_, perr := client.Ping(pctx)
		pcancel()
		if perr != nil {
			t.Fatalf("ping %d while the consumer is stalled: %v", i, perr)
		}
		deadline := time.Now().Add(5 * time.Second)
		for client.Health().SampleCount() == before {
			if time.Now().After(deadline) {
				t.Fatalf("ping %d: no PONG from the receiver's readLoop within 5 s", i)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	if got := len(ss.(*tcpStream).recvCh); got != queue {
		t.Fatalf("premise: the receiver's queue holds %d unread messages, want the full %d", got, queue)
	}

	// Now the consumer reads: every queued message, in order, then the
	// typed end.
	for want := 0; ; want++ {
		rctx, rcancel := context.WithTimeout(ctx, 5*time.Second)
		data, err := ss.Receive(rctx)
		rcancel()
		if err != nil {
			if !errors.Is(err, aether.ErrStreamOverrun) {
				t.Fatalf("receiver Receive after %d messages: %v, want aether.ErrStreamOverrun", want, err)
			}
			if want != queue {
				t.Fatalf("receiver read %d messages before the typed end, want the %d the queue held", want, queue)
			}
			break
		}
		if got := int(binary.BigEndian.Uint32(data)); got != want {
			t.Fatalf("receiver message %d carries index %d: a gap or reorder", want, got)
		}
	}
	if err := ss.Send(ctx, []byte("x")); !errors.Is(err, aether.ErrStreamOverrun) {
		t.Errorf("receiver Send after its own overrun: %v, want aether.ErrStreamOverrun", err)
	}

	if got := server.DeliveryStats().Dropped.Load(); got != 1 {
		t.Errorf("receiver Dropped = %d, want 1 (only the message the full queue refused)", got)
	}
	if got := server.DeliveryStats().Delivered.Load(); got != int64(queue) {
		t.Errorf("receiver Delivered = %d, want %d", got, queue)
	}
	if hits := client.Throttle().TotalHits() - hitsBefore; hits != 0 {
		t.Errorf("the sender applied %d CONGESTION frames; the overrun sends none", hits)
	}
	server.mu.Lock()
	_, still := server.streams[streamID]
	server.mu.Unlock()
	if still {
		t.Errorf("the overrun stream is still in the receiver's session")
	}
}

// TestTCPStream_AReplyAfterALocalCloseIsReceived: Close ends only this side's
// sending, so the peer's reply to a request followed by Close (the
// request-then-half-close pattern) still reaches Receive, and is not refused
// as a message after the receive side's end.
func TestTCPStream_AReplyAfterALocalCloseIsReceived(t *testing.T) {
	for round := 0; round < 10; round++ {
		client, server := tcpPairWithOptions(t, aether.DefaultSessionOptions())
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cs, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: 40, Reliability: aether.ReliableOrdered, Priority: 128})
		if err != nil {
			cancel()
			t.Fatalf("round %d open: %v", round, err)
		}
		if err := cs.Send(ctx, []byte("request")); err != nil {
			cancel()
			t.Fatalf("round %d send: %v", round, err)
		}
		ss, err := server.AcceptStream(ctx)
		if err != nil {
			cancel()
			t.Fatalf("round %d accept: %v", round, err)
		}
		if _, err := ss.Receive(ctx); err != nil {
			cancel()
			t.Fatalf("round %d server receive: %v", round, err)
		}
		if err := cs.Close(); err != nil {
			cancel()
			t.Fatalf("round %d close: %v", round, err)
		}
		if err := ss.Send(ctx, []byte("reply")); err != nil {
			cancel()
			t.Fatalf("round %d reply send: %v", round, err)
		}
		rctx, rcancel := context.WithTimeout(ctx, 5*time.Second)
		data, err := cs.Receive(rctx)
		rcancel()
		cancel()
		if err != nil {
			t.Fatalf("round %d: the reply after the client's Close was not received: %v", round, err)
		}
		if string(data) != "reply" {
			t.Fatalf("round %d: received %q, want %q", round, data, "reply")
		}
	}
}

// TestTCPStream_APeerRefusalReadsAsARefusal: a stream the peer refuses at its
// stream cap (registerStream's RESET(ResetRefused)) returns
// aether.ErrStreamRefused from Receive and Send, not io.EOF.
func TestTCPStream_APeerRefusalReadsAsARefusal(t *testing.T) {
	opts := aether.DefaultSessionOptions()
	opts.MaxConcurrentStreams = 1
	client, server := tcpPairWithOptions(t, opts)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: 100, Reliability: aether.ReliableOrdered, Priority: 128}); err != nil {
		t.Fatalf("open the first stream: %v", err)
	}
	if _, err := server.AcceptStream(ctx); err != nil {
		t.Fatalf("accept the first stream: %v", err)
	}
	refused, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: 101, Reliability: aether.ReliableOrdered, Priority: 128})
	if err != nil {
		t.Fatalf("open the second stream: %v", err)
	}
	rctx, rcancel := context.WithTimeout(ctx, 5*time.Second)
	_, err = refused.Receive(rctx)
	rcancel()
	if !errors.Is(err, aether.ErrStreamRefused) {
		t.Fatalf("Receive on the refused stream: %v, want aether.ErrStreamRefused", err)
	}
	if errors.Is(err, io.EOF) {
		t.Fatalf("Receive on the refused stream reads as an ordinary end")
	}
	if err := refused.Send(ctx, []byte("x")); !errors.Is(err, aether.ErrStreamRefused) {
		t.Errorf("Send on the refused stream: %v, want aether.ErrStreamRefused", err)
	}
}
