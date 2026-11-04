//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/flow"
)

// closesOf is a filter rule on one stream's CLOSE frames.
func closesOf(id uint64, n *atomic.Int64, firstCopies int64) func(*aether.Frame) bool {
	return func(f *aether.Frame) bool {
		return f.Type == aether.TypeCLOSE && f.StreamID == id && n.Add(1) <= firstCopies
	}
}

// TestNoiseStream_ALostCloseIsWrittenAgainAndEndsThePeersReceive: the first copy of
// a CLOSE is lost on the path. The sender writes it again on a timer with a sequence
// number one past its DATA, and the peer's Receive reaches io.EOF without waiting for
// its stream GC. The sender keeps the stream until the ACK.
func TestNoiseStream_ALostCloseIsWrittenAgainAndEndsThePeersReceive(t *testing.T) {
	client, server, toServer, _ := filteredPair(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cs, ss := openWithCredit(t, ctx, client, server, 800, 0)
	waitSendWindowEmpty(t, cs, "the opening message acknowledged")

	var copies atomic.Int64
	toServer.setRule(closesOf(800, &copies, 1))
	if err := cs.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	waitLong(t, "the first CLOSE lost", func() bool { return copies.Load() >= 1 })
	if cs.closeDone.Load() {
		t.Fatal("closeDone is set with the only CLOSE lost")
	}
	r := <-receiveAsync(ctx, ss, time.Minute)
	if !errors.Is(r.err, io.EOF) {
		t.Fatalf("the peer's Receive returned %d bytes, %v; want io.EOF", len(r.data), r.err)
	}
	if copies.Load() < 2 {
		t.Fatalf("%d copies of the CLOSE were written", copies.Load())
	}
	waitLong(t, "the CLOSE acknowledged", func() bool { return cs.closeDone.Load() })
	if streamPresent(client, 800) != true {
		t.Fatal("the closer left before the peer's CLOSE came")
	}
	if err := ss.Close(); err != nil {
		t.Fatalf("peer close: %v", err)
	}
	waitLong(t, "the stream out of both sessions", func() bool {
		return !streamPresent(client, 800) && !streamPresent(server, 800)
	})
}

// TestNoiseStream_AStreamLeavesOnlyOnItsClosesACK: every ACK of the client's CLOSE
// is lost while the server's CLOSE reaches the client. The client has both CLOSEs
// and still holds the stream, because a peer that never got its CLOSE would hold its
// receive side open and, once its GC resets it, stop granting for what it holds. The
// ACK arriving takes the stream out.
func TestNoiseStream_AStreamLeavesOnlyOnItsClosesACK(t *testing.T) {
	client, server, _, toClient := filteredPair(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cs, ss := openWithCredit(t, ctx, client, server, 802, 0)
	waitSendWindowEmpty(t, cs, "the opening message acknowledged")

	var blocked atomic.Bool
	blocked.Store(true)
	toClient.setRule(func(f *aether.Frame) bool {
		return blocked.Load() && f.Type == aether.TypeACK && f.StreamID == 802
	})
	if err := cs.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	waitFor(t, "the client's CLOSE at the server", func() bool { return ss.peerClosed.Load() })
	if err := ss.Close(); err != nil {
		t.Fatalf("server close: %v", err)
	}
	waitFor(t, "the server's CLOSE at the client", func() bool { return cs.peerClosed.Load() })
	time.Sleep(100 * time.Millisecond)
	if cs.closeDone.Load() || !streamPresent(client, 802) {
		t.Fatalf("the client left with its CLOSE unacknowledged (done %v)", cs.closeDone.Load())
	}
	blocked.Store(false)
	waitLong(t, "the stream out of the client", func() bool { return !streamPresent(client, 802) })
}

// TestNoiseStream_ARetransmittedCloseToAStreamThatLeftIsAnswered: the ACK of the
// client's CLOSE is lost until the server has left on both CLOSEs. The retransmit
// then finds no stream there, and the answer it gets ends the client's stream.
func TestNoiseStream_ARetransmittedCloseToAStreamThatLeftIsAnswered(t *testing.T) {
	client, server, _, toClient := filteredPair(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cs, ss := openWithCredit(t, ctx, client, server, 804, 0)
	waitSendWindowEmpty(t, cs, "the opening message acknowledged")

	var left atomic.Bool
	toClient.setRule(func(f *aether.Frame) bool {
		return !left.Load() && f.Type == aether.TypeACK && f.StreamID == 804 && f.AckNo == 1
	})
	if err := cs.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	waitFor(t, "the client's CLOSE at the server", func() bool { return ss.peerClosed.Load() })
	if err := ss.Close(); err != nil {
		t.Fatalf("server close: %v", err)
	}
	waitLong(t, "the server out on both CLOSEs", func() bool { return !streamPresent(server, 804) })
	left.Store(true)
	waitLong(t, "the client out on the answer to its retransmit", func() bool { return !streamPresent(client, 804) })
}

// TestNoiseStream_CloseWaitsForEveryDataACK: a CLOSE for a stream the peer does not
// hold is answered with a cumulative ACK, so the CLOSE is held until the stream's
// DATA is acknowledged. With the OPEN lost, the peer never takes the DATA: no CLOSE
// goes out, and the unacknowledged frame stays in the send window for its retransmit
// and does not read as delivered.
func TestNoiseStream_CloseWaitsForEveryDataACK(t *testing.T) {
	client, _, toServer, _ := filteredPair(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	toServer.setRule(func(f *aether.Frame) bool { return f.Type == aether.TypeOPEN && f.StreamID == 806 })
	st, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: 806, Reliability: aether.ReliableOrdered, Priority: 128})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := st.Send(ctx, []byte("into a stream the peer does not hold")); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if written, _ := toServer.count(aether.TypeCLOSE); written != 0 {
		t.Fatalf("%d CLOSE frames went out over unacknowledged DATA", written)
	}
	if got := asNoiseStream(t, st).sendWindow.InFlight(); got != 1 {
		t.Fatalf("send window holds %d frames", got)
	}
}

// TestNoiseStream_AnOvertakingCloseWaitsItsTurn: a CLOSE takes the next sequence
// number, so one that arrives ahead of a frame before it ends nothing until that
// frame has been delivered; then the reader sees the frame, then io.EOF. A second
// copy of the CLOSE changes nothing.
func TestNoiseStream_AnOvertakingCloseWaitsItsTurn(t *testing.T) {
	client, server := noisePairWithRealms(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cs, ss := openWithCredit(t, ctx, client, server, 808, 0)
	waitSendWindowEmpty(t, cs, "the opening message acknowledged")

	closeFrame := &aether.Frame{Type: aether.TypeCLOSE, StreamID: 808, SeqNo: 2}
	server.handleClose(closeFrame)
	if ss.peerClosed.Load() {
		t.Fatal("a CLOSE ahead of its frame ended the receive side")
	}
	injectData(server, 808, 1, 1, 100)
	if !ss.peerClosed.Load() {
		t.Fatal("the frame before the CLOSE did not release it")
	}
	server.handleClose(closeFrame)
	r := <-receiveAsync(ctx, ss, 10*time.Second)
	if r.err != nil || len(r.data) != 100 {
		t.Fatalf("after the CLOSE: %d bytes, %v", len(r.data), r.err)
	}
	if r := <-receiveAsync(ctx, ss, 10*time.Second); !errors.Is(r.err, io.EOF) {
		t.Fatalf("after the frame: %d bytes, %v; want io.EOF", len(r.data), r.err)
	}
}

// TestNoiseStream_ALostCloseStrandsNoCredit: the client's message sits unread at the
// server, and the client's CLOSE is lost while the server's arrives. The client does
// not leave on the server's CLOSE: its retransmit ends the server's receive side, and
// the late read grants the credit back to the client after both have left.
func TestNoiseStream_ALostCloseStrandsNoCredit(t *testing.T) {
	client, server, toServer, _ := filteredPair(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cs, ss := openWithCredit(t, ctx, client, server, 810, 0)
	full := flow.CurrentBounds().ConnCredit()
	msg := make([]byte, 4096)
	if err := cs.Send(ctx, msg); err != nil {
		t.Fatalf("send: %v", err)
	}
	waitSendWindowEmpty(t, cs, "the message acknowledged")
	waitBooksAgree(t, "the opening message's grant", client, server)

	var copies atomic.Int64
	toServer.setRule(closesOf(810, &copies, 1))
	if err := cs.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	waitFor(t, "the client's first CLOSE lost", func() bool { return copies.Load() >= 1 })
	if err := ss.Close(); err != nil {
		t.Fatalf("server close: %v", err)
	}
	waitFor(t, "the server's CLOSE at the client", func() bool { return cs.peerClosed.Load() })
	if ss.peerClosed.Load() && !cs.closeDone.Load() && copies.Load() < 2 {
		t.Fatal("the server read a CLOSE the path lost")
	}
	waitLong(t, "the stream out of both sessions", func() bool {
		return !streamPresent(client, 810) && !streamPresent(server, 810)
	})
	if got := client.connWindow.Available(); got != full-messageCredit(int64(len(msg))) {
		t.Fatalf("client's connection credit %d before the read, full %d", got, full)
	}
	if r := <-receiveAsync(ctx, ss, 10*time.Second); r.err != nil || len(r.data) != len(msg) {
		t.Fatalf("late read: %d bytes, %v", len(r.data), r.err)
	}
	waitLong(t, "the read's grant at the client", func() bool { return client.connWindow.Available() == full })
}

// TestNoiseStream_RepliesAndClosesOverALossyPath: every frame in both directions
// has a chance of loss, ACKs, CLOSEs and retransmits among them. Every RPC's reply
// reaches the caller whole, then io.EOF, and the stream leaves both sessions.
func TestNoiseStream_RepliesAndClosesOverALossyPath(t *testing.T) {
	client, server, toServer, toClient := filteredPair(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	var mu sync.Mutex
	rng := rand.New(rand.NewSource(0x5eed))
	lossy := func(f *aether.Frame) bool {
		if f.StreamID < 820 || f.StreamID >= 850 {
			return false
		}
		switch f.Type {
		case aether.TypeDATA, aether.TypeACK, aether.TypeCLOSE:
			mu.Lock()
			defer mu.Unlock()
			return rng.Intn(100) < 15
		}
		return false
	}
	toServer.setRule(lossy)
	toClient.setRule(lossy)
	for k := 0; k < 15; k++ {
		id := uint64(820 + k)
		cs, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: id, Reliability: aether.ReliableOrdered, Priority: 128})
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if err := cs.Send(ctx, []byte("request")); err != nil {
			t.Fatalf("request: %v", err)
		}
		_ = cs.Close()
		ss, err := server.AcceptStream(ctx)
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
		if r := <-receiveAsync(ctx, ss, time.Minute); r.err != nil {
			t.Fatalf("rpc %d: request: %v", k, r.err)
		}
		reply := burstMessage(k, 900)
		if err := ss.Send(ctx, reply); err != nil {
			t.Fatalf("rpc %d: reply: %v", k, err)
		}
		_ = ss.Close()
		r := <-receiveAsync(ctx, cs, time.Minute)
		if r.err != nil || !bytes.Equal(r.data, reply) {
			t.Fatalf("rpc %d: the caller got %d bytes: %v", k, len(r.data), r.err)
		}
		if r := <-receiveAsync(ctx, cs, time.Minute); !errors.Is(r.err, io.EOF) {
			t.Fatalf("rpc %d: after the reply: %d bytes, %v", k, len(r.data), r.err)
		}
		waitLong(t, fmt.Sprintf("rpc %d's stream out of both sessions", k), func() bool {
			return !streamPresent(client, id) && !streamPresent(server, id)
		})
	}
}
