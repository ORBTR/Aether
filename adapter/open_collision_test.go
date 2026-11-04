//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// TestNoiseSession_ALocalOpenOfALiveIDIsRefused: OpenStream of an ID a stream holds
// is the typed refusal and writes no second OPEN, and the stream in place goes on
// working. It holds for a stream the peer opened too.
func TestNoiseSession_ALocalOpenOfALiveIDIsRefused(t *testing.T) {
	client, server, toServer, _ := filteredPair(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cs, ss := openWithCredit(t, ctx, client, server, 820, 0)
	cfg := aether.StreamConfig{StreamID: 820, Reliability: aether.ReliableOrdered}
	opens := func() int {
		toServer.mu.Lock()
		defer toServer.mu.Unlock()
		return toServer.written[aether.TypeOPEN]
	}
	before := opens()
	if st, err := client.OpenStream(ctx, cfg); st != nil || !errors.Is(err, aether.ErrDuplicateStreamID) {
		t.Fatalf("OpenStream of the opener's live ID = %v, %v", st, err)
	}
	if st, err := server.OpenStream(ctx, cfg); st != nil || !errors.Is(err, aether.ErrDuplicateStreamID) {
		t.Fatalf("OpenStream of the accepted live ID = %v, %v", st, err)
	}
	if got := opens(); got != before {
		t.Fatalf("%d OPEN frames after the refusal, %d before", got, before)
	}
	if err := cs.Send(ctx, []byte("still here")); err != nil {
		t.Fatalf("send: %v", err)
	}
	if r := <-receiveAsync(ctx, ss, 30*time.Second); r.err != nil || string(r.data) != "still here" {
		t.Fatalf("receive: %q, %v", r.data, r.err)
	}
}

// bothClose closes the two ends of a stream and waits until the client's has left.
func bothClose(t *testing.T, client *NoiseSession, cs, ss *noiseStream) {
	t.Helper()
	if err := cs.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}
	if err := ss.Close(); err != nil {
		t.Fatalf("server close: %v", err)
	}
	waitLong(t, "the client's stream leaving", func() bool { return !streamPresent(client, cs.streamID) })
}

// TestNoiseSession_AnIDStaysQuietAfterItsStreamLeaves: a stream that left on both
// CLOSEs holds its ID against a local OpenStream for reopenQuietRTOs of its RTO, with
// the typed refusal, because the peer may still be writing its CLOSE again, and the
// ID opens once that time is over.
func TestNoiseSession_AnIDStaysQuietAfterItsStreamLeaves(t *testing.T) {
	client, server := noisePairWithRealms(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cs, ss := openWithCredit(t, ctx, client, server, 822, 0)
	rto := cs.rtt.RTO()
	bothClose(t, client, cs, ss)

	cfg := aether.StreamConfig{StreamID: 822, Reliability: aether.ReliableOrdered}
	if st, err := client.OpenStream(ctx, cfg); st != nil || !errors.Is(err, aether.ErrDuplicateStreamID) {
		t.Fatalf("OpenStream right after the leave = %v, %v; want ErrDuplicateStreamID", st, err)
	}
	time.Sleep(reopenQuietRTOs*rto + 50*time.Millisecond)
	st, err := client.OpenStream(ctx, cfg)
	if err != nil {
		t.Fatalf("OpenStream after the quiet time: %v", err)
	}
	if err := st.Send(ctx, []byte("next")); err != nil {
		t.Fatalf("send: %v", err)
	}
	acc, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if r := <-receiveAsync(ctx, acc, 30*time.Second); r.err != nil || string(r.data) != "next" {
		t.Fatalf("receive on the next stream: %q, %v", r.data, r.err)
	}
}

// TestNoiseSession_APeersOpenReplacesAStreamBothSidesClosed: the server's CLOSE was
// received and every ACK of it is lost, so its stream stays waiting. The client has
// left and opens the ID again: the server's stream goes, the OPEN admits the next one,
// and the new stream's messages reach its consumer, not the old stream's ended queue.
func TestNoiseSession_APeersOpenReplacesAStreamBothSidesClosed(t *testing.T) {
	client, server, toServer, _ := filteredPair(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	const id = 824
	cs, ss := openWithCredit(t, ctx, client, server, id, 0)
	waitSendWindowEmpty(t, cs, "the opening message acknowledged")
	var lostACKs atomic.Bool
	lostACKs.Store(true)
	rule := func(f *aether.Frame) bool {
		return lostACKs.Load() && f.Type == aether.TypeACK && f.StreamID == id
	}
	if err := cs.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}
	waitLong(t, "the client's CLOSE acknowledged", func() bool { return cs.closeDone.Load() })
	toServer.setRule(rule)
	if err := ss.Close(); err != nil {
		t.Fatalf("server close: %v", err)
	}
	waitLong(t, "the client's stream leaving", func() bool { return !streamPresent(client, id) })
	if ss.closeDone.Load() || !streamPresent(server, id) {
		t.Fatalf("the server's CLOSE ACK was lost, yet closeDone %v, present %v", ss.closeDone.Load(), streamPresent(server, id))
	}

	cfg := aether.StreamConfig{StreamID: id, Reliability: aether.ReliableOrdered}
	var next aether.Stream
	waitLong(t, "the ID's quiet time ending", func() bool {
		st, err := client.OpenStream(ctx, cfg)
		if err == nil {
			next = st
			return true
		}
		if !errors.Is(err, aether.ErrDuplicateStreamID) {
			t.Fatalf("OpenStream: %v", err)
		}
		return false
	})
	lostACKs.Store(false)
	if err := next.Send(ctx, []byte("next")); err != nil {
		t.Fatalf("send: %v", err)
	}
	acc, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if acc == aether.Stream(ss) {
		t.Fatal("the acceptor handed back the closed stream")
	}
	if r := <-receiveAsync(ctx, acc, 30*time.Second); r.err != nil || string(r.data) != "next" {
		t.Fatalf("receive on the next stream: %q, %v", r.data, r.err)
	}
	if r := <-receiveAsync(ctx, ss, 10*time.Second); !errors.Is(r.err, io.EOF) {
		t.Fatalf("the old stream: %d bytes, %v; want io.EOF", len(r.data), r.err)
	}
}
