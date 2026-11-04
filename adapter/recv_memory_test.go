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
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/flow"
)

// TestNoiseSession_APeersSessionsStayAtThePeerCeiling: three sessions to one peer,
// each inside the credit of its own connection window, queue no more together than the
// profile's per-peer ceiling. The stream that meets it ends with the typed reset at
// both ends, its reader gets what it holds, nobody is charged for abuse, and reading
// makes room for the next message.
func TestNoiseSession_APeersSessionsStayAtThePeerCeiling(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	const size = 64 * 1024
	bounds := flow.CurrentBounds()
	type accepted struct {
		cs, ss *noiseStream
	}
	var (
		servers []*NoiseSession
		first   []accepted
		overrun *noiseStream
	)
	total := func() int64 {
		var n int64
		for _, s := range servers {
			n += s.recvQueued.Load()
		}
		return n
	}
	for p := 0; p < 3; p++ {
		client, server := noisePairWithRealms(t, nil, nil)
		servers = append(servers, server)
		// Each stream takes less than its credit, and twenty of them less than the
		// session's connection credit, so only the peer's ceiling can refuse.
		for k := 0; k < 20; k++ {
			id := uint64(1000 + k)
			cs, ss := openWithCredit(t, ctx, client, server, id, 0)
			waitSendWindowEmpty(t, cs, "the opening message acknowledged")
			if p == 0 {
				first = append(first, accepted{cs, ss})
			}
			for i := 0; i < 12 && !ss.overrun.Load(); i++ {
				server.handleData(&aether.Frame{
					Type: aether.TypeDATA, StreamID: id, SeqNo: uint32(1 + i),
					Flags: aether.FlagANTIREPLAY, Length: size, Payload: make([]byte, size),
				})
			}
			if ss.overrun.Load() && overrun == nil {
				overrun = ss
			}
			if got := total(); got > bounds.PeerMemoryCeiling {
				t.Fatalf("one peer's sessions queue %d, ceiling %d", got, bounds.PeerMemoryCeiling)
			}
		}
		if got := server.PeerAbuseScore(); got != 0 {
			t.Fatalf("session %d charged the peer %v for its per-peer ceiling", p, got)
		}
	}
	if overrun == nil {
		t.Fatalf("no stream met the peer ceiling at %d queued", total())
	}
	for read := 0; ; read++ {
		_, err := overrun.Receive(ctx)
		if err != nil {
			if !errors.Is(err, aether.ErrStreamOverrun) {
				t.Fatalf("the refused stream's reader after %d messages: %v", read, err)
			}
			break
		}
	}

	// Reading the first session's stream gives the peer its room back.
	before := total()
	r := first[0]
	for i := 0; i < 12; i++ {
		if got, err := r.ss.Receive(ctx); err != nil || len(got) != size {
			t.Fatalf("read %d: %d bytes, %v", i, len(got), err)
		}
	}
	if got := total(); got >= before {
		t.Fatalf("after reading a stream %d stays queued, %d before", got, before)
	}
	if !servers[2].peerShare.fits(size) {
		t.Fatal("the last session has no room after the first's reader made some")
	}
}

// TestNoiseSession_AClosedSessionGivesThePeerItsShareBack: what a closed session's
// queues hold goes out of the peer's count at the close, and a later read of them does
// not count against the sessions still running.
func TestNoiseSession_AClosedSessionGivesThePeerItsShareBack(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	client, server := noisePairWithRealms(t, nil, nil)
	cs, ss := openWithCredit(t, ctx, client, server, 1040, 0)
	waitSendWindowEmpty(t, cs, "the opening message acknowledged")
	injectData(server, 1040, 1, 3, 1024)
	peer := server.peerShare.parent
	if got := peer.held(); got != 3*messageCredit(1024) {
		t.Fatalf("the peer holds %d, want %d", got, 3*messageCredit(1024))
	}
	second, secondServer := noisePairWithRealms(t, nil, nil)
	_ = second
	if secondServer.peerShare.parent != peer {
		t.Fatal("two sessions to one peer hold different ledgers")
	}
	_ = server.Close()
	if got := peer.held(); got != 0 {
		t.Fatalf("after the close the peer holds %d", got)
	}
	if _, err := ss.Receive(ctx); err != nil {
		t.Fatalf("a queued message after the close: %v", err)
	}
	if got := peer.held(); got != 0 {
		t.Fatalf("after the late read the peer holds %d", got)
	}
}

// liteFill is the frames that open stream id and queue count messages of size bytes.
func liteFill(id uint64, count, size int) []*aether.Frame {
	frames := []*aether.Frame{synFrame(id)}
	for i := 0; i < count; i++ {
		frames = append(frames, &aether.Frame{StreamID: id, Type: aether.TypeDATA, Payload: make([]byte, size)})
	}
	return frames
}

// drainAtEnd reads the peer's conn when the test ends, ahead of the session's close,
// whose RESET of each stream still in the acceptor's backlog writes to that net.Pipe.
func drainAtEnd(t *testing.T, p *liteRawPeer) {
	t.Helper()
	t.Cleanup(func() { go func() { _, _ = io.Copy(io.Discard, p.conn) }() })
}

// acceptEach takes n streams off the session's acceptor, in whichever of its queues
// each one has reached by now, keyed by stream ID.
func acceptEach(t *testing.T, ctx context.Context, sess *TCPSession, n int) map[uint64]aether.Stream {
	t.Helper()
	got := make(map[uint64]aether.Stream, n)
	for i := 0; i < n; i++ {
		st, err := sess.AcceptStream(ctx)
		if err != nil {
			t.Fatalf("accept %d of %d: %v", i, n, err)
		}
		got[st.StreamID()] = st
	}
	return got
}

// liteSettled waits until the readLoop has served everything written before this
// call, by the PONG it answers in order.
func liteSettled(p *liteRawPeer, frames ...*aether.Frame) {
	p.t.Helper()
	writeFrames(p.t, p.conn, append(frames, &aether.Frame{StreamID: 2, Type: aether.TypePING})...)
	for {
		if f := p.next(); f.Type == aether.TypePONG {
			return
		}
	}
}

// TestTCPSession_DeliveryQueuesStayAtTheSessionCeiling: streams that each stay inside
// the stream credit reach the profile's session ceiling together: the stream that meets
// it ends with a typed reset its reader and its sender both read, and the session's
// queues never pass the ceiling. Reading a queue makes room for a later stream.
func TestTCPSession_DeliveryQueuesStayAtTheSessionCeiling(t *testing.T) {
	p := newLiteRawPeer(t)
	drainAtEnd(t, p)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	const size, perStream = 64 * 1024, 15
	ceiling := flow.CurrentBounds().SessionMemoryCeiling
	var frames []*aether.Frame
	const streams = 18
	for k := 0; k < streams; k++ {
		frames = append(frames, liteFill(uint64(200+k), perStream, size)...)
	}
	var resets []*aether.Frame
	writeFrames(t, p.conn, append(frames, &aether.Frame{StreamID: 2, Type: aether.TypePING})...)
	for {
		f := p.next()
		if f.Type == aether.TypePONG {
			break
		}
		if f.Type == aether.TypeRESET {
			resets = append(resets, f)
		}
	}
	if got := p.sess.recvQueued.Load(); got > ceiling {
		t.Fatalf("the session queues %d, ceiling %d", got, ceiling)
	}
	if len(resets) != 1 || resets[0].StreamID != 200+streams-1 || aether.DecodeReset(resets[0].Payload) != aether.ResetFlowCtrl {
		t.Fatalf("resets %+v, want RESET(ResetFlowCtrl) on the last stream", resets)
	}
	accepted := acceptEach(t, ctx, p.sess, streams)
	first, over := accepted[200], accepted[200+streams-1]
	for {
		if _, err := over.Receive(ctx); err != nil {
			if !errors.Is(err, aether.ErrStreamOverrun) {
				t.Fatalf("the refused stream's reader: %v", err)
			}
			break
		}
	}
	for i := 0; i < perStream; i++ {
		if _, err := first.Receive(ctx); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
	}
	resets = nil
	writeFrames(t, p.conn, append(liteFill(300, perStream, size), &aether.Frame{StreamID: 2, Type: aether.TypePING})...)
	for {
		f := p.next()
		if f.Type == aether.TypePONG {
			break
		}
		if f.Type == aether.TypeRESET {
			resets = append(resets, f)
		}
	}
	if len(resets) != 0 {
		t.Fatalf("after a reader made room, resets %+v", resets)
	}
}

// TestTCPSession_ResetQueuesMakeRoomAndTheSweepDiscardsAbandonedOnes: queues a RESET
// ended do not stop a later stream: the longest-idle goes when a message needs its room,
// and its reader comes back to aether.ErrStreamOverrun. A queue ended by the peer's
// CLOSE stays for its late reader until the idle sweep, which then discards it and takes
// its cost off the session.
func TestTCPSession_ResetQueuesMakeRoomAndTheSweepDiscardsAbandonedOnes(t *testing.T) {
	p := newLiteRawPeer(t)
	drainAtEnd(t, p)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	const size, perStream = 64 * 1024, 15
	ceiling := flow.CurrentBounds().SessionMemoryCeiling
	reset := aether.EncodeReset(aether.ResetCancel)
	var frames []*aether.Frame
	for k := 0; k < 17; k++ {
		id := uint64(400 + k)
		frames = append(frames, liteFill(id, perStream, size)...)
		frames = append(frames, &aether.Frame{StreamID: id, Type: aether.TypeRESET, Payload: reset})
	}
	liteSettled(p, frames...)
	if p.sess.recvCharged.Load() != 0 {
		t.Fatalf("%d charged behind queues a RESET ended", p.sess.recvCharged.Load())
	}
	if got := p.sess.recvQueued.Load(); got > ceiling {
		t.Fatalf("queued %d, ceiling %d", got, ceiling)
	}
	abandoned := acceptEach(t, ctx, p.sess, 17)
	var seen []*aether.Frame
	writeFrames(t, p.conn, append(liteFill(500, perStream, size), &aether.Frame{StreamID: 2, Type: aether.TypePING})...)
	for {
		f := p.next()
		if f.Type == aether.TypePONG {
			break
		}
		seen = append(seen, f)
	}
	if len(seen) != 0 {
		t.Fatalf("frames %+v: the next stream was refused beside queues a RESET ended", seen)
	}
	if got := p.sess.recvQueued.Load(); got > ceiling {
		t.Fatalf("queued %d, ceiling %d", got, ceiling)
	}
	if _, err := abandoned[400].Receive(ctx); !errors.Is(err, aether.ErrStreamOverrun) {
		t.Fatalf("a reader of the discarded queue: %v, want ErrStreamOverrun", err)
	}

	writeFrames(t, p.conn, &aether.Frame{StreamID: 500, Type: aether.TypeCLOSE})
	liteSettled(p)
	live := acceptEach(t, ctx, p.sess, 1)[500]
	go func() { _, _ = io.Copy(io.Discard, p.conn) }()
	if err := live.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	waitLong(t, "the stream leaving on both CLOSEs", func() bool { return !inSession(p.sess, 500) })
	before := p.sess.recvQueued.Load()
	if before == 0 {
		t.Fatal("nothing queued for the late reader")
	}
	p.sess.sweepEnded(time.Now(), nil)
	if got := p.sess.recvQueued.Load(); got != before {
		t.Fatalf("a sweep inside the idle time took the queue: %d, %d before", got, before)
	}
	if _, err := live.Receive(ctx); err != nil {
		t.Fatalf("the late reader: %v", err)
	}
	p.sess.sweepEnded(time.Now().Add(2*aether.DefaultStreamIdleTimeout), nil)
	if got := p.sess.recvQueued.Load(); got != 0 {
		t.Fatalf("after the idle sweep %d stays queued", got)
	}
	if _, err := live.Receive(ctx); !errors.Is(err, aether.ErrStreamOverrun) {
		t.Fatalf("after the sweep's discard: %v, want ErrStreamOverrun", err)
	}
}
