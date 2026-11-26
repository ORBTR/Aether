//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package adapter

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// Tests of what the session's stream acceptor does with a stream the peer opened that
// no consumer can take: the NoiseSession and the TCPSession refuse it with
// RESET(ResetRefused) and release what it held at once (refuseUnaccepted), and an ID
// the session's options claim (aether.SessionOptions.ClaimedStreams) reaches only its
// AcceptStreamByID however late that call comes.

// noisePairWithServerOptions runs two NoiseSessions over one loopback connection,
// the server built with serverOpts.
func noisePairWithServerOptions(t *testing.T, serverOpts aether.SessionOptions) (client, server *NoiseSession) {
	t.Helper()
	chosen := aetherChosen(t)
	c, s := loopbackPair(t)
	client = NewNoiseSession(realmConn{Conn: c, chosen: chosen}, "vl1_accept_client", "vl1_accept_server", aether.DefaultSessionOptions())
	server = NewNoiseSession(realmConn{Conn: s, chosen: chosen}, "vl1_accept_server", "vl1_accept_client", serverOpts)
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client, server
}

func acceptCfg(id uint64) aether.StreamConfig {
	return aether.StreamConfig{StreamID: id, Reliability: aether.ReliableOrdered, Priority: 128}
}

// openPastTheFIFO opens n streams from client, each with one message, while no Accept
// runs on server, waits past the backlog grace, then takes what server's AcceptStream
// has and reads each opened stream once. It returns the server's accepted streams and
// how many of the opener's streams ended with aether.ErrStreamRefused; a stream that
// neither reached Accept nor ended is counted in neither.
func openPastTheFIFO(t *testing.T, ctx context.Context, client, server aether.Session, base uint64, n int) (accepted []aether.Stream, refused int) {
	t.Helper()
	var opened []aether.Stream
	for i := 0; i < n; i++ {
		cs, err := client.OpenStream(ctx, acceptCfg(base+uint64(2*i)))
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		if err := cs.Send(ctx, []byte("x")); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
		opened = append(opened, cs)
	}
	time.Sleep(aether.ByIDBacklogGrace + 900*time.Millisecond)
	for {
		actx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		st, err := server.AcceptStream(actx)
		cancel()
		if err != nil {
			break
		}
		accepted = append(accepted, st)
	}
	ends := make([]<-chan receiveResult, len(opened))
	for i, cs := range opened {
		ends[i] = receiveAsync(ctx, cs, 2*time.Second)
	}
	for i, end := range ends {
		r := <-end
		switch {
		case errors.Is(r.err, aether.ErrStreamRefused):
			refused++
		case r.err != nil && !errors.Is(r.err, context.DeadlineExceeded):
			t.Errorf("opened stream %d: %v, want aether.ErrStreamRefused or no end", i, r.err)
		}
	}
	return accepted, refused
}

// TestNoiseSession_AnOpenPastAFullAcceptFIFOIsRefused: more streams opened than the
// acceptor's FIFO holds, while no Accept runs. Every stream the server admitted either
// reaches Accept or is refused, so its opener reads aether.ErrStreamRefused, and a
// refused stream gives back its slot, its credit reservation and its queued message at
// once, not at the stream GC's idle timeout or the ended-queue sweep.
func TestNoiseSession_AnOpenPastAFullAcceptFIFOIsRefused(t *testing.T) {
	const n = aether.AcceptChDefaultBuffer + 4
	client, server := noisePairWithRealms(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	heldBefore := server.admitted.held()
	accepted, refused := openPastTheFIFO(t, ctx, client, server, 2000, n)
	if len(accepted) != aether.AcceptChDefaultBuffer || refused != n-aether.AcceptChDefaultBuffer {
		t.Fatalf("%d opened, %d accepted, %d refused; want %d accepted and %d refused, none lost",
			n, len(accepted), refused, aether.AcceptChDefaultBuffer, n-aether.AcceptChDefaultBuffer)
	}
	var reserved int64
	for _, st := range accepted {
		reserved += asNoiseStream(t, st).reserved.Load()
	}
	server.mu.Lock()
	live := len(server.streams)
	server.mu.Unlock()
	if live != len(accepted) {
		t.Fatalf("the server holds %d streams, want the %d accepted", live, len(accepted))
	}
	if got := server.admitted.held() - heldBefore; got != reserved {
		t.Fatalf("the server's reservations hold %d, want the accepted streams' %d", got, reserved)
	}
	for _, st := range accepted {
		if got, err := st.Receive(ctx); err != nil || string(got) != "x" {
			t.Fatalf("accepted stream %d: %q, %v", st.StreamID(), got, err)
		}
	}
	if got := server.recvQueued.Load(); got != 0 {
		t.Fatalf("with every accepted message read the server's queues hold %d, want 0", got)
	}
}

// TestTCPSession_AnOpenPastAFullAcceptFIFOIsRefused is the same on a TCP-family
// session: the refused streams leave s.streams and their queued messages leave the
// session's ceiling at once.
func TestTCPSession_AnOpenPastAFullAcceptFIFOIsRefused(t *testing.T) {
	const n = aether.AcceptChDefaultBuffer + 4
	client, server := tcpPairWithOptions(t, aether.DefaultSessionOptions())
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	accepted, refused := openPastTheFIFO(t, ctx, client, server, 200, n)
	if len(accepted) != aether.AcceptChDefaultBuffer || refused != n-aether.AcceptChDefaultBuffer {
		t.Fatalf("%d opened, %d accepted, %d refused; want %d accepted and %d refused, none lost",
			n, len(accepted), refused, aether.AcceptChDefaultBuffer, n-aether.AcceptChDefaultBuffer)
	}
	server.mu.Lock()
	live := len(server.streams)
	server.mu.Unlock()
	if live != len(accepted) {
		t.Fatalf("the server holds %d streams, want the %d accepted", live, len(accepted))
	}
	for _, st := range accepted {
		if got, err := st.Receive(ctx); err != nil || string(got) != "x" {
			t.Fatalf("accepted stream %d: %q, %v", st.StreamID(), got, err)
		}
	}
	if got := server.recvQueued.Load(); got != 0 {
		t.Fatalf("with every accepted message read the server's queues hold %d, want 0", got)
	}
}

// claimantArrivesLate opens id from client while server runs an AcceptStream loop, arms
// server's AcceptStreamByID(id) well past the backlog grace, and fails unless the
// claimant, and not the loop, took the stream.
func claimantArrivesLate(t *testing.T, client, server aether.Session, id uint64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	loopTook := make(chan uint64, 4)
	loopCtx, stopLoop := context.WithCancel(ctx)
	defer stopLoop()
	go func() {
		for {
			st, err := server.AcceptStream(loopCtx)
			if err != nil {
				return
			}
			loopTook <- st.StreamID()
		}
	}()
	cs, err := client.OpenStream(ctx, acceptCfg(id))
	if err != nil {
		t.Fatalf("open %d: %v", id, err)
	}
	if err := cs.Send(ctx, []byte("claimed")); err != nil {
		t.Fatalf("send: %v", err)
	}
	time.Sleep(3 * aether.ByIDBacklogGrace)
	actx, acancel := context.WithTimeout(ctx, 5*time.Second)
	defer acancel()
	st, err := server.AcceptStreamByID(actx, id)
	if err != nil {
		select {
		case got := <-loopTook:
			t.Fatalf("the AcceptStream loop took claimed stream %d; the claimant got %v", got, err)
		default:
			t.Fatalf("AcceptStreamByID(%d): %v", id, err)
		}
	}
	if got, err := st.Receive(ctx); err != nil || string(got) != "claimed" {
		t.Fatalf("the claimant's stream read %q, %v", got, err)
	}
	stopLoop()
	select {
	case got := <-loopTook:
		t.Fatalf("the AcceptStream loop also took stream %d", got)
	default:
	}
}

// TestSessions_AClaimedStreamReachesItsLateClaimantNotTheAcceptLoop: the server's
// options claim stream 101; its AcceptStream loop runs while the stream arrives, and
// its AcceptStreamByID(101) arms three backlog graces later. The claimant gets the
// stream and the loop never sees it, on Noise and on TCP.
func TestSessions_AClaimedStreamReachesItsLateClaimantNotTheAcceptLoop(t *testing.T) {
	opts := aether.DefaultSessionOptions()
	opts.ClaimedStreams = []uint64{101}
	t.Run("noise", func(t *testing.T) {
		client, server := noisePairWithServerOptions(t, opts)
		claimantArrivesLate(t, client, server, 101)
	})
	t.Run("tcp", func(t *testing.T) {
		client, server := tcpPairWithOptions(t, opts)
		claimantArrivesLate(t, client, server, 101)
	})
}

// liteRawPeerWithOptions is newLiteRawPeer with the TCPSession's options chosen by
// the test.
func liteRawPeerWithOptions(t *testing.T, opts aether.SessionOptions) *liteRawPeer {
	t.Helper()
	sess, conn := rawPeer(t, opts)
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	offer, err := aether.ReadWireVersionsPreface(conn)
	if err != nil {
		t.Fatalf("read preface: %v", err)
	}
	if err := aether.WriteWireVersionsPreface(conn, frameOnlyOffer()); err != nil {
		t.Fatalf("write preface: %v", err)
	}
	chosen, err := aether.ChooseWireVersions(frameOnlyOffer(), offer)
	if err != nil {
		t.Fatalf("choose: %v", err)
	}
	return &liteRawPeer{t: t, sess: sess, conn: conn, decoder: wireDecoder(chosen)}
}

// TestTCPSession_AFullClaimedBacklogIsRefusedWithoutTheReadLoopWriting: the session's
// options claim an ID no consumer has armed, and the peer opens and resets it more
// times than its by-ID backlog holds (aether.MaxByIDBacklogPerStream), so the acceptor
// refuses the excess on the readLoop (refuseUnaccepted). The peer reads nothing while
// it writes, so a readLoop that wrote the refusal itself would stop at that write: the
// DATA the peer sends behind the refused opens must still reach its stream, and once
// the peer reads, a RESET(ResetRefused) for the claimed ID is on the wire.
func TestTCPSession_AFullClaimedBacklogIsRefusedWithoutTheReadLoopWriting(t *testing.T) {
	const claimed = 700
	opts := aether.DefaultSessionOptions()
	opts.ClaimedStreams = []uint64{claimed}
	p := liteRawPeerWithOptions(t, opts)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const id = 40
	writeFrames(t, p.conn, synFrame(id))
	st, err := p.sess.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	open := func(gen uint64) *aether.Frame {
		return &aether.Frame{StreamID: claimed, Type: aether.TypeDATA, Flags: aether.FlagSYN,
			Payload: aether.EncodeOpenPayload(aether.OpenPayload{Reliability: aether.ReliableOrdered, Generation: gen})}
	}
	reset := func(gen uint64) *aether.Frame {
		return &aether.Frame{StreamID: claimed, Type: aether.TypeRESET, Payload: aether.EncodeResetPayload(aether.ResetPayload{
			Reason: aether.ResetCancel, Incarnation: aether.StreamIncarnation{Generation: gen, WriterOpened: true}})}
	}
	var frames []*aether.Frame
	for g := uint64(1); g <= aether.MaxByIDBacklogPerStream+2; g++ {
		frames = append(frames, open(1000+g), reset(1000+g))
	}
	frames = append(frames, &aether.Frame{StreamID: id, Type: aether.TypeDATA, Payload: []byte("after")})
	writeFrames(t, p.conn, frames...)
	if r := <-receiveAsync(ctx, st, 5*time.Second); r.err != nil || string(r.data) != "after" {
		t.Fatalf("the DATA behind a full claimed backlog's refusal: %q, %v; the readLoop waited on a write", r.data, r.err)
	}
	refused := false
	for i := 0; i < 4*len(frames) && !refused; i++ {
		_ = p.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		f, _, _, err := aether.ReadNextFrame(p.conn, p.decoder)
		if err != nil {
			break
		}
		if f.StreamID == claimed && f.Type == aether.TypeRESET && !f.Flags.Has(aether.FlagACK) {
			if rp := aether.DecodeResetPayload(f.Payload); rp.Reason == aether.ResetRefused {
				refused = true
			}
		}
	}
	if !refused {
		t.Fatal("no RESET(ResetRefused) for the claimed ID on the wire: the backlog never filled, so the refusal was never reached")
	}
}
