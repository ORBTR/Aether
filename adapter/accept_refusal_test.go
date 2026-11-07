//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
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
