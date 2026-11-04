//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/flow"
)

// queueCost reads what a queue holds charged to its session's budget.
func queueCost(q *recvQueue) int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.cost
}

// streamPresent reports whether s.streams holds id.
func streamPresent(s *NoiseSession, id uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.streams[id]
	return ok
}

// TestNoiseStream_APeerClosingFilledStreamsStaysInsideTheSessionCeiling: the
// local side half-closes each stream first, as the reply side of an RPC does, and
// does not read yet; a peer that ignores credit fills each stream to three
// quarters of its ceiling and CLOSEs it, over eight streams, each opened with
// the most credit one stream can hold, the stream ceiling the OPEN gives the
// server. The messages stay charged to the session's budget after the
// peer's CLOSE, so the ceiling refuses the stream that would pass it: what the
// queues hold never exceeds the session ceiling, the budget equals what the
// queues hold, and a late reader still drains a closed stream to io.EOF, which
// takes its cost off the budget.
func TestNoiseStream_APeerClosingFilledStreamsStaysInsideTheSessionCeiling(t *testing.T) {
	client, server := noisePairWithRealms(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	const size = 64 * 1024
	var held []*noiseStream
	var streamLimit, sessionLimit int64
	for k := 0; k < 8; k++ {
		id := uint64(300 + k)
		cs, ss := openWithCredit(t, ctx, client, server, id, flow.MaxGrowableWindow)
		waitSendWindowEmpty(t, cs, "the opening message")
		streamLimit, sessionLimit = ss.receiveCeilings()
		if err := ss.Close(); err != nil {
			t.Fatalf("local close %d: %v", id, err)
		}
		frames := int((streamLimit * 3 / 4) / size)
		for i := 0; i < frames; i++ {
			server.handleData(&aether.Frame{
				Type: aether.TypeDATA, StreamID: id, SeqNo: uint32(1 + i),
				Flags: aether.FlagANTIREPLAY, Length: size, Payload: make([]byte, size),
			})
		}
		server.handleClose(&aether.Frame{Type: aether.TypeCLOSE, StreamID: id, SeqNo: uint32(1 + frames)})
		held = append(held, ss)
	}
	var retained, charged int64
	for _, ss := range held {
		retained += ss.recvQ.queuedBytes()
		charged += queueCost(ss.recvQ)
	}
	t.Logf("streamLimit=%d sessionLimit=%d retained=%d charged=%d budget=%d",
		streamLimit, sessionLimit, retained, charged, server.recvQueued.Load())
	if charged > sessionLimit {
		t.Errorf("%d held for late readers past the %d session ceiling", charged, sessionLimit)
	}
	if retained <= sessionLimit/2 {
		t.Fatalf("premise: only %d bytes retained, the ceiling was never approached", retained)
	}
	if got := server.recvQueued.Load(); got != charged {
		t.Errorf("session budget reads %d, the queues hold %d charged", got, charged)
	}

	before := server.recvQueued.Load()
	firstCost := queueCost(held[0].recvQ)
	n := 0
	for {
		_, err := held[0].Receive(ctx)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatalf("late read: %v", err)
			}
			break
		}
		n++
	}
	if n == 0 {
		t.Fatalf("the late reader read nothing from a stream the peer filled and closed")
	}
	if got := server.recvQueued.Load(); got != before-firstCost {
		t.Errorf("after draining the first stream the budget reads %d, want %d", got, before-firstCost)
	}
}

// TestNoiseStream_SmallMessagesInsideCreditAreNotRefused: messages of 16 bytes
// and empty ones, as many as the stream's credit admits at messageCredit each,
// all queue for a consumer that is not reading, and the session's budget is
// what credit charged for them; the message after the stream's credit is
// refused.
func TestNoiseStream_SmallMessagesInsideCreditAreNotRefused(t *testing.T) {
	for _, size := range []int64{16, 0} {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			client, server := noisePairWithRealms(t, nil, nil)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			_, ss := openWithCredit(t, ctx, client, server, 311, flow.MaxGrowableWindow)
			streamLimit, _ := ss.receiveCeilings()
			n := int(streamLimit / messageCredit(size))
			for i := 0; i < n; i++ {
				if !ss.enqueueDelivery(make([]byte, size)) {
					t.Fatalf("message %d of %d (credit %d of the stream's %d) refused",
						i+1, n, int64(i+1)*messageCredit(size), streamLimit)
				}
			}
			if got, want := server.recvQueued.Load(), int64(n)*messageCredit(size); got != want {
				t.Errorf("budget %d after %d messages, want their credit %d", got, n, want)
			}
			if ss.enqueueDelivery(make([]byte, size)) {
				t.Errorf("a message past the stream's credit (%d of %d) was admitted",
					int64(n+1)*messageCredit(size), streamLimit)
			}
		})
	}
}

// TestNoiseStream_GracefulCloseReturnsConnectionCredit: RPC-shaped churn past the
// connection window. The client sends a request and half-closes; the server
// replies 256 KiB, the reply is acknowledged, and the server closes; the client
// reads the reply either before the server's CLOSE reaches it or after. The
// server's Close, the second close, takes the stream out of the session and
// returns no credit; the client's reads return it by grant, also when the read
// comes after the client's stream has left. So seventy replies, past the 16 MiB
// connection window in total, all go, and the window ends whole.
func TestNoiseStream_GracefulCloseReturnsConnectionCredit(t *testing.T) {
	for _, late := range []bool{true, false} {
		t.Run(fmt.Sprintf("lateReader=%v", late), func(t *testing.T) {
			key := uint32(0x5eed5eed)
			client, server := noisePairWithRealms(t, &key, &key)
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
			defer cancel()
			reply := make([]byte, 256*1024)
			for i := range reply {
				reply[i] = byte(i * 7)
			}
			initial, _ := server.connWindow.ReceiveCeilings()
			for k := 0; k < 70; k++ {
				id := uint64(400 + k)
				cs, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: id, Reliability: aether.ReliableOrdered, Priority: 128})
				if err != nil {
					t.Fatalf("open: %v", err)
				}
				if err := cs.Send(ctx, []byte("req")); err != nil {
					t.Fatalf("req: %v", err)
				}
				_ = cs.Close()
				ss, err := server.AcceptStream(ctx)
				if err != nil {
					t.Fatalf("accept: %v", err)
				}
				if got, err := ss.Receive(ctx); err != nil || string(got) != "req" {
					t.Fatalf("server receive: %q %v", got, err)
				}
				done := make(chan error, 1)
				var got []byte
				if !late {
					go func() {
						var err error
						got, err = cs.Receive(ctx)
						done <- err
					}()
				}
				sctx, scancel := context.WithTimeout(ctx, 15*time.Second)
				err = ss.Send(sctx, reply)
				scancel()
				if err != nil {
					t.Fatalf("RPC %d: server reply Send: %v (server connection credit %d of %d)",
						k, err, server.connWindow.Available(), initial)
				}
				waitSendWindowEmpty(t, asNoiseStream(t, ss), "the reply acked before the close")
				_ = ss.Close()
				if k == 0 {
					// The second close ends the closer's receive side too:
					// Receive reports the end and does not wait.
					ectx, ecancel := context.WithTimeout(ctx, 2*time.Second)
					_, err := ss.Receive(ectx)
					ecancel()
					if !errors.Is(err, io.EOF) {
						t.Fatalf("server Receive after both sides closed: %v, want io.EOF", err)
					}
				}
				if late {
					waitFor(t, "the server's CLOSE ending the client's stream", func() bool { return !streamPresent(client, id) })
					rctx, rcancel := context.WithTimeout(ctx, 10*time.Second)
					got, err = cs.Receive(rctx)
					rcancel()
				} else {
					err = <-done
				}
				if err != nil || len(got) != len(reply) {
					t.Fatalf("RPC %d: client got %d of %d reply bytes: %v", k, len(got), len(reply), err)
				}
				waitFor(t, "the closed stream out of the server's session", func() bool { return !streamPresent(server, id) })
			}
			waitLong(t, "the server's connection window whole again", func() bool { return server.connWindow.Available() == initial })
		})
	}
}

// TestNoiseStream_AClosedStreamWritesItsCloseAndLeavesOnTheACKThatEmptiesItsWindow:
// the client has closed; the server sends a frame and closes at once. While the
// frame is unacknowledged the server's CLOSE is not written and the stream stays
// in the session, where handleACK and the reliability tick reach it; the ACK
// that empties its send window writes the CLOSE (finishSend), the stream leaves,
// and its connection credit comes back when the client's consumer reads the frame.
func TestNoiseStream_AClosedStreamWritesItsCloseAndLeavesOnTheACKThatEmptiesItsWindow(t *testing.T) {
	key := uint32(0x5eed5eed)
	client, server := noisePairWithRealms(t, &key, &key)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	initial, _ := server.connWindow.ReceiveCeilings()
	cs, ss := openWithCredit(t, ctx, client, server, 450, 0)
	if err := cs.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}
	waitFor(t, "the client's CLOSE at the server", func() bool { return ss.peerClosed.Load() })
	if err := ss.Send(ctx, make([]byte, 8*1024)); err != nil {
		t.Fatalf("send: %v", err)
	}
	_ = ss.Close()
	if ss.closeDone.Load() {
		t.Skip("the frame was acknowledged before Close; nothing left to wait on")
	}
	if !streamPresent(server, 450) {
		t.Fatalf("the stream left the session with %d frames unacknowledged", ss.sendWindow.InFlight())
	}
	waitFor(t, "the CLOSE written after the last ACK", func() bool { return ss.closeDone.Load() })
	waitFor(t, "the stream out of the session after its last ACK", func() bool { return !streamPresent(server, 450) })
	waitFor(t, "the client's CLOSE leaving its stream", func() bool { return !streamPresent(client, 450) })
	if got, want := server.connWindow.Available(), initial-messageCredit(8*1024); got != want {
		t.Fatalf("connection credit %d after the leave; want %d, what the client's queue still holds", got, want)
	}
	if got, err := cs.Receive(ctx); err != nil || len(got) != 8*1024 {
		t.Fatalf("the client's late read: %d bytes, %v", len(got), err)
	}
	waitLong(t, "the connection credit back by the client's grant", func() bool { return server.connWindow.Available() == initial })
}

// creditPairWithStreamCap is noisePairWithRealms with no realm and the given
// MaxConcurrentStreams on both sides, so the session's credit ceiling
// (flow.BoundsProfile.AdmittedCreditCeiling) is that many default stream credits, and node IDs no
// other test uses, so the two sessions' peer ledgers are this pair's alone.
func creditPairWithStreamCap(t *testing.T, streams int, tag string) (client, server *NoiseSession) {
	t.Helper()
	return creditPairWithStreamCaps(t, streams, streams, tag)
}

// creditPairWithStreamCaps is creditPairWithStreamCap with a stream cap, and
// so a credit ceiling, for each side.
func creditPairWithStreamCaps(t *testing.T, clientStreams, serverStreams int, tag string) (client, server *NoiseSession) {
	t.Helper()
	chosen := aetherChosen(t)
	c, s := loopbackPair(t)
	clientOpts, serverOpts := aether.DefaultSessionOptions(), aether.DefaultSessionOptions()
	clientOpts.MaxConcurrentStreams = clientStreams
	serverOpts.MaxConcurrentStreams = serverStreams
	clientID, serverID := aether.NodeID("vl1_credit_client_"+tag), aether.NodeID("vl1_credit_server_"+tag)
	client = NewNoiseSession(realmConn{Conn: c, chosen: chosen}, clientID, serverID, clientOpts)
	server = NewNoiseSession(realmConn{Conn: s, chosen: chosen}, serverID, clientID, serverOpts)
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client, server
}

// TestNoiseSession_AnInitialCreditAboveTheStreamCeilingIsRefused: OpenStream
// refuses an initial credit above the stream's own ceiling (its MaxCredit, or
// flow.MaxGrowableWindow), which would otherwise raise the window's growth
// ceiling to it, and admits one at the ceiling.
func TestNoiseSession_AnInitialCreditAboveTheStreamCeilingIsRefused(t *testing.T) {
	client, _ := noisePairWithRealms(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, cfg := range []aether.StreamConfig{
		{StreamID: 650, InitialCredit: flow.MaxGrowableWindow + 1},
		{StreamID: 651, InitialCredit: 2 << 20, MaxCredit: 1 << 20},
	} {
		st, err := client.OpenStream(ctx, cfg)
		if !errors.Is(err, aether.ErrStreamCreditRefused) || st != nil || !strings.Contains(err.Error(), "stream ceiling") {
			t.Errorf("initial %d, max %d: stream %v, err %v; want ErrStreamCreditRefused naming the stream ceiling",
				cfg.InitialCredit, cfg.MaxCredit, st, err)
		}
		if streamPresent(client, cfg.StreamID) {
			t.Errorf("stream %d refused and in s.streams", cfg.StreamID)
		}
	}
	st, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: 652, InitialCredit: flow.MaxGrowableWindow})
	if err != nil {
		t.Fatalf("initial credit at the stream ceiling: %v", err)
	}
	if got := asNoiseStream(t, st).window.CurrentWindow(); got != flow.MaxGrowableWindow {
		t.Errorf("window %d, want %d", got, flow.MaxGrowableWindow)
	}
}

// TestNoiseSession_OpenPastTheSessionCreditCeilingIsRefusedBeforePublication:
// streams whose receive credit together fill the session's ceiling open; the
// next is refused with aether.ErrStreamCreditRefused before it is in s.streams,
// so no OPEN reaches the peer and no acceptor sees it, though the stream cap has
// room; a Reset gives its stream's credit back and the same open then succeeds.
func TestNoiseSession_OpenPastTheSessionCreditCeilingIsRefusedBeforePublication(t *testing.T) {
	const streamCap = 8
	client, server := creditPairWithStreamCap(t, streamCap, "session")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ceiling := client.admitted.ceiling
	if ceiling != streamCap*flow.DefaultStreamCredit {
		t.Fatalf("premise: session ceiling %d, want %d stream credits", ceiling, streamCap)
	}
	const credit = 2 << 20
	n := int((ceiling - client.admitted.held()) / credit)
	var opened []aether.Stream
	for i := 0; i < n; i++ {
		st, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: uint64(600 + i), Reliability: aether.ReliableOrdered, InitialCredit: credit})
		if err != nil {
			t.Fatalf("open %d of %d inside the ceiling: %v", i+1, n, err)
		}
		opened = append(opened, st)
	}
	if n >= streamCap {
		t.Fatalf("premise: %d streams fill the credit ceiling, the stream cap %d would refuse first", n, streamCap)
	}
	refusedID := uint64(600 + n)
	st, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: refusedID, Reliability: aether.ReliableOrdered, InitialCredit: credit})
	if !errors.Is(err, aether.ErrStreamCreditRefused) || st != nil {
		t.Fatalf("open past the session ceiling: stream %v, err %v; want nil and ErrStreamCreditRefused", st, err)
	}
	if !strings.Contains(err.Error(), "session ceiling") {
		t.Errorf("refusal %q does not name the session ceiling", err)
	}
	if streamPresent(client, refusedID) {
		t.Errorf("the refused stream is in s.streams")
	}
	actx, acancel := context.WithTimeout(ctx, 500*time.Millisecond)
	got, err := server.AcceptStreamByID(actx, refusedID)
	acancel()
	if err == nil || got != nil {
		t.Errorf("the peer's acceptor saw the refused stream: %v, %v", got, err)
	}

	if err := opened[0].Reset(aether.ResetCancel); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if _, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: refusedID, Reliability: aether.ReliableOrdered, InitialCredit: credit}); err != nil {
		t.Fatalf("open after a Reset gave its stream's credit back: %v", err)
	}
}

// TestNoiseSession_PeerOpenPastTheCreditCeilingIsResetAndReachesNoAcceptor: the
// server's own streams fill its session ceiling; a stream the client then opens
// is admitted on the client and refused on the server, which answers
// RESET(ResetRefused) before the stream is published, so the server's acceptor
// never sees it, and the client's Send and Receive on it return
// aether.ErrStreamRefused while the client's reservation for it goes back.
// The client's stream cap, and so its credit ceiling, is twice the server's:
// a stream reserves its opener's credit on both sides, so the server's streams
// hold as much of the client's ceiling as of the server's own.
func TestNoiseSession_PeerOpenPastTheCreditCeilingIsResetAndReachesNoAcceptor(t *testing.T) {
	client, server := creditPairWithStreamCaps(t, 16, 8, "remote")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	const credit = 2 << 20
	fill := int((server.admitted.ceiling - server.admitted.held()) / credit)
	for i := 0; i < fill; i++ {
		if _, err := server.OpenStream(ctx, aether.StreamConfig{StreamID: uint64(700 + i), Reliability: aether.ReliableOrdered, InitialCredit: credit}); err != nil {
			t.Fatalf("server open %d: %v", i, err)
		}
	}
	waitFor(t, "the client admitting the server's streams", func() bool {
		for i := 0; i < fill; i++ {
			if !streamPresent(client, uint64(700+i)) {
				return false
			}
		}
		return true
	})
	refusedBefore := server.StreamRefusedCount()
	clientHeld := client.admitted.held()
	cs, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: 710, Reliability: aether.ReliableOrdered, Priority: 128})
	if err != nil {
		t.Fatalf("client open: %v", err)
	}
	rctx, rcancel := context.WithTimeout(ctx, 10*time.Second)
	_, err = cs.Receive(rctx)
	rcancel()
	if !errors.Is(err, aether.ErrStreamRefused) {
		t.Fatalf("client Receive on the refused stream: %v, want ErrStreamRefused", err)
	}
	if err := cs.Send(ctx, []byte("x")); !errors.Is(err, aether.ErrStreamRefused) {
		t.Errorf("client Send on the refused stream: %v, want ErrStreamRefused", err)
	}
	if got := server.StreamRefusedCount(); got <= refusedBefore {
		t.Errorf("server refusals %d, want more than %d", got, refusedBefore)
	}
	if streamPresent(server, 710) {
		t.Errorf("the refused stream is in the server's s.streams")
	}
	actx, acancel := context.WithTimeout(ctx, 500*time.Millisecond)
	got, err := server.AcceptStream(actx)
	acancel()
	if err == nil || got != nil {
		t.Errorf("the server's acceptor saw a stream: %v, %v", got, err)
	}
	waitFor(t, "the client's reservation for the refused stream back", func() bool { return client.admitted.held() == clientHeld })
}

// TestNoiseSession_StreamsAcrossTwoSessionsOfOnePeerMeetThePeerCeiling: two
// sessions naming the same peer share its ledger. One fills its own ceiling and
// the other opens up to what the peer ceiling leaves; the other's next stream
// fits its own session ceiling and is refused by the peer's, and once the first
// session closes, its share goes back and the same open succeeds.
func TestNoiseSession_StreamsAcrossTwoSessionsOfOnePeerMeetThePeerCeiling(t *testing.T) {
	_, serverA := creditPairWithStreamCap(t, 8, "peer")
	_, serverB := creditPairWithStreamCap(t, 8, "peer")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	peer := serverA.admitted.parent
	if peer == nil || peer != serverB.admitted.parent {
		t.Fatalf("premise: two sessions naming one peer hold different peer ledgers")
	}
	sessionCeiling := serverA.admitted.ceiling
	if peer.ceiling != peerCreditCeiling(sessionCeiling) || peer.ceiling >= 2*sessionCeiling {
		t.Fatalf("premise: peer ceiling %d for session ceiling %d", peer.ceiling, sessionCeiling)
	}
	const credit = 2 << 20
	open := func(s *NoiseSession, id uint64) error {
		_, err := s.OpenStream(ctx, aether.StreamConfig{StreamID: id, Reliability: aether.ReliableOrdered, InitialCredit: credit})
		return err
	}
	fillA := int((sessionCeiling - serverA.admitted.held()) / credit)
	for i := 0; i < fillA; i++ {
		if err := open(serverA, uint64(800+i)); err != nil {
			t.Fatalf("session A open %d: %v", i, err)
		}
	}
	fillB := int((peer.ceiling - peer.held()) / credit)
	for i := 0; i < fillB; i++ {
		if err := open(serverB, uint64(820+i)); err != nil {
			t.Fatalf("session B open %d inside the peer ceiling: %v", i, err)
		}
	}
	if serverB.admitted.held()+credit > sessionCeiling {
		t.Fatalf("premise: session B holds %d, no room left under its own ceiling %d", serverB.admitted.held(), sessionCeiling)
	}
	err := open(serverB, 830)
	if !errors.Is(err, aether.ErrStreamCreditRefused) || !strings.Contains(err.Error(), "peer ceiling") {
		t.Fatalf("session B open past the peer ceiling: %v, want ErrStreamCreditRefused naming the peer ceiling", err)
	}
	if streamPresent(serverB, 830) {
		t.Errorf("the refused stream is in session B's s.streams")
	}
	_ = serverA.Close()
	if err := open(serverB, 830); err != nil {
		t.Fatalf("open after the other session to the peer closed: %v", err)
	}
}

// TestNoiseSession_AnAbandonedQueueIsDiscardedAfterTheIdleTimeout: messages
// queued when the peer RESETs the stream stay readable and charged; the sweep
// keeps them while the queue is younger than the stream idle timeout and
// discards them, returning their cost, once nobody has taken from it for that
// long.
func TestNoiseSession_AnAbandonedQueueIsDiscardedAfterTheIdleTimeout(t *testing.T) {
	client, server := noisePairWithRealms(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cs, ss := openWithCredit(t, ctx, client, server, 900, 0)
	for i := 0; i < 3; i++ {
		if err := cs.Send(ctx, burstMessage(i, 512)); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	waitStepAcked(t, cs)
	if err := cs.Reset(aether.ResetCancel); err != nil {
		t.Fatalf("reset: %v", err)
	}
	waitFor(t, "the peer's RESET ending the server's stream", func() bool { return !streamPresent(server, 900) })
	cost := queueCost(ss.recvQ)
	if cost != 3*messageCredit(512) || server.recvQueued.Load() != cost {
		t.Fatalf("premise: queue cost %d, budget %d; want both %d", cost, server.recvQueued.Load(), 3*messageCredit(512))
	}
	server.sweepEndedQueues(time.Now())
	if got := server.recvQueued.Load(); got != cost {
		t.Fatalf("a queue ended a moment ago was swept: budget %d, want %d", got, cost)
	}
	// A take restarts the idle clock: a sweep one idle timeout after the end,
	// but less than one after the take, keeps the queue.
	time.Sleep(100 * time.Millisecond)
	if got, err := ss.Receive(ctx); err != nil || len(got) != 512 {
		t.Fatalf("a message queued before the RESET: %d bytes, %v", len(got), err)
	}
	took := time.Now()
	server.sweepEndedQueues(took.Add(aether.DefaultStreamIdleTimeout - 50*time.Millisecond))
	if got := server.recvQueued.Load(); got != 2*messageCredit(512) {
		t.Fatalf("a queue its consumer took from within the idle timeout was swept: budget %d, want %d", got, 2*messageCredit(512))
	}
	server.sweepEndedQueues(took.Add(aether.DefaultStreamIdleTimeout + time.Second))
	if got := server.recvQueued.Load(); got != 0 {
		t.Errorf("after the idle sweep the budget reads %d, want 0", got)
	}
	if _, err := ss.Receive(ctx); !errors.Is(err, aether.ErrStreamOverrun) {
		t.Errorf("Receive after the discard: %v, want ErrStreamOverrun", err)
	}
	server.mu.Lock()
	tracked := len(server.endedQueues)
	server.mu.Unlock()
	if tracked != 0 {
		t.Errorf("%d queues still tracked after the sweep", tracked)
	}
}
