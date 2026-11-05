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
	"testing"
	"time"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/flow"
	"github.com/ORBTR/aether/reliability"
)

// waitLong is waitFor with room for what crosses a loopback under a loaded host.
func waitLong(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not reached after 45 s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// injectData hands the session's readLoop path DATA frames a peer's credit does
// not cover: count frames of size bytes on stream id, from sequence number first.
func injectData(s *NoiseSession, id uint64, first uint32, count, size int) {
	for i := 0; i < count; i++ {
		s.handleData(&aether.Frame{
			Type: aether.TypeDATA, StreamID: id, SeqNo: first + uint32(i),
			Flags: aether.FlagANTIREPLAY, Length: uint32(size), Payload: make([]byte, size),
		})
	}
}

// TestNoiseSession_SessionsBuildTheBoundsProfile: a session's connection credit
// and its receive ceiling are the profile's one number, and its admitted-credit
// ceiling and stream cap are the profile's.
func TestNoiseSession_SessionsBuildTheBoundsProfile(t *testing.T) {
	client, _ := noisePairWithRealms(t, nil, nil)
	p := flow.CurrentBounds()
	initial, maximum := client.connWindow.ReceiveCeilings()
	if initial != p.SessionMemoryCeiling || maximum != p.SessionMemoryCeiling || client.connWindow.Available() != p.ConnCredit() {
		t.Fatalf("connection window initial %d, maximum %d, available %d; profile's ceiling %d",
			initial, maximum, client.connWindow.Available(), p.SessionMemoryCeiling)
	}
	if client.opts.MaxConcurrentStreams != p.StreamCap {
		t.Fatalf("stream cap %d, profile's %d", client.opts.MaxConcurrentStreams, p.StreamCap)
	}
	if client.admitted.ceiling != p.AdmittedCreditCeiling(p.StreamCap) {
		t.Fatalf("admitted ceiling %d, profile's %d", client.admitted.ceiling, p.AdmittedCreditCeiling(p.StreamCap))
	}
}

// TestNoiseSession_SixteenUndrainedStreamsStallTheSession: sixteen streams hold
// their whole stream credit unread and nothing is refused: the connection credit
// is then spent, a seventeenth stream with all its own credit meets typed
// backpressure, the receiver holds exactly the ceiling, and reading one of the
// sixteen lets the seventeenth send. A control frame queued beside them, which
// the session's memory holds and no sender's credit paid for, does not put that
// honest sender past the ceiling.
func TestNoiseSession_SixteenUndrainedStreamsStallTheSession(t *testing.T) {
	key := uint32(0x5eed5eed)
	client, server := noisePairWithRealms(t, &key, &key)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	p := flow.CurrentBounds()
	if want := p.SessionMemoryCeiling / p.StreamCredit; want != 16 {
		t.Fatalf("premise: the profile lets %d streams fall behind", want)
	}
	// One stream's credit, the opening "hello" taken and granted or not, is
	// filled to the byte by a last message sized to what remains.
	const size = 64 * 1024
	fill := func(cs *noiseStream) {
		t.Helper()
		// The opening message's grant may not have come yet; what Send charges
		// here plus what is left of it must end at the window's edge.
		waitLong(t, "the opening message granted", func() bool {
			return cs.window.Available() == p.StreamCredit
		})
		msg := make([]byte, size)
		for cs.window.Available() >= messageCredit(size) {
			if err := cs.Send(ctx, msg); err != nil {
				t.Fatalf("stream %d: %v", cs.streamID, err)
			}
		}
		if err := cs.Send(ctx, make([]byte, cs.window.Available()-recvQueueEntryCost)); err != nil {
			t.Fatalf("stream %d last message: %v", cs.streamID, err)
		}
		if cs.window.Available() != 0 {
			t.Fatalf("stream %d: %d of its credit left", cs.streamID, cs.window.Available())
		}
		waitLong(t, "the stream's burst acknowledged", func() bool { return cs.sendWindow.InFlight() == 0 })
	}
	_, control := openWithCredit(t, ctx, client, server, server.layout.Control, 0)
	server.deliverToControl(make([]byte, 1024))
	controlCost := queueCost(control.recvQ)
	if controlCost != messageCredit(1024) {
		t.Fatalf("premise: the control frame's cost %d", controlCost)
	}
	waitLong(t, "the control stream's opening message granted", func() bool {
		return client.connWindow.Available() == p.ConnCredit()
	})
	readers := make([]*noiseStream, 0, 16)
	for i := 0; i < 16; i++ {
		cs, ss := openWithCredit(t, ctx, client, server, uint64(200+i), 0)
		fill(cs)
		readers = append(readers, ss)
	}
	waitLong(t, "the connection credit spent", func() bool { return client.connWindow.Available() == 0 })
	waitLong(t, "every message queued at the receiver", func() bool {
		return server.recvCharged.Load() == p.SessionMemoryCeiling
	})
	if got, want := server.recvQueued.Load(), p.SessionMemoryCeiling+controlCost; got != want {
		t.Fatalf("receiver holds %d, want the ceiling and the control frame's cost %d", got, want)
	}

	// The seventeenth stream: open, with its whole stream credit, stalled.
	last, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: 299, Reliability: aether.ReliableOrdered})
	if err != nil {
		t.Fatalf("a seventeenth stream is admitted and stalls, it is not refused: %v", err)
	}
	stalled, cancelStall := context.WithTimeout(ctx, 500*time.Millisecond)
	err = last.Send(stalled, []byte("x"))
	cancelStall()
	if !errors.Is(err, flow.ErrCreditExhausted) {
		t.Fatalf("seventeenth stream's Send with the session's credit spent: %v, want ErrCreditExhausted", err)
	}
	for _, ss := range readers {
		if !ss.IsOpen() {
			t.Fatalf("stream %d was reset at the ceiling", ss.streamID)
		}
	}

	for {
		rctx, rc := context.WithTimeout(ctx, 200*time.Millisecond)
		_, err := readers[0].Receive(rctx)
		rc()
		if err != nil {
			break
		}
	}
	if err := last.Send(ctx, []byte("x")); err != nil {
		t.Fatalf("after one stream was read, the seventeenth's Send: %v", err)
	}
}

// TestNoiseStream_RepliesToAClosedLateReaderStopAtCreditAndAllArrive: an honest
// server answers RPCs whose client half-closed after its request and reads
// nothing until the end. Each RPC's stream leaves both sessions on its two
// CLOSEs, and that returns the server no connection credit, so the server meets
// typed backpressure exactly where the client's memory ceiling is, not a reset
// and not a lost reply. The late reader then gets every message of every reply
// and io.EOF, and those reads return the server's credit. A sender whose leave
// returned its credit would keep going, and the client would reset an honest
// sender at its ceiling and lose replies it had already acknowledged.
func TestNoiseStream_RepliesToAClosedLateReaderStopAtCreditAndAllArrive(t *testing.T) {
	key := uint32(0x5eed5eed)
	client, server := noisePairWithRealms(t, &key, &key)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	const msgs, size = 15, 64 * 1024
	limit := flow.CurrentBounds().SessionMemoryCeiling
	wantReplies := int(limit / (msgs * messageCredit(size)))

	open := func(id uint64) (aether.Stream, aether.Stream) {
		cs, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: id, Reliability: aether.ReliableOrdered, Priority: 128})
		if err != nil {
			t.Fatalf("open %d: %v", id, err)
		}
		if err := cs.Send(ctx, []byte("req")); err != nil {
			t.Fatalf("request %d: %v", id, err)
		}
		_ = cs.Close()
		ss, err := server.AcceptStream(ctx)
		if err != nil {
			t.Fatalf("accept %d: %v", id, err)
		}
		if got, err := ss.Receive(ctx); err != nil || string(got) != "req" {
			t.Fatalf("server receive %d: %q %v", id, got, err)
		}
		return cs, ss
	}

	var held []aether.Stream
	for k := 0; k < wantReplies; k++ {
		id := uint64(600 + k)
		cs, ss := open(id)
		for i := 0; i < msgs; i++ {
			if err := ss.Send(ctx, burstMessage(i, size)); err != nil {
				t.Fatalf("reply %d message %d inside the session's credit: %v", k, i, err)
			}
		}
		waitLong(t, "the reply acknowledged", func() bool { return asNoiseStream(t, ss).sendWindow.InFlight() == 0 })
		if err := ss.Close(); err != nil {
			t.Fatalf("close %d: %v", k, err)
		}
		waitLong(t, "the stream gone from both sessions", func() bool {
			return !streamPresent(server, id) && !streamPresent(client, id)
		})
		held = append(held, cs)
	}
	if got := client.recvCharged.Load(); got != int64(wantReplies*msgs)*messageCredit(size) {
		t.Fatalf("client holds %d charged for %d replies", got, wantReplies)
	}
	if got := server.connWindow.Available(); got != limit-int64(wantReplies*msgs)*messageCredit(size) {
		t.Fatalf("server's connection credit %d after streams left: their leave must return none of it", got)
	}

	// The next reply's next message would pass the ceiling: typed backpressure,
	// with the stream alive.
	_, next := open(uint64(600 + wantReplies))
	stalled, cancelStall := context.WithTimeout(ctx, 500*time.Millisecond)
	err := next.Send(stalled, burstMessage(0, size))
	cancelStall()
	if !errors.Is(err, flow.ErrCreditExhausted) {
		t.Fatalf("the message past the session's credit: %v, want ErrCreditExhausted", err)
	}

	for k, cs := range held {
		for i := 0; i < msgs; i++ {
			got, err := cs.Receive(ctx)
			if err != nil {
				t.Fatalf("late reader, reply %d message %d: %v", k, i, err)
			}
			if int(binary.BigEndian.Uint32(got)) != i {
				t.Fatalf("late reader, reply %d message %d numbered %d", k, i, binary.BigEndian.Uint32(got))
			}
		}
		if _, err := cs.Receive(ctx); !errors.Is(err, io.EOF) {
			t.Fatalf("reply %d after its last message: %v, want io.EOF", k, err)
		}
	}
	waitLong(t, "the server's connection credit back through the client's grants", func() bool {
		return server.connWindow.Available() == limit
	})
	if err := next.Send(ctx, burstMessage(0, size)); err != nil {
		t.Fatalf("with the replies read, the next reply's Send: %v", err)
	}
	if got := client.recvCharged.Load(); got < 0 {
		t.Fatalf("client's charged count %d went negative", got)
	}
}

// TestNoiseStream_TheSweepGrantsBackWhatItDiscards: a late reader that never
// returns leaves a queue of a stream gone on both CLOSEs. The sweep discards it
// and grants its sender the credit, which nothing else would return; a reader
// that returns after that reads ErrStreamOverrun, not an end that looks whole.
func TestNoiseStream_TheSweepGrantsBackWhatItDiscards(t *testing.T) {
	key := uint32(0x5eed5eed)
	client, server := noisePairWithRealms(t, &key, &key)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cs, ss := openWithCredit(t, ctx, client, server, 610, 0)
	const count, size = 6, 32 * 1024
	limit := flow.CurrentBounds().SessionMemoryCeiling
	for i := 0; i < count; i++ {
		if err := cs.Send(ctx, make([]byte, size)); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	waitLong(t, "the burst acknowledged", func() bool { return cs.sendWindow.InFlight() == 0 })
	if err := cs.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}
	if err := ss.Close(); err != nil {
		t.Fatalf("server close: %v", err)
	}
	waitLong(t, "the stream gone from both sessions", func() bool {
		return !streamPresent(server, 610) && !streamPresent(client, 610)
	})
	waitLong(t, "the opening message's credit back", func() bool {
		return client.connWindow.Available() == limit-int64(count)*messageCredit(size)
	})
	if got := server.recvQueued.Load(); got != int64(count)*messageCredit(size) {
		t.Fatalf("server holds %d queued", got)
	}

	server.sweepEndedQueues(time.Now().Add(aether.DefaultStreamIdleTimeout + time.Second))
	if got := server.recvQueued.Load(); got != 0 || server.recvCharged.Load() != 0 {
		t.Fatalf("after the sweep the server holds %d queued, %d charged", got, server.recvCharged.Load())
	}
	waitLong(t, "the discarded messages' credit granted back", func() bool {
		return client.connWindow.Available() == limit
	})
	if _, err := ss.Receive(ctx); !errors.Is(err, aether.ErrStreamOverrun) {
		t.Fatalf("a reader returning after the sweep: %v, want ErrStreamOverrun", err)
	}
}

// TestNoiseStream_AnOverrunIsTypedAtBothEndsAndTheReaderKeepsWhatItHeld: a peer
// past its stream credit is reset. The receiver's consumer reads every message
// the queue took and then ErrStreamOverrun, and the sender's Send and Receive
// read ErrStreamOverrun, so no acknowledged message goes missing unannounced.
func TestNoiseStream_AnOverrunIsTypedAtBothEndsAndTheReaderKeepsWhatItHeld(t *testing.T) {
	client, server := noisePairWithRealms(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cs, ss := openWithCredit(t, ctx, client, server, 620, 0)
	waitSendWindowEmpty(t, cs, "the opening message")
	const size = 64 * 1024
	streamLimit, _ := ss.receiveCeilings()
	fit := int(streamLimit / messageCredit(size))
	injectData(server, 620, 1, fit+1, size)

	for i := 0; i < fit; i++ {
		got, err := ss.Receive(ctx)
		if err != nil || len(got) != size {
			t.Fatalf("receiver, message %d of %d it queued: %d bytes, %v", i, fit, len(got), err)
		}
	}
	if _, err := ss.Receive(ctx); !errors.Is(err, aether.ErrStreamOverrun) {
		t.Fatalf("receiver after what it held: %v, want ErrStreamOverrun", err)
	}
	waitLong(t, "the RESET at the sender", func() bool { return !streamPresent(client, 620) })
	if err := cs.Send(ctx, []byte("x")); !errors.Is(err, aether.ErrStreamOverrun) {
		t.Fatalf("sender's Send after the RESET: %v, want ErrStreamOverrun", err)
	}
	if _, err := cs.Receive(ctx); !errors.Is(err, aether.ErrStreamOverrun) {
		t.Fatalf("sender's Receive after the RESET: %v, want ErrStreamOverrun", err)
	}
}

// TestNoiseSession_FramesHeldBehindAGapMeetTheCeilingWhenItFills: a peer ignoring
// credit holds frames in each stream's receive window behind a sequence gap and
// a CLOSE behind them, which ends nothing until the gap fills. Then each stream is
// held to its credit as in order, and the streams to the session's ceiling, however
// many streams the peer does this on.
func TestNoiseSession_FramesHeldBehindAGapMeetTheCeilingWhenItFills(t *testing.T) {
	client, server := noisePairWithRealms(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	const size = 64 * 1024
	limit := flow.CurrentBounds().SessionMemoryCeiling
	for k := 0; k < 40; k++ {
		id := uint64(700 + k)
		cs, ss := openWithCredit(t, ctx, client, server, id, 0)
		waitSendWindowEmpty(t, cs, "the opening message")
		injectData(server, id, 2, 30, size)
		server.handleClose(peerClose(ss, 32))
		if ss.peerClosed.Load() {
			t.Fatalf("stream %d: a CLOSE behind a gap ended the receive side", id)
		}
		injectData(server, id, 1, 1, size)
		if q := ss.recvQ.queuedBytes(); messageCreditOf(q, size) > ss.window.CurrentWindow() {
			t.Fatalf("stream %d queued %d at close, past its credit %d", id, q, ss.window.CurrentWindow())
		}
		if got := server.recvQueued.Load(); got > limit {
			t.Fatalf("after %d streams the session holds %d, ceiling %d", k+1, got, limit)
		}
	}
}

// messageCreditOf is the credit q payload bytes hold as messages of size bytes.
func messageCreditOf(q int64, size int64) int64 {
	return q + q/size*recvQueueEntryCost
}

// TestNoiseStream_ResetAfterBothClosesGrantsWhatItWillNotRead: Reset on a stream
// that left on both CLOSEs writes no frame, since no peer stream is left for it,
// and grants the sender the credit of the unread messages, which no RESET would
// return now that the sender's stream has left. The messages stay readable, and
// reading them grants nothing more.
func TestNoiseStream_ResetAfterBothClosesGrantsWhatItWillNotRead(t *testing.T) {
	key := uint32(0x5eed5eed)
	client, server := noisePairWithRealms(t, &key, &key)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cs, ss := openWithCredit(t, ctx, client, server, 630, 0)
	limit := flow.CurrentBounds().SessionMemoryCeiling
	const count, size = 4, 32 * 1024
	for i := 0; i < count; i++ {
		if err := cs.Send(ctx, make([]byte, size)); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	waitLong(t, "the burst acknowledged", func() bool { return cs.sendWindow.InFlight() == 0 })
	_ = cs.Close()
	_ = ss.Close()
	waitLong(t, "the stream gone from both sessions", func() bool {
		return !streamPresent(server, 630) && !streamPresent(client, 630)
	})
	// A new stream on the ID, once the ID's quiet time is over: a RESET from either
	// old stream would end it.
	waitLong(t, "the ID's quiet time ending", func() bool {
		client.mu.Lock()
		defer client.mu.Unlock()
		return !client.reopenQuietLocked(630)
	})
	ncs, nss := openWithCredit(t, ctx, client, server, 630, 0)
	if err := ss.Reset(aether.ResetCancel); err != nil {
		t.Fatalf("Reset after the stream left: %v", err)
	}
	if err := cs.Reset(aether.ResetCancel); err != nil {
		t.Fatalf("Reset after the stream left: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if !ncs.IsOpen() || !nss.IsOpen() || !streamPresent(client, 630) || !streamPresent(server, 630) {
		t.Fatal("Reset on a stream that left reached the new stream on its ID")
	}
	if server.recvCharged.Load() != 0 {
		t.Fatalf("after the Reset %d stays charged", server.recvCharged.Load())
	}
	waitLong(t, "the client's credit back through the Reset's grant", func() bool {
		return client.connWindow.Available() == limit
	})
	consumed := server.connWindow.Stats().Consumed
	for i := 0; i < count; i++ {
		if got, err := ss.Receive(ctx); err != nil || len(got) != size {
			t.Fatalf("late read %d: %d bytes, %v", i, len(got), err)
		}
	}
	if _, err := ss.Receive(ctx); !errors.Is(err, io.EOF) {
		t.Fatalf("after the last message: %v, want io.EOF", err)
	}
	time.Sleep(50 * time.Millisecond)
	if got := server.connWindow.Stats().Consumed; got != consumed {
		t.Fatalf("reading after the Reset's grant recorded %d more consumed", got-consumed)
	}
}

// TestNoiseSession_ResetStreamsGiveWayToACreditedSender: an honest sender fills
// and resets streams behind a late reader. The RESET returns the sender's credit
// (it cannot tell what reached the queue), so what those queues hold is memory no
// credit pays for; a sender inside its credit is never refused because of it, and
// the session's memory stays under the ceiling because the longest-idle such queue
// gives way. Its reader reads ErrStreamOverrun; the newest queue's reader reads
// every message.
func TestNoiseSession_ResetStreamsGiveWayToACreditedSender(t *testing.T) {
	key := uint32(0x5eed5eed)
	client, server := noisePairWithRealms(t, &key, &key)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	limit := flow.CurrentBounds().SessionMemoryCeiling
	const msgs, size = 15, 64 * 1024
	var readers []*noiseStream
	for k := 0; k < 20; k++ {
		id := uint64(800 + k)
		cs, ss := openWithCredit(t, ctx, client, server, id, 0)
		for i := 0; i < msgs; i++ {
			if err := cs.Send(ctx, burstMessage(i, size)); err != nil {
				t.Fatalf("stream %d message %d: %v", id, i, err)
			}
		}
		waitLong(t, "the burst acknowledged", func() bool { return cs.sendWindow.InFlight() == 0 })
		if err := cs.Reset(aether.ResetCancel); err != nil {
			t.Fatalf("reset %d: %v", id, err)
		}
		waitLong(t, "the RESET at the receiver", func() bool { return !streamPresent(server, id) })
		if got := server.recvQueued.Load(); got > limit {
			t.Fatalf("after stream %d the session holds %d, ceiling %d", id, got, limit)
		}
		waitLong(t, "the RESET's queue out of the charged count", func() bool { return server.recvCharged.Load() == 0 })
		readers = append(readers, ss)
	}
	if _, err := readers[0].Receive(ctx); !errors.Is(err, aether.ErrStreamOverrun) {
		t.Fatalf("reader of the longest-idle queue: %v, want ErrStreamOverrun", err)
	}
	newest := readers[len(readers)-1]
	for i := 0; i < msgs; i++ {
		got, err := newest.Receive(ctx)
		if err != nil || int(binary.BigEndian.Uint32(got)) != i {
			t.Fatalf("reader of the newest queue, message %d: %v", i, err)
		}
	}
	if _, err := newest.Receive(ctx); !errors.Is(err, io.EOF) {
		t.Fatalf("reader of the newest queue after its last message: %v, want io.EOF", err)
	}
}

// TestNoiseSession_RoomComesOnlyFromQueuesAResetEnded: a late reader holds the
// queues of streams closed on both sides and of streams the sender reset, and the
// sender goes on inside its credit. The room it needs comes from the reset queues,
// whose credit the sender already took back; every closed stream's queue, whose
// credit only its read can return, stays whole for its reader.
func TestNoiseSession_RoomComesOnlyFromQueuesAResetEnded(t *testing.T) {
	key := uint32(0x5eed5eed)
	client, server := noisePairWithRealms(t, &key, &key)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	limit := flow.CurrentBounds().SessionMemoryCeiling
	const closed, resets, msgs, size = 8, 12, 15, 64 * 1024
	var late []*noiseStream
	for k := 0; k < closed+resets; k++ {
		id := uint64(900 + k)
		cs, ss := openWithCredit(t, ctx, client, server, id, 0)
		for i := 0; i < msgs; i++ {
			if err := cs.Send(ctx, burstMessage(i, size)); err != nil {
				t.Fatalf("stream %d message %d: %v", id, i, err)
			}
		}
		waitLong(t, "the burst acknowledged", func() bool { return cs.sendWindow.InFlight() == 0 })
		if k < closed {
			_ = cs.Close()
			_ = ss.Close()
			late = append(late, ss)
		} else if err := cs.Reset(aether.ResetCancel); err != nil {
			t.Fatalf("reset %d: %v", id, err)
		}
		waitLong(t, "the stream gone from the receiver", func() bool { return !streamPresent(server, id) })
		if got := server.recvQueued.Load(); got > limit {
			t.Fatalf("after stream %d the session holds %d, ceiling %d", id, got, limit)
		}
	}
	for k, ss := range late {
		for i := 0; i < msgs; i++ {
			got, err := ss.Receive(ctx)
			if err != nil || int(binary.BigEndian.Uint32(got)) != i {
				t.Fatalf("closed stream %d, message %d: %v", k, i, err)
			}
		}
		if _, err := ss.Receive(ctx); !errors.Is(err, io.EOF) {
			t.Fatalf("closed stream %d after its last message: %v, want io.EOF", k, err)
		}
	}
}

// TestNoiseStream_ADiscardedFragmentGroupGrantsItsMessageCharge: on a session's
// stream, a reassembly group the receiver discards grants the connection window
// its bytes and the message's recvQueueEntryCost, what Send charged for it.
func TestNoiseStream_ADiscardedFragmentGroupGrantsItsMessageCharge(t *testing.T) {
	key := uint32(0x5eed5eed)
	client, server := noisePairWithRealms(t, &key, &key)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cs, ss := openWithCredit(t, ctx, client, server, 960, 0)
	const maxPayload = 1024
	frags, err := SplitMessage(client.fragmentBinding(cs), 77, make([]byte, 3*maxPayload), maxPayload)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if _, whole := ss.reassemble(reliability.RecvDelivery{Payload: frags[0], Marked: true}); whole {
		t.Fatal("the first fragment completed a message")
	}
	before := server.connWindow.Stats().Consumed
	env, chunk, err := ParseFragment(frags[1])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	env.Total++
	if _, whole := ss.reassemble(reliability.RecvDelivery{Payload: fxFragment(env, chunk), Marked: true}); whole {
		t.Fatal("a conflicting fragment completed a message")
	}
	want := int64(len(frags[0])-FragmentEnvelopeSize) + int64(len(chunk)) + recvQueueEntryCost
	if got := server.connWindow.Stats().Consumed - before; got != want {
		t.Fatalf("the discard granted %d, want both slices and the message's charge %d", got, want)
	}
}

// TestFragmentBuffer_ADiscardedGroupReturnsItsMessageCharge: a sender charges
// recvQueueEntryCost once per message beyond its bytes. A reassembly group that
// is discarded will never reach Receive, so its message's charge comes back with
// its bytes, and nothing else returns it once streams keep their credit past
// their CLOSEs.
func TestFragmentBuffer_ADiscardedGroupReturnsItsMessageCharge(t *testing.T) {
	r := fxReceiver()
	fb := newChargedFragmentBuffer(recvQueueEntryCost)
	_, frags := fxMessage(t, fxBinding(), 5, 700)
	if _, released, err := fb.Add(r, 7, frags[0]); err != nil || released != 0 {
		t.Fatalf("first fragment: released %d, %v", released, err)
	}
	env, chunk, _ := ParseFragment(frags[1])
	env.Total = 4
	_, released, err := fb.Add(r, 7, fxFragment(env, chunk))
	wantRefusal(t, "same ID, another total", err, FragmentConflict)
	if want := int64(len(frags[0])+len(chunk)-FragmentEnvelopeSize) + recvQueueEntryCost; released != want {
		t.Fatalf("released %d, want both slices and the message's charge %d", released, want)
	}
}
