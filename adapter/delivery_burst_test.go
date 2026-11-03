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
)

// burstMessage is a payload of size bytes whose first four bytes number it.
func burstMessage(i, size int) []byte {
	m := make([]byte, size)
	binary.BigEndian.PutUint32(m, uint32(i))
	return m
}

// lateReaderBurst sends n messages of size bytes on a fresh stream in steps of
// step, waiting after each step until the peer has acknowledged all of it, with
// no Receive running. It then requires every Receive in order. handleData
// acknowledges a frame before it hands it to the stream's queue, so a message the
// queue lost is one no retransmit brings back and its Receive runs into the
// deadline. Steps stay under the initial congestion window, so what this drives
// is the receive queue and not the write loop's congestion gate.
func lateReaderBurst(t *testing.T, n, size, step int) {
	t.Helper()
	client, server := noisePairWithRealms(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	const streamID = 104
	cs, ss := openAccept(t, ctx, client, server, streamID)
	st := asNoiseStream(t, cs)
	for i := 0; i < n; i++ {
		if err := cs.Send(ctx, burstMessage(i, size)); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
		if (i+1)%step == 0 || i == n-1 {
			waitStepAcked(t, st)
		}
	}
	recvCtx, recvCancel := context.WithTimeout(ctx, 5*time.Second)
	defer recvCancel()
	for i := 0; i < n; i++ {
		got, err := ss.Receive(recvCtx)
		if err != nil {
			t.Fatalf("receive %d of %d: %v", i, n, err)
		}
		if len(got) != size || int(binary.BigEndian.Uint32(got)) != i {
			t.Fatalf("receive %d of %d: %d bytes numbered %d", i, n, len(got), binary.BigEndian.Uint32(got))
		}
	}
}

// waitStepAcked polls until the stream's SendWindow holds no entry. The bound is
// wide because a frame the write loop's congestion gate holds waits on a
// retransmit timer under a loaded machine, and that wait is not what this asserts.
func waitStepAcked(t *testing.T, st *noiseStream) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for st.sendWindow.InFlight() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d entries still in the send window after 45 s", st.sendWindow.InFlight())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestNoiseStream_BurstWithALateReaderDeliversEveryMessageInOrder: 20 messages
// of 512 bytes, twenty fresh sessions, every Receive completes in order.
func TestNoiseStream_BurstWithALateReaderDeliversEveryMessageInOrder(t *testing.T) {
	for run := 0; run < 20; run++ {
		lateReaderBurst(t, 20, 512, 20)
	}
}

// TestNoiseStream_LateReaderIsBoundedByCreditAndNotByACount: 400 small messages
// wait for a reader that arrives after the last ACK; what bounds the wait is the
// stream's credit, which they fit, and no count of messages.
func TestNoiseStream_LateReaderIsBoundedByCreditAndNotByACount(t *testing.T) {
	lateReaderBurst(t, 400, 512, 8)
}

// openWithCredit opens a stream whose sender holds credit bytes and returns
// both ends once the opening message has been taken off the queue.
func openWithCredit(t *testing.T, ctx context.Context, client, server *NoiseSession, id uint64, credit int64) (*noiseStream, *noiseStream) {
	t.Helper()
	cs, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: id, Reliability: aether.ReliableOrdered, Priority: 128, InitialCredit: credit})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := cs.Send(ctx, []byte("hello")); err != nil {
		t.Fatalf("first send: %v", err)
	}
	ss, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if got, err := ss.Receive(ctx); err != nil || string(got) != "hello" {
		t.Fatalf("first receive %q, %v", got, err)
	}
	return asNoiseStream(t, cs), asNoiseStream(t, ss)
}

// waitFor polls cond for up to five seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not reached after 5 s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestNoiseStream_SenderPastItsCreditMeetsTypedBackpressure: a sender with no
// reader on the far side stops at its credit with ErrCreditExhausted, whether
// its frames are under flow.MinGuaranteedWindow or over it. ACKs arrive
// meanwhile and return nothing, no CONGESTION reaches it, and once the consumer
// reads, every message is there in order and credit is back. A session with a
// realm, since the path's MSS may send the larger size as fragments.
//
// The credit is the window as it stands: reliabilityTick runs autoTuneWindows on
// the session's first tick and every 10 s after, and for a stream with an RTT
// its aether.AutoTuneWindow step grows the sender's window by up to a quarter
// when the peak outstanding is above two thirds of it. The test runs that step
// itself, with an RTT given, once three quarters of the initial credit is
// outstanding, so the window grows mid-burst on every run, and each bound is
// read from cs.window when it is asserted.
func TestNoiseStream_SenderPastItsCreditMeetsTypedBackpressure(t *testing.T) {
	for _, size := range []int{512, 2048} {
		key := uint32(0x5eed5eed)
		client, server := noisePairWithRealms(t, &key, &key)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		const credit = 16 * 1024
		cs, ss := openWithCredit(t, ctx, client, server, 105, credit)
		hitsBefore := client.Throttle().TotalHits()

		sent := 0
		var sendErr error
		for int64(sent*size) <= cs.window.CurrentWindow() {
			if sent*size == credit*3/4 {
				aether.AutoTuneWindow(cs.window, 50*time.Millisecond)
			}
			sendCtx, sendCancel := context.WithTimeout(ctx, 300*time.Millisecond)
			sendErr = cs.Send(sendCtx, burstMessage(sent, size))
			sendCancel()
			if sendErr != nil {
				break
			}
			sent++
		}
		window := cs.window.CurrentWindow()
		if !errors.Is(sendErr, flow.ErrCreditExhausted) {
			t.Fatalf("size %d: after %d messages Send returned %v, want ErrCreditExhausted", size, sent, sendErr)
		}
		if int64(sent*size) > window {
			t.Fatalf("size %d: %d messages of %d bytes admitted past a %d-byte window", size, sent, size, window)
		}
		if window <= credit {
			t.Fatalf("premise wrong: the window stayed at %d after the auto-tune step with %d bytes outstanding", window, credit*3/4)
		}
		waitSendWindowEmpty(t, cs, "acks of everything admitted")
		got := cs.window.Available()
		if window = cs.window.CurrentWindow(); got > window-int64(sent*size)+5 {
			t.Fatalf("size %d: ACKs alone returned credit: %d available of a %d-byte window after %d charged", size, got, window, sent*size)
		}
		if q := ss.recvQ.queuedBytes(); q > window {
			t.Fatalf("size %d: receive queue holds %d bytes past the sender's %d-byte window", size, q, window)
		}
		if hits := client.Throttle().TotalHits() - hitsBefore; hits != 0 {
			t.Fatalf("size %d: sender saw %d CONGESTION frames with no byte lost", size, hits)
		}
		for i := 0; i < sent; i++ {
			got, err := ss.Receive(ctx)
			if err != nil {
				t.Fatalf("size %d: receive %d: %v", size, i, err)
			}
			if len(got) != size || int(binary.BigEndian.Uint32(got)) != i {
				t.Fatalf("size %d: receive %d: %d bytes numbered %d", size, i, len(got), binary.BigEndian.Uint32(got))
			}
		}
		waitFor(t, "credit back after the consumer read", func() bool { return cs.window.Available() >= int64(size) })
		if err := cs.Send(ctx, burstMessage(sent, size)); err != nil {
			t.Fatalf("size %d: send after the consumer read: %v", size, err)
		}
		if got, err := ss.Receive(ctx); err != nil || len(got) != size {
			t.Fatalf("size %d: last receive: %d bytes, %v", size, len(got), err)
		}
	}
}

// TestNoiseStream_SmallSenderCreditReturnsAgainstALargeReceiveWindow: the opener
// charges its own small initial credit while the accepting side's window is the
// default, so the receive window's threshold is four times what this sender can
// ever have outstanding. Grants still return it, and the sender moves far more than
// its credit.
func TestNoiseStream_SmallSenderCreditReturnsAgainstALargeReceiveWindow(t *testing.T) {
	key := uint32(0x5eed5eed)
	client, server := noisePairWithRealms(t, &key, &key)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const credit = 8 * 1024
	cs, ss := openWithCredit(t, ctx, client, server, 106, credit)
	msg := burstMessage(0, 4096)
	const total = 16
	done := make(chan error, 1)
	go func() {
		for i := 0; i < total; i++ {
			if err := cs.Send(ctx, msg); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	for i := 0; i < total; i++ {
		if _, err := ss.Receive(ctx); err != nil {
			t.Fatalf("receive %d: %v", i, err)
		}
	}
	if err := <-done; err != nil {
		t.Fatalf("send: %v", err)
	}
}

// overCreditFrames feeds server's readLoop path with DATA in order on the given
// stream, as a peer that ignores credit, until send reports stop or the stream
// is gone, requiring the bound at every step.
func overCreditFrames(t *testing.T, server *NoiseSession, st *noiseStream, firstSeq uint32, frames int, size int, direct bool, bound func() bool) {
	t.Helper()
	for i := 0; i < frames; i++ {
		if direct {
			st.enqueueDelivery(make([]byte, size))
		} else {
			server.handleData(&aether.Frame{
				Type:     aether.TypeDATA,
				StreamID: st.streamID,
				SeqNo:    firstSeq + uint32(i),
				Flags:    aether.FlagANTIREPLAY,
				Length:   uint32(size),
				Payload:  make([]byte, size),
			})
		}
		if !bound() {
			t.Fatalf("after %d frames of %d bytes: past the bound (stream holds %d, session %d)",
				i+1, size, st.recvQ.queuedBytes(), server.recvQueued.Load())
		}
		server.mu.Lock()
		_, alive := server.streams[st.streamID]
		server.mu.Unlock()
		if !alive {
			return
		}
	}
	t.Fatalf("%d frames of %d bytes past every ceiling and the stream was not refused", frames, size)
}

// TestNoiseStream_APeerIgnoringCreditIsResetAndGrowsNoMemory: DATA past what any
// honest sender can hold gets a flow-control RESET and an abuse charge, the queue
// never passes the ceiling on the way there and is freed after it, and the
// session's budget returns to zero. Empty messages charge no credit, and the
// per-message cost still stops them.
func TestNoiseStream_APeerIgnoringCreditIsResetAndGrowsNoMemory(t *testing.T) {
	for _, tc := range []struct {
		name   string
		size   int
		frames int
		// direct feeds enqueueDelivery without handleData's per-frame ACK, for
		// the hundreds of thousands of frames the empty case needs.
		direct bool
	}{
		{"large frames", 64 * 1024, 2 * 1024, false},
		{"empty frames", 0, 1 << 20, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := noisePairWithRealms(t, nil, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			cs, ss := openWithCredit(t, ctx, client, server, 107, 0)
			streamLimit, sessionLimit := ss.receiveCeilings()
			waitSendWindowEmpty(t, cs, "the opening message")
			overCreditFrames(t, server, ss, 1, tc.frames, tc.size, tc.direct, func() bool {
				return ss.recvQ.queuedBytes() <= streamLimit && server.recvQueued.Load() <= sessionLimit
			})
			if got := server.recvQueued.Load(); got != 0 {
				t.Errorf("session budget after the refusal: %d, want 0", got)
			}
			if got := ss.recvQ.len(); got != 0 {
				t.Errorf("refused queue still holds %d messages", got)
			}
			if got := server.deliveryStats.StreamOtherDropped.Load(); got != 1 {
				t.Errorf("StreamOtherDropped %d, want 1", got)
			}
			if _, err := ss.Receive(ctx); !errors.Is(err, io.EOF) {
				t.Errorf("receive on the refused stream: %v, want io.EOF", err)
			}
			waitFor(t, "the peer's stream reset", func() bool { return !cs.IsOpen() })
		})
	}
}

// TestNoiseStream_DepartingStreamsReturnEveryConnectionByte: a stream that ends
// with messages unread and frames in flight gives its bytes back, by the local
// Reset, by a RESET from the peer, and by the peer's side reading nothing. Churn
// that stranded them would end in "insufficient connection credit" for the
// session's other streams. The server's consumer reads none of its streams'
// messages: they stay charged to its budget until the sweep finds the queues
// abandoned, which returns all of it.
func TestNoiseStream_DepartingStreamsReturnEveryConnectionByte(t *testing.T) {
	client, server := noisePairWithRealms(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	msg := burstMessage(0, 512)
	for i := uint64(0); i < 12; i++ {
		id := 200 + i
		cs, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: id, Reliability: aether.ReliableOrdered, Priority: 128})
		if err != nil {
			t.Fatalf("open %d: %v", id, err)
		}
		for j := 0; j < 40; j++ {
			if err := cs.Send(ctx, msg); err != nil {
				t.Fatalf("stream %d send %d: %v", id, j, err)
			}
		}
		ss, err := server.AcceptStream(ctx)
		if err != nil {
			t.Fatalf("accept %d: %v", id, err)
		}
		if i%2 == 0 {
			_ = cs.Reset(aether.ResetCancel)
			if st := asNoiseStream(t, ss); st != nil {
				waitFor(t, "the peer's end", func() bool { return !st.IsOpen() })
			}
			_ = ss.Close()
		} else {
			_ = ss.Reset(aether.ResetCancel)
			waitFor(t, "the peer's end", func() bool { return !cs.IsOpen() })
		}
	}
	initial, _ := client.connWindow.ReceiveCeilings()
	deadline := time.Now().Add(5 * time.Second)
	for client.connWindow.Available() != initial {
		if time.Now().After(deadline) {
			t.Fatalf("connection credit: %d available of %d; client %+v server %+v", client.connWindow.Available(), initial, client.connWindow.Stats(), server.connWindow.Stats())
		}
		time.Sleep(5 * time.Millisecond)
	}
	waitFor(t, "every server stream out of the session", func() bool {
		for i := uint64(0); i < 12; i++ {
			if streamPresent(server, 200+i) {
				return false
			}
		}
		return true
	})
	if server.recvQueued.Load() == 0 {
		t.Fatalf("premise: the server's unread messages hold nothing of its budget")
	}
	server.sweepEndedQueues(time.Now().Add(aether.DefaultStreamIdleTimeout + time.Second))
	if got := server.recvQueued.Load(); got != 0 {
		t.Errorf("after the sweep of abandoned queues the server's budget reads %d, want 0", got)
	}
}

// TestNoiseStream_LocalCloseKeepsReceiving: Close ends the send side only; what
// the peer sends after it still reaches Receive, and the peer's CLOSE ends it.
func TestNoiseStream_LocalCloseKeepsReceiving(t *testing.T) {
	client, server := noisePairWithRealms(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cs, ss := openWithCredit(t, ctx, client, server, 108, 0)
	if err := cs.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	waitFor(t, "the peer seeing the CLOSE", func() bool { return !ss.state.CanReceive() })
	if err := ss.Send(ctx, []byte("reply")); err != nil {
		t.Fatalf("reply send: %v", err)
	}
	if got, err := cs.Receive(ctx); err != nil || string(got) != "reply" {
		t.Fatalf("receive after local close: %q, %v", got, err)
	}
	if err := ss.Close(); err != nil {
		t.Fatalf("peer close: %v", err)
	}
	if _, err := cs.Receive(ctx); !errors.Is(err, io.EOF) {
		t.Fatalf("receive after both closed: %v, want io.EOF", err)
	}
}

// TestNoiseSession_ControlFramesAreBoundedAndChargeNothing: WHOIS and the like go
// to the control stream with no credit charged, so a flood stops at the count
// limit and is counted, reading them replenishes nothing, and the stream stays up.
func TestNoiseSession_ControlFramesAreBoundedAndChargeNothing(t *testing.T) {
	client, server := noisePairWithRealms(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cs, ss := openWithCredit(t, ctx, client, server, server.layout.Control, 0)
	_ = cs
	limit := 2 * recvChCapacity(server.layout.Control)
	ss.grantDebouncer.Flush()
	grantsBefore := ss.window.Stats().Consumed
	for i := 0; i < limit+50; i++ {
		server.deliverToControl([]byte("whois"))
	}
	if got := ss.recvQ.len(); got != limit {
		t.Fatalf("control queue holds %d messages, want the limit %d", got, limit)
	}
	if got := server.deliveryStats.Dropped.Load(); got != 50 {
		t.Fatalf("Dropped %d, want 50", got)
	}
	if !ss.IsOpen() {
		t.Fatal("control flood reset the stream")
	}
	for i := 0; i < limit; i++ {
		if _, err := ss.Receive(ctx); err != nil {
			t.Fatalf("receive %d: %v", i, err)
		}
	}
	ss.grantDebouncer.Flush()
	if got := ss.window.Stats().Consumed - grantsBefore; got != 0 {
		t.Fatalf("reading uncharged frames recorded %d consumed bytes", got)
	}
	if got := server.recvQueued.Load(); got != 0 {
		t.Fatalf("session budget after reading: %d, want 0", got)
	}
}

// TestNoiseStream_SendDoesNotTouchAFrameATLPProbeMayBeWriting: once Send has handed
// a frame over, the write loop's write boundary rewrites Payload, Length and Flags.
// This goroutine queues the newest entry's frame as a probe while Send runs, the
// earliest the write loop could reach it, so under -race any field access Send
// makes after SendWindow.Add is reported.
func TestNoiseStream_SendDoesNotTouchAFrameATLPProbeMayBeWriting(t *testing.T) {
	client, server := noisePairWithRealms(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cs, ss := openAccept(t, ctx, client, server, 109)
	st := asNoiseStream(t, cs)
	done := make(chan struct{})
	go func() {
		defer close(done)
		seen := uint32(0)
		for ctx.Err() == nil {
			if next := st.sendWindow.Next(); next > seen {
				if e := st.sendWindow.GetEntry(next - 1); e != nil {
					client.sched.EnqueueProbe(st.streamID, e.Frame)
					seen = next
				}
			}
			select {
			case <-st.recvDone:
				return
			default:
			}
		}
	}()
	msg := compressibleMessage()
	const n = 200
	for i := 0; i < n; i++ {
		if err := cs.Send(ctx, msg); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
		if _, err := ss.Receive(ctx); err != nil {
			t.Fatalf("receive %d: %v", i, err)
		}
	}
	cancel()
	<-done
}
