//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// The session's inFlightBytes counter is the pipe the write loop's CanSend
// gate and handleACK's OnAckWithPipe read. Every frame a stream adds to its
// SendWindow is charged to it and every frame that leaves the window is
// subtracted, so after every frame a session ever sent has been acked, or
// the stream holding them has left s.streams, the counter reads 0. These
// tests send payloads writeFrame shortens at the write boundary (the
// compressed Payload replaces the plaintext on the same *Frame the window
// holds), so a subtraction by the frame's committed length, not by the count
// the frame was charged, would leave the counter above 0.

// droppingConn is a net.Conn whose Write, once dropping is set, reports the
// bytes written and writes nothing, so the peer never sees the frame and
// never acks it: the sender's SendWindow keeps the entry in flight until the
// stream leaves the session.
type droppingConn struct {
	net.Conn
	dropping atomic.Bool
}

func (d *droppingConn) Write(b []byte) (int, error) {
	if d.dropping.Load() {
		return len(b), nil
	}
	return d.Conn.Write(b)
}

// noisePairWithDroppingClient is noisePairWithRealms with the client's conn
// wrapped so a test can keep the client's frames from reaching the server.
func noisePairWithDroppingClient(t *testing.T) (client, server *NoiseSession, drop *droppingConn) {
	t.Helper()
	chosen := aetherChosen(t)
	c, s := loopbackPair(t)
	drop = &droppingConn{Conn: c}
	client = NewNoiseSession(realmConn{Conn: drop, chosen: chosen}, "vl1_drop_client", "vl1_drop_server", aether.DefaultSessionOptions())
	server = NewNoiseSession(realmConn{Conn: s, chosen: chosen}, "vl1_drop_server", "vl1_drop_client", aether.DefaultSessionOptions())
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client, server, drop
}

// waitSendWindowEmpty polls until the stream's SendWindow holds no entry.
func waitSendWindowEmpty(t *testing.T, st *noiseStream, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for st.sendWindow.InFlight() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%s: %d entries still in the send window after 5 s", what, st.sendWindow.InFlight())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitInFlightBytesZero polls the session counter until it reads 0 and fails
// with the value it settled on otherwise. The counter is session-wide, so a
// control frame of another stream may be in flight for a moment after the
// data stream's last ACK; the assertion is the value the counter returns to.
func waitInFlightBytesZero(t *testing.T, s *NoiseSession, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		v := s.inFlightBytes.Load()
		if v == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: session inFlightBytes reads %d after 5 s, want 0", what, v)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func asNoiseStream(t *testing.T, s aether.Stream) *noiseStream {
	t.Helper()
	st, ok := s.(*noiseStream)
	if !ok {
		t.Fatalf("stream of type %T, want *noiseStream", s)
	}
	return st
}

// TestNoiseSession_InFlightBytesReturnsToZeroAfterOneCompressedFrameIsAcked:
// one compressible message, acked, leaves the counter at 0.
func TestNoiseSession_InFlightBytesReturnsToZeroAfterOneCompressedFrameIsAcked(t *testing.T) {
	client, server := noisePairWithRealms(t, nil, nil)
	if !client.compressionEnabled.Load() {
		t.Fatal("premise: the client session compresses DATA payloads")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cs, ss := openAccept(t, ctx, client, server, 102)
	st := asNoiseStream(t, cs)
	waitSendWindowEmpty(t, st, "hello")
	waitInFlightBytesZero(t, client, "before the send")

	msg := compressibleMessage()
	if err := cs.Send(ctx, msg); err != nil {
		t.Fatalf("send: %v", err)
	}
	if got, err := ss.Receive(ctx); err != nil || len(got) != len(msg) {
		t.Fatalf("receive: %d bytes, %v", len(got), err)
	}
	waitSendWindowEmpty(t, st, "the message")
	waitInFlightBytesZero(t, client, "after the ACK removed the only entry")
}

// TestNoiseSession_InFlightBytesReturnsToZeroAfterManyCompressedFramesAreAcked:
// the counter returns to 0 after every one of many compressible messages is
// acked, whether the ACKs come one at a time or cumulatively. The messages go
// in bursts of several frames so more than one entry is in flight at once,
// and each burst is received before the next is sent, so what this test asserts
// is the counter, and delivery has its own tests in delivery_burst_test.go.
func TestNoiseSession_InFlightBytesReturnsToZeroAfterManyCompressedFramesAreAcked(t *testing.T) {
	client, server := noisePairWithRealms(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	const streamID = 103
	cs, ss := openAccept(t, ctx, client, server, streamID)
	st := asNoiseStream(t, cs)
	waitSendWindowEmpty(t, st, "hello")
	waitInFlightBytesZero(t, client, "before the sends")

	const burst = 4
	const rounds = 5
	msg := compressibleMessage()
	for r := 0; r < rounds; r++ {
		for i := 0; i < burst; i++ {
			if err := cs.Send(ctx, msg); err != nil {
				t.Fatalf("round %d send %d: %v", r, i, err)
			}
		}
		for i := 0; i < burst; i++ {
			if got, err := ss.Receive(ctx); err != nil || len(got) != len(msg) {
				t.Fatalf("round %d receive %d: %d bytes, %v", r, i, len(got), err)
			}
		}
	}
	waitSendWindowEmpty(t, st, "the messages")
	waitInFlightBytesZero(t, client, "after every ACK")
}

// TestNoiseSession_InFlightBytesReturnsToZeroWhenAStreamLeavesWithFramesInFlight:
// frames the peer never acks (the client's writes are dropped) stay charged
// while the stream lives; the counter returns to 0 when the stream leaves
// s.streams, on each path that removes it: a local Reset, the peer's RESET,
// and a CLOSE from the peer after the local Close.
func TestNoiseSession_InFlightBytesReturnsToZeroWhenAStreamLeavesWithFramesInFlight(t *testing.T) {
	cases := []struct {
		name  string
		leave func(t *testing.T, cs, ss aether.Stream)
	}{
		{name: "local reset", leave: func(t *testing.T, cs, ss aether.Stream) {
			if err := cs.Reset(aether.ResetCancel); err != nil {
				t.Logf("reset: %v", err)
			}
		}},
		{name: "peer reset", leave: func(t *testing.T, cs, ss aether.Stream) {
			if err := ss.Reset(aether.ResetCancel); err != nil {
				t.Fatalf("peer reset: %v", err)
			}
		}},
		{name: "close from both sides", leave: func(t *testing.T, cs, ss aether.Stream) {
			if err := cs.Close(); err != nil {
				t.Logf("close: %v", err)
			}
			if err := ss.Close(); err != nil {
				t.Fatalf("peer close: %v", err)
			}
		}},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server, drop := noisePairWithDroppingClient(t)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cs, ss := openAccept(t, ctx, client, server, uint64(110+i))
			st := asNoiseStream(t, cs)
			waitSendWindowEmpty(t, st, "hello")
			waitInFlightBytesZero(t, client, "before the sends")

			drop.dropping.Store(true)
			const n = 5
			msg := compressibleMessage()
			for j := 0; j < n; j++ {
				if err := cs.Send(ctx, msg); err != nil {
					t.Fatalf("send %d: %v", j, err)
				}
			}
			if got := st.sendWindow.InFlight(); got != n {
				t.Fatalf("premise: %d entries in the send window, want %d (nothing acks a dropped frame)", got, n)
			}
			if v := client.inFlightBytes.Load(); v <= 0 {
				t.Fatalf("premise: session inFlightBytes reads %d with %d frames in flight, want > 0", v, n)
			}

			tc.leave(t, cs, ss)
			deadline := time.Now().Add(5 * time.Second)
			for {
				client.mu.Lock()
				_, present := client.streams[st.streamID]
				client.mu.Unlock()
				if !present {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("the stream is still in s.streams 5 s after %s", tc.name)
				}
				time.Sleep(5 * time.Millisecond)
			}
			waitInFlightBytesZero(t, client, "after the stream left the session")
		})
	}
}
