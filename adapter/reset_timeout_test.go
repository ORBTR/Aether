//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.com.au
 */
package adapter

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// resetEndCase is one RESET reason and the end it gives the stream at the peer that
// reads it: a stream GC's ResetTimeout is aether.ErrStreamTimedOut, which a caller
// tells from the io.EOF of a CLOSE after reading, and ResetCancel stays io.EOF.
var resetEndCases = []struct {
	name   string
	reason aether.ResetReason
	want   error
}{
	{"timeout", aether.ResetTimeout, aether.ErrStreamTimedOut},
	{"cancel", aether.ResetCancel, io.EOF},
}

// checkResetEnd reads a message the resetting side queued before its RESET, then the
// stream's end, and a Send after it, against want.
func checkResetEnd(t *testing.T, ctx context.Context, st aether.Stream, before string, want error) {
	t.Helper()
	if r := <-receiveAsync(ctx, st, 5*time.Second); r.err != nil || string(r.data) != before {
		t.Fatalf("the message queued before the RESET: %q, %v", r.data, r.err)
	}
	r := <-receiveAsync(ctx, st, 5*time.Second)
	if !errors.Is(r.err, want) {
		t.Fatalf("Receive after the RESET = %q, %v; want %v", r.data, r.err, want)
	}
	if want == io.EOF {
		return
	}
	if err := st.Send(ctx, []byte("after the reset")); !errors.Is(err, want) {
		t.Fatalf("Send after the RESET = %v, want %v", err, want)
	}
}

// TestNoiseStream_APeersIdleResetEndsTheStreamTimedOut: the peer resets a stream with
// RESET(ResetTimeout), as its stream GC (resetIdleStream) does; this side's consumer
// reads what was queued before it and then aether.ErrStreamTimedOut, and Send returns
// the same. A RESET(ResetCancel) still ends the stream as io.EOF.
func TestNoiseStream_APeersIdleResetEndsTheStreamTimedOut(t *testing.T) {
	for i, c := range resetEndCases {
		t.Run(c.name, func(t *testing.T) {
			client, server, _, _ := filteredPair(t, func(o *aether.SessionOptions) { o.SessionWarmupGrace = -1 })
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			cs, ss := openWithCredit(t, ctx, client, server, uint64(1130+2*i), 0)
			if err := ss.Send(ctx, []byte("queued before the reset")); err != nil {
				t.Fatal(err)
			}
			waitFor(t, "the message acknowledged", func() bool { return ss.sendWindow.InFlight() == 0 })
			if err := ss.Reset(c.reason); err != nil {
				t.Fatal(err)
			}
			checkResetEnd(t, ctx, cs, "queued before the reset", c.want)
		})
	}
}

// TestTCPSession_APeersIdleResetEndsTheStreamTimedOut is the byte-stream session's
// case of the same: the stream GC's reap (Reset(ResetTimeout)) reaches the peer as
// aether.ErrStreamTimedOut after the messages queued before it, and ResetCancel as
// io.EOF.
func TestTCPSession_APeersIdleResetEndsTheStreamTimedOut(t *testing.T) {
	for i, c := range resetEndCases {
		t.Run(c.name, func(t *testing.T) {
			client, server := tcpPairWithOptions(t, aether.DefaultSessionOptions())
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			cs, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: uint64(1140 + 2*i), Reliability: aether.ReliableOrdered})
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if err := cs.Send(ctx, []byte("hello")); err != nil {
				t.Fatalf("send: %v", err)
			}
			ss, err := server.AcceptStream(ctx)
			if err != nil {
				t.Fatalf("accept: %v", err)
			}
			if r := <-receiveAsync(ctx, ss, 5*time.Second); r.err != nil || string(r.data) != "hello" {
				t.Fatalf("first receive %q, %v", r.data, r.err)
			}
			if err := ss.Send(ctx, []byte("queued before the reset")); err != nil {
				t.Fatal(err)
			}
			// A frame the write loop has taken goes out ahead of the RESET; one still
			// in the scheduler leaves with the stream.
			waitFor(t, "the message taken from the scheduler", func() bool { return server.sched.QueueLen(ss.StreamID()) == 0 })
			if err := ss.Reset(c.reason); err != nil {
				t.Fatal(err)
			}
			checkResetEnd(t, ctx, cs, "queued before the reset", c.want)
		})
	}
}
