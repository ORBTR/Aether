//go:build !js

/*
 * Copyright (c) 2026 ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@orbtr.io
 */
package adapter

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"
	"time"

	aether "github.com/ORBTR/aether"
)

// Stream and connection credit hold one kind of bytes: the plaintext length Send
// charges (noiseStream.Send's n). writeFrame may shorten the frame afterwards and
// the receiver hands the consumer the plaintext again, so what the consumer's
// Receive grants back is exactly what Send charged, whatever the wire carried.

func creditPair(t *testing.T, ctx context.Context, client, server *NoiseSession, id uint64, credit int64) (*noiseStream, *noiseStream) {
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

func waitCredit(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not reached in 15 s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// halfCompressible is size bytes that deflate to about half, so the committed
// frame is shorter than the plaintext and still over 1 KiB.
func halfCompressible(t *testing.T, size int) []byte {
	t.Helper()
	b := make([]byte, size)
	if _, err := rand.Read(b[:size/2]); err != nil {
		t.Fatal(err)
	}
	return b
}

// TestNoiseStream_CreditHoldsPlaintextBytesThroughACompressedFrame: a compressed
// message charges its plaintext length on both windows, its ACK returns none of
// it, and the consumer's Receive returns all of it.
func TestNoiseStream_CreditHoldsPlaintextBytesThroughACompressedFrame(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
		make func(*testing.T, int) []byte
	}{
		{"deflates to almost nothing", 4096, func(_ *testing.T, n int) []byte { return bytes.Repeat([]byte{'a'}, n) }},
		{"deflates to about half", 4096, halfCompressible},
		{"fragments on the way", 64 * 1024, halfCompressible},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := uint32(7)
			client, server := noisePairWithRealms(t, &key, &key)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cs, ss := creditPair(t, ctx, client, server, 120, 1<<20)
			waitCredit(t, "the first message's stream credit back", func() bool { return cs.window.Outstanding() == 0 })
			connBefore := client.connWindow.Stats().Outstanding

			msg := tc.make(t, tc.size)
			if err := cs.Send(ctx, msg); err != nil {
				t.Fatalf("send: %v", err)
			}
			want := int64(len(msg))
			if got := cs.window.Outstanding(); got != want {
				t.Fatalf("after Send: stream outstanding %d, want the plaintext %d", got, want)
			}
			if got := client.connWindow.Stats().Outstanding - connBefore; got != want {
				t.Fatalf("after Send: connection outstanding grew %d, want the plaintext %d", got, want)
			}

			waitCredit(t, "every frame of the message acked", func() bool { return cs.sendWindow.InFlight() == 0 })
			if got := cs.window.Outstanding(); got != want {
				t.Fatalf("after the ACK with no reader: stream outstanding %d, want %d: an ACK returns no credit", got, want)
			}

			got, err := ss.Receive(ctx)
			if err != nil || !bytes.Equal(got, msg) {
				t.Fatalf("receive: %d bytes, %v; want the %d sent", len(got), err, len(msg))
			}
			waitCredit(t, "the consumer's read returning all stream credit", func() bool { return cs.window.Outstanding() == 0 })
			waitCredit(t, "the consumer's read returning the connection credit", func() bool {
				return client.connWindow.Stats().Outstanding <= connBefore
			})
		})
	}
}

// TestNoiseStream_ACompressingStreamKeepsItsCredit: many windows' worth of
// compressible plaintext crosses a stream with a reading consumer, and every
// byte's credit comes back, so no Send ever meets the credit it charged and did
// not recover.
func TestNoiseStream_ACompressingStreamKeepsItsCredit(t *testing.T) {
	key := uint32(7)
	client, server := noisePairWithRealms(t, &key, &key)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	const credit = 64 * 1024
	cs, ss := creditPair(t, ctx, client, server, 121, credit)
	msg := bytes.Repeat([]byte{'b'}, 4096)
	const total = 3 * credit / 4096
	readDone := make(chan error, 1)
	go func() {
		for i := 0; i < total; i++ {
			got, err := ss.Receive(ctx)
			if err != nil {
				readDone <- err
				return
			}
			if !bytes.Equal(got, msg) {
				t.Errorf("receive %d: %d bytes differ from the %d sent", i, len(got), len(msg))
			}
		}
		readDone <- nil
	}()
	for i := 0; i < total; i++ {
		if err := cs.Send(ctx, msg); err != nil {
			t.Fatalf("send %d of %d: %v", i, total, err)
		}
	}
	if err := <-readDone; err != nil {
		t.Fatalf("reader: %v", err)
	}
	waitCredit(t, "all stream credit back", func() bool { return cs.window.Outstanding() == 0 })
}
