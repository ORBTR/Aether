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
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ORBTR/aether"
)

// teardownRaceRounds is how many times each test below rebuilds a session
// pair and resets a stream while its peer is still sending into it. The
// race detector needs the reset and a hand-off to be unordered in one run;
// a dozen rounds gives it that on a loaded machine within a few seconds.
const teardownRaceRounds = 12

// teardownRaceBurst is how many messages the peer sends into the stream its
// receiver resets, and teardownRacePace the gap between them: a paced
// stream of frames that is still arriving through the readLoop when the
// reset runs, on both adapters (the Noise pair over a loopback conn does
// not carry a back-to-back burst).
const (
	teardownRaceBurst = 64
	teardownRacePace  = 2 * time.Millisecond
)

// teardownRaceUnreadBeforeReset is how many payloads must sit in the
// stream's receive queue, put there by the readLoop and not yet read, when
// the reset runs: those hand-offs are then unordered with the teardown,
// while the rest of the burst is still arriving.
const teardownRaceUnreadBeforeReset = 3

// unreadMessages reports how many payloads st's receive queue holds, read under
// the queue's lock.
func unreadMessages(t *testing.T, st aether.Stream) int {
	t.Helper()
	switch s := st.(type) {
	case *tcpStream:
		return s.recvQ.len()
	case *noiseStream:
		return s.recvQ.len()
	}
	t.Fatalf("stream of type %T is not one of this package's", st)
	return 0
}

// resetUnderBurst opens a stream from client to server, has the client send
// teardownRaceBurst paced messages on its own goroutine, waits until the
// server's readLoop has put several of them on the stream's receive queue
// unread with more still arriving, resets the server's stream from this
// goroutine, and then requires every later Receive on the reset stream to end
// with io.EOF within the bound. The reset therefore races the readLoop's
// hand-off to the receive queue the way an application's Reset does.
func resetUnderBurst(t *testing.T, client, server aether.Session, streamID uint64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cs, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: streamID, Reliability: aether.ReliableOrdered, Priority: 128})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	payload := make([]byte, 512)
	for i := range payload {
		payload[i] = byte(i)
	}
	if err := cs.Send(ctx, payload); err != nil {
		t.Fatalf("first send: %v", err)
	}
	ss, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if _, err := ss.Receive(ctx); err != nil {
		t.Fatalf("first receive: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 1; i < teardownRaceBurst; i++ {
			// A send fails once the peer's RESET has torn the client's stream
			// down or the round's context ends; either ends the burst.
			if err := cs.Send(ctx, payload); err != nil {
				return
			}
			select {
			case <-time.After(teardownRacePace):
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait until several payloads sit in the stream's receive queue unread
	// while the burst still arrives, then reset.
	deadline := time.Now().Add(5 * time.Second)
	for unreadMessages(t, ss) < teardownRaceUnreadBeforeReset {
		if time.Now().After(deadline) {
			t.Fatalf("premise wrong: %d payloads sat unread in the receive queue after 5 s, want at least %d",
				unreadMessages(t, ss), teardownRaceUnreadBeforeReset)
		}
		time.Sleep(200 * time.Microsecond)
	}
	_ = ss.Reset(aether.ResetCancel)

	// Whatever the stream still held is handed over, then the stream ends:
	// Receive after Reset returns io.EOF, never a hang on the caller's context.
	recvCtx, recvCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer recvCancel()
	for n := 0; ; n++ {
		data, err := ss.Receive(recvCtx)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Receive %d after Reset returned %v, want io.EOF", n, err)
		}
		if len(data) != len(payload) {
			t.Fatalf("Receive %d after Reset returned %d bytes, want %d", n, len(data), len(payload))
		}
		if n > teardownRaceBurst {
			t.Fatalf("Receive after Reset returned more messages than the peer sends")
		}
	}
	cancel()
	wg.Wait()
}

// TestTCPStream_ResetUnderABurstFromThePeer resets a TCP stream from the
// application's goroutine while the peer is still sending into it. The
// readLoop is then putting payloads on the stream's recvQ while the reset
// tears the stream down; that hand-off may not race the teardown, and
// Receive after the reset ends with io.EOF.
func TestTCPStream_ResetUnderABurstFromThePeer(t *testing.T) {
	for round := 0; round < teardownRaceRounds; round++ {
		t.Run(fmt.Sprintf("round%02d", round), func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			client := NewTCPSession(clientConn, "vl1_teardown_client", "vl1_teardown_server", aether.ProtoTCP, aether.DefaultSessionOptions())
			server := NewTCPSession(serverConn, "vl1_teardown_server", "vl1_teardown_client", aether.ProtoTCP, aether.DefaultSessionOptions())
			t.Cleanup(func() {
				_ = client.Close()
				_ = server.Close()
				_ = clientConn.Close()
				_ = serverConn.Close()
			})
			resetUnderBurst(t, client, server, 100+uint64(round))
		})
	}
}

// TestNoiseStream_ResetUnderABurstFromThePeer is the same drive against the
// Noise adapter over a loopback connection: the reset tears the stream down
// while the readLoop's handleData is still pushing payloads onto the stream's
// receive queue (recvQ) and Receive is taking them.
func TestNoiseStream_ResetUnderABurstFromThePeer(t *testing.T) {
	for round := 0; round < teardownRaceRounds; round++ {
		t.Run(fmt.Sprintf("round%02d", round), func(t *testing.T) {
			client, server := noisePairWithRealms(t, nil, nil)
			resetUnderBurst(t, client, server, 100+uint64(round))
		})
	}
}
