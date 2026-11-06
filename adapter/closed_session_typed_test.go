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

// wantSessionClosed fails unless err is the typed close a caller tells apart with
// errors.Is (aether.ErrSessionClosed), whatever text wraps it.
func wantSessionClosed(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, aether.ErrSessionClosed) {
		t.Errorf("%s: %v, want aether.ErrSessionClosed", what, err)
	}
}

// TestTCPSession_AClosedSessionAnswersTyped: once a TCP-family session closes with
// nothing queued, its stream's Receive and the session's OpenStream answer
// aether.ErrSessionClosed, as the stream's Send and Close do (closedError).
func TestTCPSession_AClosedSessionAnswersTyped(t *testing.T) {
	client, server := tcpPairWithOptions(t, aether.DefaultSessionOptions())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cs, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: 30, Reliability: aether.ReliableOrdered, Priority: 128})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := cs.Send(ctx, []byte("x")); err != nil {
		t.Fatalf("send: %v", err)
	}
	ss, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if _, err := ss.Receive(ctx); err != nil {
		t.Fatalf("receive: %v", err)
	}
	_ = client.Close()
	r := <-receiveAsync(ctx, cs, 5*time.Second)
	wantSessionClosed(t, "Receive on the closed session", r.err)
	_, err = client.OpenStream(ctx, aether.StreamConfig{StreamID: 31, Reliability: aether.ReliableOrdered})
	wantSessionClosed(t, "OpenStream on the closed session", err)
}

// TestNoiseSession_AClosedSessionAnswersTyped: once a NoiseSession closes, a stream
// it still holds answers Receive with aether.ErrSessionClosed, and so do OpenStream
// and a Close whose CLOSE nothing will write any more.
func TestNoiseSession_AClosedSessionAnswersTyped(t *testing.T) {
	client, server, _, _ := filteredPair(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cs, _ := openWithCredit(t, ctx, client, server, 905, 0)
	waitSendWindowEmpty(t, cs, "the opening message acknowledged")
	_ = client.Close()
	r := <-receiveAsync(ctx, cs, 5*time.Second)
	wantSessionClosed(t, "Receive on the closed session", r.err)
	_, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: 906, Reliability: aether.ReliableOrdered})
	wantSessionClosed(t, "OpenStream on the closed session", err)
	wantSessionClosed(t, "Close of a stream on the closed session", cs.Close())
}

// TestQUICSession_AClosedSessionAnswersTyped: OpenStream on a QUICSession that has
// closed answers aether.ErrSessionClosed.
func TestQUICSession_AClosedSessionAnswersTyped(t *testing.T) {
	client, server := quicLoopback(t)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: 10, Reliability: aether.ReliableOrdered}); err != nil {
		t.Fatalf("open: %v", err)
	}
	_ = client.Close()
	_, err := client.OpenStream(ctx, aether.StreamConfig{StreamID: 11, Reliability: aether.ReliableOrdered})
	wantSessionClosed(t, "OpenStream on the closed session", err)
}
